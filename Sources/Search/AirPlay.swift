import AppKit
import WebKit

/// Anchors the native AirPlay route picker NSPopover directly above in-page
/// playback target buttons (such as YouTube's AirPlay button `.ytp-airplay-button`),
/// pointing downwards into the button like standard video player controls.
@MainActor
final class AirPlay: NSObject, WKScriptMessageHandler {
    static let name = "officeAirPlay"
    static let shared = AirPlay()

    private var isObserving = false

    func startObserving() {
        guard !isObserving else { return }
        isObserving = true
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(popoverWillShow(_:)),
            name: NSPopover.willShowNotification,
            object: nil
        )
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(popoverDidShow(_:)),
            name: NSPopover.didShowNotification,
            object: nil
        )
    }

    /// Script that intercepts interactions on AirPlay buttons across the page
    /// and hooks HTMLMediaElement.prototype.webkitShowPlaybackTargetPicker to report
    /// the button's exact bounding box.
    static let script = """
    (() => {
      if (window.__officeAirPlayInstalled) return;
      window.__officeAirPlayInstalled = true;

      function reportRect(el) {
        if (!el || typeof el.getBoundingClientRect !== 'function') return;
        const r = el.getBoundingClientRect();
        if (r.width > 0 && r.height > 0) {
          window.webkit?.messageHandlers?.\(name)?.postMessage({
            x: r.left,
            y: r.top,
            width: r.width,
            height: r.height
          });
        }
      }

      function findAirPlayTarget(e) {
        if (!e) return null;
        const path = (typeof e.composedPath === 'function') ? e.composedPath() : [];
        for (let i = 0; i < path.length; i++) {
          const el = path[i];
          if (!el || !el.getAttribute) continue;
          const cl = el.className || '';
          const aria = el.getAttribute('aria-label') || '';
          const title = el.getAttribute('title') || '';
          if ((typeof cl === 'string' && cl.includes('ytp-airplay-button')) ||
              /airplay/i.test(aria) || /airplay/i.test(title) || el.hasAttribute('data-airplay')) {
            return el;
          }
        }
        return null;
      }

      function onPointer(e) {
        const el = findAirPlayTarget(e);
        if (el) reportRect(el);
      }

      addEventListener('pointerdown', onPointer, true);
      addEventListener('mousedown', onPointer, true);
      addEventListener('click', onPointer, true);

      try {
        const orig = HTMLMediaElement.prototype.webkitShowPlaybackTargetPicker;
        if (orig) {
          HTMLMediaElement.prototype.webkitShowPlaybackTargetPicker = function() {
            try {
              const btn = document.querySelector('.ytp-airplay-button, button[aria-label*="AirPlay" i], button[title*="AirPlay" i]');
              if (btn) reportRect(btn);
            } catch (_) {}
            return orig.apply(this, arguments);
          };
        }
      } catch (_) {}
    })();
    """

    static var userScript: WKUserScript {
        WKUserScript(source: script, injectionTime: .atDocumentStart, forMainFrameOnly: false, in: Web.world)
    }

    static var pageWorldUserScript: WKUserScript {
        WKUserScript(source: script, injectionTime: .atDocumentStart, forMainFrameOnly: false, in: .defaultClient)
    }

    static func install(on controller: WKUserContentController) {
        controller.add(shared, contentWorld: Web.world, name: name)
        controller.add(shared, contentWorld: .defaultClient, name: name)
        shared.startObserving()
    }

    private var lastTarget: (rect: NSRect, view: PageView, time: TimeInterval)?
    private var lastMouseDown: (point: NSPoint, view: PageView, time: TimeInterval)?

    func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
        guard let body = message.body as? [String: Any],
              let x = body["x"] as? Double,
              let y = body["y"] as? Double,
              let width = body["width"] as? Double,
              let height = body["height"] as? Double,
              let webView = message.webView as? PageView else { return }

        let rect = NSRect(x: x, y: y, width: width, height: height)
        lastTarget = (rect: rect, view: webView, time: ProcessInfo.processInfo.systemUptime)
    }

    func noteMouseDown(at point: NSPoint, in webView: PageView) {
        lastMouseDown = (point: point, view: webView, time: ProcessInfo.processInfo.systemUptime)
    }

    @objc private func popoverWillShow(_ notification: Notification) {
        adjustPopover(notification)
    }

    @objc private func popoverDidShow(_ notification: Notification) {
        adjustPopover(notification)
    }

    private func adjustPopover(_ notification: Notification) {
        guard let popover = notification.object as? NSPopover else { return }

        let positioningView: NSView? = {
            let sel = NSSelectorFromString("positioningView")
            if popover.responds(to: sel) {
                return popover.value(forKey: "positioningView") as? NSView
            }
            return nil
        }()

        let now = ProcessInfo.processInfo.systemUptime
        var targetInPage: NSRect?
        var pageView: PageView?

        if let target = lastTarget, now - target.time < 3.0 {
            pageView = target.view
            let m = target.view.magnification
            targetInPage = NSRect(
                x: target.rect.origin.x * m,
                y: target.rect.origin.y * m,
                width: target.rect.width * m,
                height: target.rect.height * m
            )
        } else if let mouse = lastMouseDown, now - mouse.time < 3.0 {
            pageView = mouse.view
            targetInPage = NSRect(x: mouse.point.x - 18, y: mouse.point.y - 18, width: 36, height: 36)
        } else if popover.positioningRect.height > 150 && popover.positioningRect.width > 200 {
            let orig = popover.positioningRect
            popover.positioningRect = NSRect(x: orig.maxX - 100, y: orig.maxY - 44, width: 36, height: 36)
            return
        }

        guard let target = targetInPage, let page = pageView else { return }

        if let pv = positioningView, pv !== page {
            popover.positioningRect = page.convert(target, to: pv)
        } else {
            popover.positioningRect = target
        }
    }
}
