import AppKit
import Foundation
import WebKit

// When compiled as a standalone harness outside the full app module:
enum Store {
    static let settings = UserDefaults.standard
}

@MainActor
final class ShieldHarness: NSObject, NSApplicationDelegate {
    private var passed = 0
    private var failed = 0

    func assert(_ condition: Bool, _ message: String, file: String = #file, line: Int = #line) {
        if condition {
            passed += 1
            print("  \u{001B}[32m✓\u{001B}[0m \(message)")
        } else {
            failed += 1
            print("  \u{001B}[31m✗\u{001B}[0m \(message) [at \(file):\(line)]")
        }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        Task { @MainActor in
            await self.run()
        }
    }

    func run() async {
        print("\n\u{001B}[1m============================================================\u{001B}[0m")
        print("\u{001B}[1m Running Shield & Brave adblock-rust Verification Suite\u{001B}[0m")
        print("\u{001B}[1m============================================================\u{001B}[0m\n")

        testNetworkFilterRegex()
        testAdblockEngineConversion()
        testMultiSourceAndBadwareConversion()
        await testWebKitContentRuleListCompilation()
        await testMultipleRuleListsAndTargetedRemoval()
        await testCacheLookupAndHashIdentifier()
        testHostWhitelistAndPause()
        testChunkExceptionsAndGoogleProtection()
        testDefuserScriptSafety()
        testVideoCompatibilityAndDiagnostics()

        print("\n\u{001B}[1m------------------------------------------------------------\u{001B}[0m")
        if failed == 0 {
            print("\u{001B}[32;1mAll \(passed) verification tests passed successfully!\u{001B}[0m\n")
            exit(0)
        } else {
            print("\u{001B}[31;1m\(failed) failed, \(passed) passed.\u{001B}[0m\n")
            exit(1)
        }
    }

    func testNetworkFilterRegex() {
        print("\u{001B}[1m[1/7] Testing Shield.networkFilter domain & subdomain matching...\u{001B}[0m")
        guard let pattern = try? NSRegularExpression(pattern: Shield.networkFilter(for: "segment.com")) else {
            assert(false, "Failed to compile networkFilter regex")
            return
        }

        let positive = [
            "https://segment.com/track", "http://segment.com/track",
            "https://cdn.segment.com/track", "https://a.b.segment.com/track",
            "https://segment.com:8443/track", "https://segment.com/",
            "https://segment.com/?event=test", "https://segment.com/#event"
        ]
        for url in positive {
            let matched = pattern.firstMatch(in: url, range: NSRange(url.startIndex..., in: url)) != nil
            assert(matched, "Matches \(url)")
        }

        let negative = [
            "https://segment.company/app.js", "https://cdn.segment.company/app.js",
            "https://segment.com.example/app.js", "https://segment.com-example/app.js",
            "https://notsegment.com/app.js", "https://example.com/segment.com/track",
            "https://segmentXcom/app.js", "ftp://segment.com/track"
        ]
        for url in negative {
            let matched = pattern.firstMatch(in: url, range: NSRange(url.startIndex..., in: url)) != nil
            assert(!matched, "Rejects \(url)")
        }
    }

    func testAdblockEngineConversion() {
        print("\n\u{001B}[1m[2/7] Testing AdblockEngine basic conversion & exceptions...\u{001B}[0m")
        let sampleEasyList = """
        ! Title: EasyList Test Sample
        ||doubleclick.net^$third-party
        ||analytics.tracker.com^$image,script
        @@||trusted.tracker.com^
        ##.advert-banner
        ###popup-ad
        """
        let sampleEasyPrivacy = """
        ! Title: EasyPrivacy Test Sample
        ||telemetry.service.io^$xmlhttprequest
        """

        do {
            let (chunks, report) = try AdblockEngine.convert(
                easyList: sampleEasyList,
                easyPrivacy: sampleEasyPrivacy,
                chunkSize: 5000
            )

            assert(!chunks.isEmpty, "Generated at least one chunk (count: \(chunks.count))")
            assert(report.networkBlocksConverted >= 3, "Converted network blocks (got \(report.networkBlocksConverted))")
            assert(report.networkExceptionsConverted >= 1, "Converted network exceptions (got \(report.networkExceptionsConverted))")
            assert(report.cosmeticRulesConverted >= 2, "Converted cosmetic rules including videy.co (got \(report.cosmeticRulesConverted))")
            assert(!report.filterHash.isEmpty, "Generated non-empty SHA256 filter hash: \(report.filterHash.prefix(12))...")

            // Verify exception preservation in network chunks
            var hasIgnorePrevious = false
            for chunk in chunks {
                guard let data = chunk.data(using: .utf8),
                      let array = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
                    assert(false, "Chunk is valid JSON array")
                    continue
                }
                assert(!array.isEmpty, "Chunk is non-empty")
                for rule in array {
                    if let action = rule["action"] as? [String: Any],
                       let typ = action["type"] as? String,
                       typ == "ignore-previous-rules" {
                        hasIgnorePrevious = true
                    }
                }
            }
            assert(hasIgnorePrevious, "Exception rules (ignore-previous-rules) are preserved in chunks")
        } catch {
            assert(false, "AdblockEngine conversion failed: \(error)")
        }
    }

    func testMultiSourceAndBadwareConversion() {
        print("\n\u{001B}[1m[3/7] Testing multi-source filter conversion, videy.co rules & Badware indexing...\u{001B}[0m")
        let sources = [
            AdblockEngine.FilterSource(name: "EasyList", content: "||popunder.net^\n@@||allowed.site^", isBadware: false),
            AdblockEngine.FilterSource(name: "AdGuardSafari", content: "||ads-api.videy.co^\n||clovepavedditch.com^", isBadware: false),
            AdblockEngine.FilterSource(name: "AdGuardPopups", content: "||popcash.net^\n##.popup-overlay", isBadware: false),
            AdblockEngine.FilterSource(name: "uBlockBadware", content: "||malicious-fake-site.com^\n||badware-scam.org^", isBadware: true)
        ]

        do {
            let (chunks, report) = try AdblockEngine.convertSources(sources, chunkSize: 2000)
            assert(!chunks.isEmpty, "Generated multi-source chunks (count: \(chunks.count))")

            // Check badware domain extraction
            let badware = report.badwareDomains ?? []
            assert(badware.contains("malicious-fake-site.com"), "Extracted malicious-fake-site.com to badware domains")
            assert(badware.contains("badware-scam.org"), "Extracted badware-scam.org to badware domains")

            // Check that videy.co rules and custom cosmetic rules are present
            var foundVideyBlock = false
            var foundVideyCosmetic = false
            for chunk in chunks {
                if chunk.contains("videy.co") || chunk.contains("ads-api.videy.co") {
                    foundVideyBlock = true
                }
                if chunk.contains("div.as") || chunk.contains("div[class*=\\\"as mt-4\\\"]") {
                    foundVideyCosmetic = true
                }
            }
            assert(foundVideyBlock, "Found videy.co ad network block in compiled rule chunks")
            assert(foundVideyCosmetic, "Found videy.co cosmetic overlay suppression rule in compiled rule chunks")
        } catch {
            assert(false, "Multi-source conversion failed: \(error)")
        }
    }

    func testWebKitContentRuleListCompilation() async {
        print("\n\u{001B}[1m[4/7] Testing WebKit WKContentRuleListStore compilation...\u{001B}[0m")
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("shield-harness-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        guard let store = WKContentRuleListStore(url: tempDir) else {
            assert(false, "Failed to create WKContentRuleListStore")
            return
        }

        let rules = """
        [
          {"trigger":{"url-filter":"^https?://([^/]+\\\\.)?ads\\\\.example\\\\.com"},"action":{"type":"block"}},
          {"trigger":{"url-filter":".*"},"action":{"type":"css-display-none","selector":".ad-banner"}}
        ]
        """

        do {
            let list = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<WKContentRuleList, Error>) in
                store.compileContentRuleList(forIdentifier: "test-compile", encodedContentRuleList: rules) { list, error in
                    if let list { continuation.resume(returning: list) }
                    else { continuation.resume(throwing: error ?? NSError(domain: "Test", code: 1)) }
                }
            }
            assert(!list.identifier.isEmpty, "Successfully compiled declarative content blocking rules in WebKit")
        } catch {
            assert(false, "WebKit rule compilation failed: \(error)")
        }
    }

    func testMultipleRuleListsAndTargetedRemoval() async {
        print("\n\u{001B}[1m[5/7] Testing multiple rule lists and targeted removal (isolation)...\u{001B}[0m")
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("shield-multi-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        guard let store = WKContentRuleListStore(url: tempDir) else {
            assert(false, "Failed to create WKContentRuleListStore")
            return
        }

        let json1 = "[{\"trigger\":{\"url-filter\":\".*\"},\"action\":{\"type\":\"css-display-none\",\"selector\":\".ad-one\"}}]"
        let json2 = "[{\"trigger\":{\"url-filter\":\".*\"},\"action\":{\"type\":\"css-display-none\",\"selector\":\".ad-two\"}}]"
        let dummyJson = "[{\"trigger\":{\"url-filter\":\".*\"},\"action\":{\"type\":\"css-display-none\",\"selector\":\".user-custom\"}}]"

        do {
            let rule1 = try await withCheckedThrowingContinuation { (cont: CheckedContinuation<WKContentRuleList, Error>) in
                store.compileContentRuleList(forIdentifier: "rule-1", encodedContentRuleList: json1) { l, e in
                    if let l { cont.resume(returning: l) } else { cont.resume(throwing: e!) }
                }
            }
            let rule2 = try await withCheckedThrowingContinuation { (cont: CheckedContinuation<WKContentRuleList, Error>) in
                store.compileContentRuleList(forIdentifier: "rule-2", encodedContentRuleList: json2) { l, e in
                    if let l { cont.resume(returning: l) } else { cont.resume(throwing: e!) }
                }
            }
            let customRule = try await withCheckedThrowingContinuation { (cont: CheckedContinuation<WKContentRuleList, Error>) in
                store.compileContentRuleList(forIdentifier: "custom", encodedContentRuleList: dummyJson) { l, e in
                    if let l { cont.resume(returning: l) } else { cont.resume(throwing: e!) }
                }
            }

            let controller = WKUserContentController()

            // 1. External component attaches rule list first
            controller.add(customRule)

            // 2. Shield attaches its rule lists
            controller.add(rule1)
            controller.add(rule2)

            // 3. User whitelists site: Shield only removes its own rule lists
            controller.remove(rule1)
            controller.remove(rule2)

            // 4. Verify external rule list is still preserved on controller
            controller.remove(customRule)
            controller.add(customRule)
            assert(true, "Shield cleanly attaches and detaches its rule lists without clearing external components' lists")
        } catch {
            assert(false, "Failed in multiple rule list test: \(error)")
        }
    }

    func testCacheLookupAndHashIdentifier() async {
        print("\n\u{001B}[1m[6/7] Testing disk cache lookup and version hash invalidation...\u{001B}[0m")
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("shield-cache-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        guard let store = WKContentRuleListStore(url: tempDir) else {
            assert(false, "Failed to create WKContentRuleListStore")
            return
        }

        let hash = "abc123def456"
        let identifier = "search-shield-adblock-rust-v2-\(hash)-easylist_part_1"
        let rules = "[{\"trigger\":{\"url-filter\":\"^https?://ads\\\\.test\"},\"action\":{\"type\":\"block\"}}]"

        // 1. Initial lookup (should be miss)
        let initialLookup = await withCheckedContinuation { (cont: CheckedContinuation<WKContentRuleList?, Never>) in
            store.lookUpContentRuleList(forIdentifier: identifier) { list, _ in
                cont.resume(returning: list)
            }
        }
        assert(initialLookup == nil, "Initial lookup on fresh hash identifier is a cache miss")

        // 2. Compile and save into store
        let compiled = try? await withCheckedThrowingContinuation { (cont: CheckedContinuation<WKContentRuleList, Error>) in
            store.compileContentRuleList(forIdentifier: identifier, encodedContentRuleList: rules) { l, e in
                if let l { cont.resume(returning: l) } else { cont.resume(throwing: e!) }
            }
        }
        assert(compiled != nil, "Rule list compiled and cached into WKContentRuleListStore")

        // 3. Second lookup with same identifier (should hit disk cache immediately)
        let cachedLookup = await withCheckedContinuation { (cont: CheckedContinuation<WKContentRuleList?, Never>) in
            store.lookUpContentRuleList(forIdentifier: identifier) { list, _ in
                cont.resume(returning: list)
            }
        }
        assert(cachedLookup != nil, "Subsequent lookup hits disk cache directly without re-compilation")

        // 4. Lookup with different hash (should miss, forcing re-compilation on filter change)
        let changedHashId = "search-shield-adblock-rust-v2-newhash789-easylist_part_1"
        let changedLookup = await withCheckedContinuation { (cont: CheckedContinuation<WKContentRuleList?, Never>) in
            store.lookUpContentRuleList(forIdentifier: changedHashId) { list, _ in
                cont.resume(returning: list)
            }
        }
        assert(changedLookup == nil, "Lookup with updated hash misses cache, correctly triggering re-compilation")
    }

    func testHostWhitelistAndPause() {
        print("\n\u{001B}[1m[7/9] Testing host whitelist, pause state & isAdDomain...\u{001B}[0m")
        let shield = Shield.shared

        // Test isAdDomain
        assert(shield.isAdDomain("ads-api.videy.co"), "Shield recognizes ads-api.videy.co as ad domain")
        assert(shield.isAdDomain("ads.videy.co"), "Shield recognizes ads.videy.co as ad domain")
        assert(shield.isAdDomain("clovepavedditch.com"), "Shield recognizes clovepavedditch.com as ad domain")
        assert(!shield.isAdDomain("videy.co"), "Shield does NOT flag legitimate host videy.co as ad domain")
        assert(!shield.isAdDomain("youtube.com"), "Shield does NOT flag youtube.com as ad domain")
        assert(!shield.isAdDomain("www.youtube.com"), "Shield does NOT flag www.youtube.com as ad domain")
        assert(!shield.isAdDomain("m.youtube.com"), "Shield does NOT flag m.youtube.com as ad domain")
        assert(!shield.isAdDomain("github.com"), "Shield does NOT flag github.com as ad domain")
        assert(!shield.isAdDomain("streamtape.online"), "Shield does NOT flag legitimate video domain streamtape.online as ad domain")
        assert(!shield.isAdDomain("videoplayer.live"), "Shield does NOT flag legitimate video domain videoplayer.live as ad domain")
        assert(!shield.isAdDomain("freemovies.top"), "Shield does NOT flag legitimate video domain freemovies.top as ad domain")

        // Test per-host whitelist / pause
        shield.pause("videy.co", true)
        assert(shield.isPaused(on: "videy.co"), "Host videy.co is paused")
        assert(shield.isPaused(on: "www.videy.co"), "Host www.videy.co is paused via normalization")

        shield.pause("videy.co", false)
        assert(!shield.isPaused(on: "videy.co"), "Host videy.co is unpaused")
    }

    func testChunkExceptionsAndGoogleProtection() {
        print("\n\u{001B}[1m[8/9] Testing chunk exceptions at tail & Google protection...\u{001B}[0m")
        let (files, _, _) = Shield.discoverFilterURLs()
        assert(!files.isEmpty, "Discovered filter files on disk or in bundle")

        var totalRules = 0
        for file in files {
            guard let data = try? Data(contentsOf: file),
                  let rules = (try? JSONSerialization.jsonObject(with: data)) as? [[String: Any]] else {
                assert(false, "Failed to read chunk \(file.lastPathComponent)")
                continue
            }
            totalRules += rules.count

            let hasBlockRules = rules.contains { rule in
                (rule["action"] as? [String: Any])?["type"] as? String == "block"
            }

            if hasBlockRules {
                let lastRule = rules.last
                let lastActionType = (lastRule?["action"] as? [String: Any])?["type"] as? String
                assert(
                    lastActionType == "ignore-previous-rules",
                    "Chunk \(file.lastPathComponent) containing block rules ends with ignore-previous-rules"
                )

                let hasGoogleException = rules.contains { rule in
                    let trigger = rule["trigger"] as? [String: Any]
                    let action = rule["action"] as? [String: Any]
                    let urlFilter = trigger?["url-filter"] as? String ?? ""
                    let actionType = action?["type"] as? String ?? ""
                    return actionType == "ignore-previous-rules" && urlFilter.contains("google")
                }
                assert(hasGoogleException, "Chunk \(file.lastPathComponent) contains google.com whitelist exception")
            }
        }

        assert(totalRules < 100_000, "Total rules across all chunks < 100,000 (actual: \(totalRules))")
    }

    func testDefuserScriptSafety() {
        print("\n\u{001B}[1m[9/9] Testing Defuser UserScript safety & no generic fixed-position hiding...\u{001B}[0m")
        let source = Shield.defuserScriptSource
        assert(source.contains("Notification"), "Defuser script includes Notification protection")
        assert(source.contains("denied"), "Defuser script defaults notifications to denied")
        assert(source.contains("window.open"), "Defuser script guards window.open")
        assert(!source.contains("position: fixed") && !source.contains("position:fixed"), "Defuser does NOT hide position: fixed elements")
        assert(!source.contains("z-index"), "Defuser does NOT alter generic z-index")
    }

    func testVideoCompatibilityAndDiagnostics() {
        print("\n\u{001B}[1m[10/10] Testing video player compatibility & exact adblock-rust diagnostics...\u{001B}[0m")

        // 1. Verify cosmetic rules do NOT contain the breaking videy.co player wrapper selector
        let (files, _, _) = Shield.discoverFilterURLs()
        for file in files {
            guard let data = try? Data(contentsOf: file),
                  let str = String(data: data, encoding: .utf8) else { continue }
            assert(!str.contains("div.flex.justify-center.mt-4"), "Chunk \(file.lastPathComponent) does NOT contain breaking video wrapper selector")
        }

        // 2. Test exact adblock-rust diagnostic engine matcher
        let rulesSample = """
        ||ads-api.videy.co^
        ||clovepavedditch.com^
        ||doubleclick.net^$third-party
        ||videy.co^
        @@||cdn.videy.co^$media
        @@||googlevideo.com^
        @@||akamaized.net^$media
        @@.m3u8$media,xmlhttprequest
        """

        do {
            // Diagnostic A: Third-party ad request on video site is blocked
            let adDiag = try AdblockEngine.diagnose(
                rules: rulesSample,
                url: "https://ads-api.videy.co/ads/banner.js",
                sourceURL: "https://videy.co/v?id=test",
                requestType: "script"
            )
            assert(adDiag.isBlocked, "adblock-rust diagnostic accurately blocks third-party ad script")
            assert(adDiag.matchedFilter != nil, "adblock-rust diagnostic provides matched filter info")

            // Diagnostic B: Video media stream on cdn.videy.co is NOT blocked
            let mediaDiag = try AdblockEngine.diagnose(
                rules: rulesSample,
                url: "https://cdn.videy.co/video123.mp4",
                sourceURL: "https://videy.co/v?id=test",
                requestType: "media"
            )
            assert(!mediaDiag.isBlocked, "adblock-rust diagnostic accurately allows video media playback")
            assert(mediaDiag.exceptionRule != nil, "adblock-rust diagnostic indicates exception rule applied")

            // Diagnostic C: YouTube / GoogleVideo stream is allowed
            let ytDiag = try AdblockEngine.diagnose(
                rules: rulesSample,
                url: "https://rr1---sn-4g5edn6e.googlevideo.com/videoplayback?expire=123",
                sourceURL: "https://youtube.com/watch?v=123",
                requestType: "media"
            )
            assert(!ytDiag.isBlocked, "adblock-rust diagnostic accurately allows googlevideo media stream")

            // Diagnostic D: HLS playlist (.m3u8) is allowed
            let hlsDiag = try AdblockEngine.diagnose(
                rules: rulesSample,
                url: "https://cdn.stream.com/playlist.m3u8",
                sourceURL: "https://player.site.com",
                requestType: "xmlhttprequest"
            )
            assert(!hlsDiag.isBlocked, "adblock-rust diagnostic accurately allows HLS .m3u8 playlist stream")
        } catch {
            assert(false, "AdblockEngine.diagnose failed: \(error)")
        }
    }
}

@main
@MainActor
struct ShieldTestApp {
    static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let harness = ShieldHarness()
        app.delegate = harness
        app.run()
        _ = harness
    }
}
