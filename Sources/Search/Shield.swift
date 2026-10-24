import WebKit

/// One compiled, disk-cached WebKit ruleset collection shared across all tab page controllers.
/// WKUserContentControllers remain per-tab because they own per-tab script message handlers
/// and content scripts; the immutable compiled WKContentRuleList instances are shared.
@MainActor
final class Shield: ObservableObject {
    static let shared = Shield()

    private nonisolated static let engineVersion = "adblock-rust-v2"
    private nonisolated static let fallbackID = "search-shield-fallback-v2"

    /// Safe defuser script that only denies notification spam and guards against cross-origin window.open abuse,
    /// without any generic fixed/z-index element hiding that breaks web apps like Google, X, and YouTube.
    static let defuserScriptSource = """
    (() => {
      try {
        if (typeof Notification !== 'undefined') {
          try {
            Object.defineProperty(Notification, 'permission', {
              get: () => 'denied',
              configurable: true
            });
          } catch (e) {
            Notification.permission = 'denied';
          }
          Notification.requestPermission = function() {
            return Promise.resolve('denied');
          };
        }
      } catch (e) {}

      try {
        const originalOpen = window.open;
        window.open = function(url, target, features) {
          if (!url) return originalOpen.apply(this, arguments);
          try {
            const targetUrl = new URL(url, window.location.href);
            if (targetUrl.origin !== window.location.origin) {
              if (!window.event || !window.event.isTrusted) {
                return null;
              }
            }
          } catch (e) {}
          return originalOpen.apply(this, arguments);
        };
      } catch (e) {}
    })();
    """

    static var userScript: WKUserScript {
        WKUserScript(
            source: defuserScriptSource,
            injectionTime: .atDocumentStart,
            forMainFrameOnly: false,
            in: .defaultClient
        )
    }

    private(set) var ruleLists: [WKContentRuleList] = []
    var list: WKContentRuleList? { ruleLists.first }

    private final class WeakController {
        weak var value: WKUserContentController?
        init(_ value: WKUserContentController) { self.value = value }
    }

    private var controllers: [WeakController] = []
    private var registered = Set<ObjectIdentifier>()
    private var hostByController = [ObjectIdentifier: String]()
    private var loading = false

    private init() {
        compile()
    }

    @Published private(set) var trouble: String?
    @Published private(set) var activeFilterHash: String?
    private(set) var badwareDomains: Set<String> = []
    @Published var enabled = true {
        didSet {
            controllers.removeAll(where: { $0.value == nil })
            apply(to: controllers.compactMap { $0.value })
        }
    }

    @Published private(set) var paused: Set<String> = Set(
        Store.settings.stringArray(forKey: "shield.paused") ?? []
    )

    /// WebKit does not provide per-rule match callbacks for declarative content rule lists.
    /// Keep native UI statistics (e.g. popups and redirects prevented) without DOM observers.
    @Published private(set) var blockedCounts: [UUID: Int] = [:]

    func count(for tabID: UUID) -> Int { blockedCounts[tabID] ?? 0 }

    func noteBlocked(for tabID: UUID, amount: Int = 1) {
        blockedCounts[tabID, default: 0] += max(1, amount)
    }

    func clear(for tabID: UUID) { blockedCounts.removeValue(forKey: tabID) }

    func isPaused(on host: String?) -> Bool {
        guard let host else { return false }
        return paused.contains(Self.normalizedHost(host))
    }

    func isActive(on host: String?) -> Bool {
        guard enabled else { return false }
        guard let host, !host.isEmpty else { return true }
        return !isPaused(on: host)
    }

    func pause(_ host: String, _ off: Bool) {
        let host = Self.normalizedHost(host)
        guard !host.isEmpty else { return }
        if off { paused.insert(host) } else { paused.remove(host) }
        Store.settings.set(Array(paused).sorted(), forKey: "shield.paused")
        controllers.removeAll(where: { $0.value == nil })
        for item in controllers {
            guard let controller = item.value else { continue }
            let id = ObjectIdentifier(controller)
            if hostByController[id] == host {
                tune(controller, for: host)
            }
        }
    }

    static func normalizedHost(_ host: String) -> String {
        let trimmed = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        return trimmed.hasPrefix("www.")
            ? String(trimmed.dropFirst(4)).trimmingCharacters(in: CharacterSet(charactersIn: "."))
            : trimmed
    }

    /// URL filter pattern matching the exact domain and its subdomains for network rules.
    nonisolated static func networkFilter(for domain: String) -> String {
        let escaped = NSRegularExpression.escapedPattern(for: domain)
        return "^https?://([^/]+\\.)?\(escaped)[:/]"
    }

    private static let spamTLDs: Set<String> = [
        "cfd", "buzz", "cam", "monster", "top", "click", "link",
        "gq", "tk", "ml", "ga", "cf", "work", "rest", "bar",
        "sbs", "beauty", "icu", "cyou", "hair", "skin", "quest",
        "surf", "fit", "live", "lat", "online", "bond", "life"
    ]

    static func isSpamTLD(_ host: String) -> Bool {
        let clean = normalizedHost(host)
        guard let tld = clean.split(separator: ".").last.map(String.init) else { return false }
        return spamTLDs.contains(tld)
    }

    static func baseDomain(of host: String) -> String {
        let clean = normalizedHost(host)
        let parts = clean.split(separator: ".").map(String.init)
        if parts.count <= 2 {
            return clean
        }
        let last2 = parts.suffix(2).joined(separator: ".")
        let commonDoubleTLDs: Set<String> = [
            "co.uk", "org.uk", "com.au", "net.au", "co.jp",
            "com.br", "co.id", "or.id", "go.id", "com.tr"
        ]
        if commonDoubleTLDs.contains(last2) && parts.count >= 3 {
            return parts.suffix(3).joined(separator: ".")
        }
        return last2
    }

    static func sameBaseDomain(_ hostA: String?, _ hostB: String?) -> Bool {
        guard let hostA, let hostB, !hostA.isEmpty, !hostB.isEmpty else { return false }
        return baseDomain(of: hostA) == baseDomain(of: hostB)
    }

    /// Popular legitimate platforms and CDNs that must never be classified as ad or badware domains.
    static let protectedPlatforms: Set<String> = [
        "youtube.com", "youtu.be", "google.com", "github.com", "github.io",
        "apple.com", "microsoft.com", "amazon.com", "amazonaws.com",
        "cloudflare.com", "facebook.com", "twitter.com", "x.com",
        "instagram.com", "reddit.com", "wikipedia.org", "discord.com",
        "discord.gg", "twitch.tv", "netflix.com", "spotify.com",
        "vimeo.com", "linkedin.com", "mediafire.com", "dropbox.com",
        "gitlab.com", "medium.com", "tiktok.com"
    ]

    static func isProtectedPlatform(_ host: String) -> Bool {
        let clean = normalizedHost(host)
        guard !clean.isEmpty else { return false }
        if protectedPlatforms.contains(clean) { return true }
        let base = baseDomain(of: clean)
        if protectedPlatforms.contains(base) { return true }
        if protectedPlatforms.contains(where: { clean.hasSuffix("." + $0) }) { return true }
        return false
    }

    /// Used for popup/redirect policies as well as content rules.
    func isAdDomain(_ host: String) -> Bool {
        let clean = Self.normalizedHost(host)
        guard !clean.isEmpty else { return false }
        if Self.isProtectedPlatform(clean) { return false }
        if Self.unwanted.contains(clean) { return true }
        if badwareDomains.contains(clean) { return true }
        let base = Self.baseDomain(of: clean)
        if Self.unwanted.contains(base) { return true }
        if badwareDomains.contains(base) { return true }
        if Self.unwanted.contains(where: { clean.hasSuffix("." + $0) }) { return true }
        if badwareDomains.contains(where: { clean.hasSuffix("." + $0) }) { return true }
        return false
    }

    /// Attach the cached compiled rule lists to a controller. Rule lists are immutable
    /// and shared; controllers remain private to their respective tabs.
    func protect(_ controller: WKUserContentController) {
        let id = ObjectIdentifier(controller)
        guard registered.insert(id).inserted else { return }
        controllers.append(WeakController(controller))
        if hostByController[id] == nil {
            hostByController[id] = ""
        }
        let host = hostByController[id]
        if enabled, !isPaused(on: host) {
            for list in ruleLists {
                controller.add(list)
            }
        }
        if ruleLists.isEmpty {
            compile()
        }
    }

    /// Apply the site's whitelist state before the next document loads.
    /// Preserves any non-Shield rule lists on the tab controller.
    func tune(_ controller: WKUserContentController, for host: String?) {
        let id = ObjectIdentifier(controller)
        let normalized = host.map(Self.normalizedHost) ?? ""
        hostByController[id] = normalized

        guard !ruleLists.isEmpty else {
            // Compilation still in flight; host is recorded in hostByController
            // and will be evaluated in install() once compilation finishes.
            return
        }

        for list in ruleLists {
            controller.remove(list)
        }
        if enabled, !isPaused(on: normalized) {
            for list in ruleLists {
                controller.add(list)
            }
        }
    }

    /// Apply global enabled/disabled state to all active tab controllers.
    func apply(to controllers: [WKUserContentController]) {
        guard !ruleLists.isEmpty else { return }
        for controller in controllers {
            for list in ruleLists {
                controller.remove(list)
            }
            let host = hostByController[ObjectIdentifier(controller)]
            if enabled, !isPaused(on: host) {
                for list in ruleLists {
                    controller.add(list)
                }
            }
        }
    }

    static var localFiltersDirectory: URL {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        return appSupport.appendingPathComponent("Search/Filters")
    }

    static func readManifest(in dir: URL) -> (hash: String, badware: Set<String>)? {
        let manifest = dir.appendingPathComponent("manifest.json")
        guard let data = try? Data(contentsOf: manifest),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let hash = json["filter_hash"] as? String, !hash.isEmpty else {
            return nil
        }
        let badwareList = json["badware_domains"] as? [String] ?? []
        return (String(hash.prefix(12)), Set(badwareList))
    }

    static func readFilterHash(in dir: URL) -> String? {
        readManifest(in: dir)?.hash
    }

    /// Dynamically discover and load all EasyList JSON chunk files from disk or bundle.
    static func discoverFilterURLs() -> (files: [URL], filterHash: String, badwareDomains: Set<String>) {
        var foundByFilename: [String: URL] = [:]

        func scan(dir: URL) {
            guard let contents = try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.isDirectoryKey]) else { return }
            for item in contents {
                var isDir: AnyObject?
                if (try? (item as NSURL).getResourceValue(&isDir, forKey: .isDirectoryKey)) != nil,
                   (isDir as? NSNumber)?.boolValue == true {
                    scan(dir: item)
                } else if item.pathExtension.lowercased() == "json", item.lastPathComponent.contains("easylist") {
                    let filename = item.lastPathComponent
                    if foundByFilename[filename] == nil {
                        foundByFilename[filename] = item
                    }
                }
            }
        }

        // 1. Check local Application Support directory (updated filters)
        let localDir = localFiltersDirectory
        if FileManager.default.fileExists(atPath: localDir.path) {
            scan(dir: localDir)
            if !foundByFilename.isEmpty {
                let manifestInfo = readManifest(in: localDir)
                let hash = manifestInfo?.hash ?? "local-v1"
                let badware = manifestInfo?.badware ?? []
                let sorted = foundByFilename.values.sorted {
                    $0.lastPathComponent.localizedStandardCompare($1.lastPathComponent) == .orderedAscending
                }
                return (sorted, hash, badware)
            }
        }

        // 2. Fall back to bundled resources
        #if SWIFT_PACKAGE
        let moduleBundle = Bundle.module
        scan(dir: moduleBundle.bundleURL)
        if let res = moduleBundle.resourceURL {
            scan(dir: res)
        }
        #endif

        if let mainRes = Bundle.main.resourceURL {
            scan(dir: mainRes)
        }

        // 3. Fall back to development source tree if running in tests or CLI
        if foundByFilename.isEmpty {
            let currentDir = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            scan(dir: currentDir.appendingPathComponent("Sources/Search/Resources/Filters"))
        }

        let sorted = foundByFilename.values.sorted {
            $0.lastPathComponent.localizedStandardCompare($1.lastPathComponent) == .orderedAscending
        }

        let bundleHash: String
        let bundleBadware: Set<String>
        if let first = sorted.first {
            let manifestInfo = readManifest(in: first.deletingLastPathComponent())
            bundleHash = manifestInfo?.hash ?? "bundled-v1"
            bundleBadware = manifestInfo?.badware ?? []
        } else {
            bundleHash = "fallback"
            bundleBadware = []
        }

        return (sorted, bundleHash, bundleBadware)
    }

    /// Compile or load rule lists asynchronously without blocking the main actor.
    func compile() {
        guard !loading, ruleLists.isEmpty else { return }
        guard let store = WKContentRuleListStore.default() else {
            trouble = "WebKit tidak dapat membuka penyimpanan aturan"
            return
        }
        loading = true
        trouble = nil

        let (files, hash, badware) = Self.discoverFilterURLs()
        self.badwareDomains = badware

        // 1. Immediately compile or load fallback rules so tabs are never unprotected
        compileFallback(in: store)

        guard !files.isEmpty else { return }

        self.activeFilterHash = hash

        // 2. Concurrently load full rule chunks in background and upgrade controllers
        Task {
            do {
                let compiled = try await Self.loadRuleLists(from: files, filterHash: hash, in: store)
                self.install(compiled)
            } catch {
                self.loading = false
                self.trouble = error.localizedDescription
            }
        }
    }

    private static func loadRuleLists(from files: [URL], filterHash: String, in store: WKContentRuleListStore) async throws -> [WKContentRuleList] {
        try await withThrowingTaskGroup(of: (Int, WKContentRuleList).self) { group in
            for (index, fileURL) in files.enumerated() {
                group.addTask {
                    let stem = fileURL.deletingPathExtension().lastPathComponent
                    let identifier = "search-shield-\(Self.engineVersion)-\(filterHash)-\(stem)"

                    // 1. Look up cached version first
                    if let cached = await lookup(store: store, identifier: identifier) {
                        return (index, cached)
                    }

                    // 2. Cache miss: read JSON and compile
                    let data = try Data(contentsOf: fileURL)
                    guard let json = String(data: data, encoding: .utf8) else {
                        throw NSError(domain: "Shield", code: 2, userInfo: [NSLocalizedDescriptionKey: "Berkas aturan \(stem) tidak valid"])
                    }
                    let compiled = try await compile(store: store, identifier: identifier, json: json)
                    return (index, compiled)
                }
            }

            var indexed: [(Int, WKContentRuleList)] = []
            for try await item in group {
                indexed.append(item)
            }
            return indexed.sorted(by: { $0.0 < $1.0 }).map(\.1)
        }
    }

    /// Background update of filter rules using adblock-rust engine.
    /// Downloads newest EasyList/EasyPrivacy, converts in a background Task, validates,
    /// compiles into WKContentRuleListStore, and atomically replaces active rulesets.
    func updateFilters(force: Bool = false) {
        guard let store = WKContentRuleListStore.default() else { return }

        Task {
            do {
                let (chunks, report) = try await AdblockEngine.updateFilters(chunkSize: 25_000)
                let newHash = String(report.filterHash.prefix(12))

                if !force, newHash == self.activeFilterHash {
                    return // Up-to-date
                }

                // 1. Pre-compile each new chunk into WKContentRuleListStore under new hash
                var compiledLists: [WKContentRuleList] = []
                for (index, chunkJson) in chunks.enumerated() {
                    let stem = "easylist_part_\(index + 1)"
                    let identifier = "search-shield-\(Self.engineVersion)-\(newHash)-\(stem)"
                    let list = try await Self.compile(store: store, identifier: identifier, json: chunkJson)
                    compiledLists.append(list)
                }

                // 2. Save new JSON chunks & manifest into local application support directory
                let targetDir = Self.localFiltersDirectory
                try FileManager.default.createDirectory(at: targetDir, withIntermediateDirectories: true)

                // Clean old files in local dir
                if let entries = try? FileManager.default.contentsOfDirectory(at: targetDir, includingPropertiesForKeys: nil) {
                    for entry in entries {
                        try? FileManager.default.removeItem(at: entry)
                    }
                }

                for (index, chunkJson) in chunks.enumerated() {
                    let fileURL = targetDir.appendingPathComponent("easylist_part_\(index + 1).json")
                    try chunkJson.write(to: fileURL, atomically: true, encoding: .utf8)
                }

                if let reportData = try? JSONEncoder().encode(report) {
                    let manifestURL = targetDir.appendingPathComponent("manifest.json")
                    try? reportData.write(to: manifestURL)
                }

                // 3. Atomically install new compiled rule lists
                self.activeFilterHash = newHash
                if let badware = report.badwareDomains {
                    self.badwareDomains = Set(badware)
                }
                self.install(compiledLists)
            } catch {
                self.trouble = "Pembaruan filter gagal: \(error.localizedDescription)"
            }
        }
    }

    private static func lookup(store: WKContentRuleListStore, identifier: String) async -> WKContentRuleList? {
        await withCheckedContinuation { continuation in
            store.lookUpContentRuleList(forIdentifier: identifier) { list, _ in
                continuation.resume(returning: list)
            }
        }
    }

    private static func compile(store: WKContentRuleListStore, identifier: String, json: String) async throws -> WKContentRuleList {
        try await withCheckedThrowingContinuation { continuation in
            store.compileContentRuleList(forIdentifier: identifier, encodedContentRuleList: json) { list, error in
                if let list {
                    continuation.resume(returning: list)
                } else {
                    continuation.resume(throwing: error ?? NSError(domain: "Shield", code: 1, userInfo: [NSLocalizedDescriptionKey: "Kompilasi aturan gagal"]))
                }
            }
        }
    }

    private func compileFallback(in store: WKContentRuleListStore) {
        Task {
            if let cached = await Self.lookup(store: store, identifier: Self.fallbackID) {
                self.install([cached])
                return
            }
            guard let data = try? JSONSerialization.data(withJSONObject: Self.fallbackRules),
                  let json = String(data: data, encoding: .utf8) else {
                self.loading = false
                self.trouble = "Tidak dapat menyiapkan aturan Shield dasar"
                return
            }
            do {
                let compiled = try await Self.compile(store: store, identifier: Self.fallbackID, json: json)
                self.install([compiled])
            } catch {
                self.loading = false
                self.trouble = error.localizedDescription
            }
        }
    }

    private func install(_ compiled: [WKContentRuleList]) {
        let previous = self.ruleLists
        self.ruleLists = compiled
        self.loading = false
        self.trouble = nil

        controllers.removeAll(where: { $0.value == nil })
        for item in controllers {
            guard let controller = item.value else { continue }
            let id = ObjectIdentifier(controller)
            let host = hostByController[id]
            for old in previous {
                controller.remove(old)
            }
            if enabled, !isPaused(on: host) {
                for list in compiled {
                    controller.remove(list)
                    controller.add(list)
                }
            }
        }
    }

    // MARK: - Fallback compact ruleset

    private static let unwanted: Set<String> = [
        "doubleclick.net", "googlesyndication.com", "googleadservices.com",
        "googletagservices.com", "adservice.google.com", "amazon-adsystem.com",
        "adnxs.com", "adsrvr.org", "criteo.com", "criteo.net", "taboola.com",
        "outbrain.com", "mgid.com", "revcontent.com", "rubiconproject.com",
        "pubmatic.com", "openx.net", "casalemedia.com", "smartadserver.com",
        "sharethrough.com", "indexww.com", "bidswitch.net", "33across.com",
        "teads.tv", "moatads.com", "adroll.com", "scorecardresearch.com",
        "quantserve.com", "hotjar.com", "mouseflow.com", "fullstory.com",
        "clarity.ms", "analytics.tiktok.com", "ads-twitter.com", "ads.linkedin.com",
        "pixel.facebook.com", "tr.snapchat.com",
        // Video streaming popunders, ad networks & deceptive fake captchas
        "ads.videy.co", "ads-api.videy.co", "ads2.videy.co", "ads3.videy.co",
        "clovepavedditch.com", "campfirecroutondecorator.com",
        "adsterra.com", "monetag.com", "propush.me", "clickadu.com", "hilltopads.net",
        "popcash.net", "popads.net", "richads.com", "exoclick.com", "juicyads.com",
        "trafficjunky.com", "ero-advertising.com", "yllix.com", "bidvertiser.com",
        "twinred.com", "adxad.com", "clickunder.net", "propellerads.com",
        "trafficfactory.biz", "zeroredirect1.com", "deloton.com", "onclickalgo.com",
        "syndication.exoclick.com", "vidoomy.com", "aniview.com", "adskeeper.co.uk",
        "traffichaus.com", "trafficstars.com", "clickcertain.com", "clksite.com",
        "popmyads.com", "propellerclick.com", "bet365.com", "1xbet.com", "betwinner.com",
        "worncalmy.cfd"
    ]

    private static let selectors = [
        ".adsbygoogle", "ins.adsbygoogle", "[id^=\"google_ads_\"]",
        "[id^=\"div-gpt-ad\"]", "[id^=\"taboola-\"]",
        "#taboola-below-article", "iframe[src*=\"doubleclick.net\"]",
        "iframe[src*=\"googlesyndication\"]", "iframe[src*=\"amazon-adsystem\"]",
        ".ad-slot", ".ad-slot-container", ".ad-leaderboard", ".ad-billboard",
        ".ad-mpu", ".ad-mrec", ".ad-unit", ".adunit", ".adslot", ".dfp-ad",
        ".gpt-ad", ".advertisement", ".ad-banner", ".banner-ad", ".ad-wrapper",
        ".ad-container", ".sponsored-post"
    ]

    private static let siteSelectors: [(sites: [String], selector: String)] = [
        (["*videy.co"], ".as, div.as, div[class*=\"as mt-4\"], a[href*=\"clovepavedditch.com\"], a[href*=\"campfire\"]"),
        (["*theguardian.com"], ".top-fronts-banner-ad-container"),
        (["*independent.co.uk", "*the-independent.com"], "#billboard-wrapper"),
        (["*cnn.com"], ".ad-slot-header__wrapper"),
        (["*detik.com"], ".banner-ad, [class*=\"ad_box\"]"),
        (["*kompas.com"], ".banner-ad, [id*=\"div-gpt-ad\"]")
    ]

    private static var fallbackRules: [[String: Any]] {
        let network: [[String: Any]] = unwanted.sorted().map { domain in
            [
                "trigger": [
                    "url-filter": networkFilter(for: domain),
                    "load-type": ["third-party"]
                ],
                "action": ["type": "block"]
            ]
        }
        let generic: [[String: Any]] = [[
            "trigger": ["url-filter": ".*"],
            "action": ["type": "css-display-none", "selector": selectors.joined(separator: ", ")]
        ]]
        let site: [[String: Any]] = siteSelectors.map { entry in
            [
                "trigger": ["url-filter": ".*", "if-domain": entry.sites],
                "action": ["type": "css-display-none", "selector": entry.selector]
            ]
        }
        let exceptions: [[String: Any]] = [
            // Ensure first-party documents load properly
            [
                "trigger": ["url-filter": ".*", "load-type": ["first-party"], "resource-type": ["document"]],
                "action": ["type": "ignore-previous-rules"]
            ],
            // Ensure video media streams on player CDNs are not blocked
            [
                "trigger": [
                    "url-filter": "^https?://([^/]+\\.)?(videy\\.co|googlevideo\\.com|akamaized\\.net|akamaihd\\.net|fastly\\.net|cloudfront\\.net)[:/].*",
                    "resource-type": ["media", "raw"]
                ],
                "action": ["type": "ignore-previous-rules"]
            ]
        ]
        return network + generic + site + exceptions
    }
}
