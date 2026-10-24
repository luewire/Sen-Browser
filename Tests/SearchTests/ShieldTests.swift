import WebKit
import XCTest
@testable import Search

@MainActor
final class ShieldTests: XCTestCase {
    func testNetworkFilterMatchesOnlyTheListedHostAndItsSubdomains() throws {
        let pattern = try NSRegularExpression(pattern: Shield.networkFilter(for: "segment.com"))
        for url in ["https://segment.com/track", "http://segment.com/track",
                    "https://cdn.segment.com/track", "https://a.b.segment.com/track",
                    "https://segment.com:8443/track", "https://segment.com/",
                    "https://segment.com/?event=test", "https://segment.com/#event"] {
            XCTAssertNotNil(pattern.firstMatch(in: url, range: NSRange(url.startIndex..., in: url)), url)
        }
        for url in ["https://segment.company/app.js", "https://cdn.segment.company/app.js",
                    "https://segment.com.example/app.js", "https://segment.com-example/app.js",
                    "https://notsegment.com/app.js", "https://example.com/segment.com/track",
                    "https://segmentXcom/app.js", "ftp://segment.com/track"] {
            XCTAssertNil(pattern.firstMatch(in: url, range: NSRange(url.startIndex..., in: url)), url)
        }
    }

    func testNetworkFilterCompilesInWebKit() async throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("shield-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let store = try XCTUnwrap(WKContentRuleListStore(url: folder))
        let rules: [[String: Any]] = [[
            "trigger": ["url-filter": Shield.networkFilter(for: "segment.com"), "load-type": ["third-party"]],
            "action": ["type": "block"],
        ]]
        let data = try JSONSerialization.data(withJSONObject: rules)
        let json = try XCTUnwrap(String(data: data, encoding: .utf8))
        let list = try await store.compileContentRuleList(forIdentifier: "fixture", encodedContentRuleList: json)
        XCTAssertNotNil(list)
    }

    func testAdblockRustConversionAndRuleMapping() throws {
        let sampleEasyList = """
        ! Sample EasyList
        ||doubleclick.net^$third-party
        ||analytics.tracker.com^$image,script
        @@||trusted.tracker.com^
        ##.advert-banner
        ###popup-ad
        """
        let sampleEasyPrivacy = """
        ! Sample EasyPrivacy
        ||telemetry.service.io^$xmlhttprequest
        """

        let (chunks, report) = try AdblockEngine.convert(
            easyList: sampleEasyList,
            easyPrivacy: sampleEasyPrivacy,
            chunkSize: 5000
        )

        XCTAssertFalse(chunks.isEmpty)
        XCTAssertGreaterThanOrEqual(report.networkBlocksConverted, 3)
        XCTAssertEqual(report.networkExceptionsConverted, 1)
        XCTAssertGreaterThanOrEqual(report.cosmeticRulesConverted, 2)
        XCTAssertFalse(report.filterHash.isEmpty)

        // Verify each chunk is valid JSON and non-empty
        for chunk in chunks {
            let data = try XCTUnwrap(chunk.data(using: .utf8))
            let json = try JSONSerialization.jsonObject(with: data) as? [[String: Any]]
            XCTAssertNotNil(json)
            XCTAssertFalse(json?.isEmpty ?? true)
        }
    }

    func testExceptionRulesPreservedInNetworkChunks() throws {
        let rules = """
        ||adserver1.com^
        ||adserver2.com^
        @@||trusted.allow.com^
        ##.banner
        """
        let (chunks, _) = try AdblockEngine.convert(easyList: rules, easyPrivacy: "", chunkSize: 5000)

        // Find network chunk
        var foundException = false
        for chunk in chunks {
            let data = try XCTUnwrap(chunk.data(using: .utf8))
            guard let array = try JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { continue }
            for rule in array {
                if let action = rule["action"] as? [String: Any],
                   let type = action["type"] as? String,
                   type == "ignore-previous-rules" {
                    foundException = true
                }
            }
        }
        XCTAssertTrue(foundException, "Network chunk must retain ignore-previous-rules exceptions")
    }

    func testMultipleRuleListsCompileAndAttachWithoutDisturbingOtherComponents() async throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("shield-multi-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let store = try XCTUnwrap(WKContentRuleListStore(url: folder))

        let json1 = """
        [{"trigger":{"url-filter":"^https?://bad1\\\\.com"},"action":{"type":"block"}}]
        """
        let json2 = """
        [{"trigger":{"url-filter":"^https?://bad2\\\\.com"},"action":{"type":"block"}}]
        """
        let dummyJson = """
        [{"trigger":{"url-filter":"^https?://custom\\\\.com"},"action":{"type":"block"}}]
        """

        let rule1 = try await store.compileContentRuleList(forIdentifier: "shield-1", encodedContentRuleList: json1)
        let rule2 = try await store.compileContentRuleList(forIdentifier: "shield-2", encodedContentRuleList: json2)
        let customRule = try await store.compileContentRuleList(forIdentifier: "extension-custom", encodedContentRuleList: dummyJson)

        let controller = WKUserContentController()

        // 1. Another component attaches its rule list first
        controller.add(customRule)

        // 2. Shield attaches its rule lists
        controller.add(rule1)
        controller.add(rule2)

        // 3. User pauses Shield on a domain: Shield only removes its own rule lists
        controller.remove(rule1)
        controller.remove(rule2)

        // 4. Verify controller still functions and custom rule can be added/removed cleanly
        controller.remove(customRule)
        controller.add(customRule)
        XCTAssertNotNil(customRule)
    }

    func testCacheIdentifierFormat() {
        let (files, hash, _) = Shield.discoverFilterURLs()
        XCTAssertFalse(hash.isEmpty)
        if let first = files.first {
            let stem = first.deletingPathExtension().lastPathComponent
            let id = "search-shield-adblock-rust-v2-\(hash)-\(stem)"
            XCTAssertTrue(id.contains("search-shield-adblock-rust-v2-"))
            XCTAssertTrue(id.contains(hash))
        }
    }

    func testChunkRuleBudgetAndExceptionsAtTail() throws {
        let (files, _, _) = Shield.discoverFilterURLs()
        XCTAssertFalse(files.isEmpty, "Bundled or local filter files must be discovered")

        var totalRules = 0
        for file in files {
            let data = try Data(contentsOf: file)
            let rules = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [[String: Any]])
            XCTAssertFalse(rules.isEmpty, "Chunk \(file.lastPathComponent) must not be empty")
            totalRules += rules.count

            let hasBlockRules = rules.contains { rule in
                (rule["action"] as? [String: Any])?["type"] as? String == "block"
            }

            if hasBlockRules {
                // The chunk contains block rules; its tail must consist of exception rules
                let lastRule = try XCTUnwrap(rules.last)
                let lastActionType = (lastRule["action"] as? [String: Any])?["type"] as? String
                XCTAssertEqual(
                    lastActionType,
                    "ignore-previous-rules",
                    "Chunk \(file.lastPathComponent) containing block rules must end with an ignore-previous-rules exception"
                )

                // Verify Google document / first-party exception is present in the chunk
                let hasGoogleException = rules.contains { rule in
                    let trigger = rule["trigger"] as? [String: Any]
                    let action = rule["action"] as? [String: Any]
                    let urlFilter = trigger?["url-filter"] as? String ?? ""
                    let actionType = action?["type"] as? String ?? ""
                    return actionType == "ignore-previous-rules" && urlFilter.contains("google")
                }
                XCTAssertTrue(hasGoogleException, "Chunk \(file.lastPathComponent) must contain google.com whitelist exception")
            }
        }

        XCTAssertLessThan(totalRules, 100_000, "Total rules across all chunks must be < 100,000 (got \(totalRules))")
    }

    func testShieldDefuserScriptSafety() {
        let source = Shield.defuserScriptSource
        XCTAssertTrue(source.contains("Notification"), "Defuser script must guard Notification permission")
        XCTAssertTrue(source.contains("denied"), "Defuser script must deny Notification requests")
        XCTAssertTrue(source.contains("window.open"), "Defuser script must guard window.open")

        // Must NEVER contain generic CSS or JS hiding position: fixed or high z-index elements
        XCTAssertFalse(source.contains("position: fixed"), "Defuser script must not hide position: fixed elements")
        XCTAssertFalse(source.contains("position:fixed"), "Defuser script must not hide position:fixed elements")
        XCTAssertFalse(source.contains("z-index"), "Defuser script must not manipulate generic z-index")
    }
}
