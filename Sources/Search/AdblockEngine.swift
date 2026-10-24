import CAdblock
import Foundation

/// Safe Swift wrapper around Brave's adblock-rust content blocking converter.
///
/// Converts EasyList, EasyPrivacy, AdGuard Safari Base, AdGuard Popups, and uBlock Badware risks
/// into partitioned Apple WKContentRuleList JSON chunks on demand, freeing all Rust memory immediately
/// upon completion.
enum AdblockEngine {
    static let easyListURL = URL(string: "https://easylist.to/easylist/easylist.txt")!
    static let easyPrivacyURL = URL(string: "https://easylist.to/easylist/easyprivacy.txt")!
    static let easyListFallbackURL = URL(string: "https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_block.txt")!
    static let adGuardSafariBaseURL = URL(string: "https://filters.adtidy.org/extension/safari/filters/2.txt")!
    static let adGuardTrackingURL = URL(string: "https://filters.adtidy.org/extension/safari/filters/3.txt")!
    static let adGuardAnnoyancesURL = URL(string: "https://filters.adtidy.org/extension/safari/filters/19.txt")!
    static let adGuardPopupsURL = URL(string: "https://filters.adtidy.org/extension/safari/filters/19.txt")!
    static let uBlockBadwareURL = URL(string: "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt")!

    struct FilterSource {
        let name: String
        let content: String
        let isBadware: Bool

        init(name: String, content: String, isBadware: Bool = false) {
            self.name = name
            self.content = content
            self.isBadware = isBadware
        }
    }

    struct ConversionReport: Codable, Sendable {
        let totalInputLines: Int
        let networkBlocksConverted: Int
        let networkExceptionsConverted: Int
        let cosmeticRulesConverted: Int
        let totalRulesGenerated: Int
        let chunkCount: Int
        let skippedRulesByReason: [String: Int]
        let filterHash: String
        let badwareDomains: [String]?

        enum CodingKeys: String, CodingKey {
            case totalInputLines = "total_input_lines"
            case networkBlocksConverted = "network_blocks_converted"
            case networkExceptionsConverted = "network_exceptions_converted"
            case cosmeticRulesConverted = "cosmetic_rules_converted"
            case totalRulesGenerated = "total_rules_generated"
            case chunkCount = "chunk_count"
            case skippedRulesByReason = "skipped_rules_by_reason"
            case filterHash = "filter_hash"
            case badwareDomains = "badware_domains"
        }
    }

    struct DiagnosticResult: Sendable {
        let isBlocked: Bool
        let isImportant: Bool
        let matchedFilter: String?
        let exceptionRule: String?
    }

    /// Evaluates a URL against adblock-rust rules to determine exact blocking or exception status.
    static func diagnose(
        rules: String,
        url: String,
        sourceURL: String,
        requestType: String = "other",
        method: String = "GET"
    ) throws -> DiagnosticResult {
        let cRules = rules.utf8CString
        let cUrl = url.utf8CString
        let cSource = sourceURL.utf8CString
        let cType = requestType.utf8CString
        let cMethod = method.utf8CString

        return try cRules.withUnsafeBufferPointer { rulesBuf in
            try cUrl.withUnsafeBufferPointer { urlBuf in
                try cSource.withUnsafeBufferPointer { sourceBuf in
                    try cType.withUnsafeBufferPointer { typeBuf in
                        try cMethod.withUnsafeBufferPointer { methodBuf in
                            let res = adblock_diagnose_request(
                                rulesBuf.baseAddress,
                                urlBuf.baseAddress,
                                sourceBuf.baseAddress,
                                typeBuf.baseAddress,
                                methodBuf.baseAddress
                            )
                            defer { adblock_free_diagnostic_result(res) }

                            if let errPtr = res.error_message {
                                throw NSError(domain: "AdblockEngine", code: 1, userInfo: [
                                    NSLocalizedDescriptionKey: String(cString: errPtr)
                                ])
                            }

                            let matched = res.matched_filter.map { String(cString: $0) }
                            let exception = res.exception_rule.map { String(cString: $0) }
                            return DiagnosticResult(
                                isBlocked: res.is_blocked,
                                isImportant: res.is_important,
                                matchedFilter: matched,
                                exceptionRule: exception
                            )
                        }
                    }
                }
            }
        }
    }

    /// Converts multiple filter sources into WebKit Content Blocker JSON chunks.
    static func convertSources(
        _ sources: [FilterSource],
        chunkSize: Int = 25_000
    ) throws -> (chunks: [String], report: ConversionReport) {
        guard !sources.isEmpty else {
            throw NSError(domain: "AdblockEngine", code: 2, userInfo: [NSLocalizedDescriptionKey: "No filter sources provided"])
        }

        let cSources = sources.map { src -> (name: ContiguousArray<CChar>, content: ContiguousArray<CChar>, isBadware: Bool) in
            return (src.name.utf8CString, src.content.utf8CString, src.isBadware)
        }

        func withCSourcesArray(
            index: Int,
            built: inout [CFilterSource],
            body: ([CFilterSource]) -> AdblockConversionResult
        ) -> AdblockConversionResult {
            if index == cSources.count {
                return body(built)
            }
            return cSources[index].name.withUnsafeBufferPointer { nameBuf in
                cSources[index].content.withUnsafeBufferPointer { contentBuf in
                    built.append(CFilterSource(
                        name: nameBuf.baseAddress,
                        content: contentBuf.baseAddress,
                        is_badware: cSources[index].isBadware
                    ))
                    let res = withCSourcesArray(index: index + 1, built: &built, body: body)
                    built.removeLast()
                    return res
                }
            }
        }

        var tempBuilt: [CFilterSource] = []
        tempBuilt.reserveCapacity(cSources.count)
        let rawResult = withCSourcesArray(index: 0, built: &tempBuilt) { cArray in
            cArray.withUnsafeBufferPointer { buf in
                adblock_convert_sources(buf.baseAddress, UInt32(buf.count), UInt32(max(1000, chunkSize)))
            }
        }
        defer { adblock_free_conversion_result(rawResult) }

        return try parseConversionResult(rawResult)
    }

    /// Converts raw EasyList and EasyPrivacy text into WebKit Content Blocker JSON chunks.
    /// Backward-compatible with previous callers.
    static func convert(
        easyList: String,
        easyPrivacy: String,
        chunkSize: Int = 25_000
    ) throws -> (chunks: [String], report: ConversionReport) {
        let sources = [
            FilterSource(name: "easylist", content: easyList, isBadware: false),
            FilterSource(name: "easyprivacy", content: easyPrivacy, isBadware: false)
        ]
        return try convertSources(sources, chunkSize: chunkSize)
    }

    private static func parseConversionResult(_ rawResult: AdblockConversionResult) throws -> (chunks: [String], report: ConversionReport) {
        if let errPtr = rawResult.error_message {
            let message = String(cString: errPtr)
            throw NSError(domain: "AdblockEngine", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
        }

        guard rawResult.chunk_count > 0, let chunkArray = rawResult.chunk_json_strings else {
            throw NSError(domain: "AdblockEngine", code: 2, userInfo: [NSLocalizedDescriptionKey: "No rule chunks generated"])
        }

        var chunks: [String] = []
        chunks.reserveCapacity(Int(rawResult.chunk_count))
        for i in 0..<Int(rawResult.chunk_count) {
            guard let ptr = chunkArray[i] else { continue }
            let json = String(cString: ptr)
            chunks.append(json)
        }

        let report: ConversionReport
        if let reportPtr = rawResult.report_json {
            let data = Data(String(cString: reportPtr).utf8)
            report = (try? JSONDecoder().decode(ConversionReport.self, from: data)) ?? ConversionReport(
                totalInputLines: 0,
                networkBlocksConverted: 0,
                networkExceptionsConverted: 0,
                cosmeticRulesConverted: 0,
                totalRulesGenerated: chunks.count,
                chunkCount: chunks.count,
                skippedRulesByReason: [:],
                filterHash: "",
                badwareDomains: nil
            )
        } else {
            report = ConversionReport(
                totalInputLines: 0,
                networkBlocksConverted: 0,
                networkExceptionsConverted: 0,
                cosmeticRulesConverted: 0,
                totalRulesGenerated: chunks.count,
                chunkCount: chunks.count,
                skippedRulesByReason: [:],
                filterHash: "",
                badwareDomains: nil
            )
        }

        // Validate JSON integrity for each chunk before returning
        for (index, json) in chunks.enumerated() {
            guard let data = json.data(using: .utf8),
                  (try? JSONSerialization.jsonObject(with: data)) != nil else {
                throw NSError(domain: "AdblockEngine", code: 3, userInfo: [
                    NSLocalizedDescriptionKey: "Generated chunk \(index + 1) contains invalid JSON"
                ])
            }
        }

        return (chunks, report)
    }

    /// Asynchronously fetch the latest EasyList, EasyPrivacy, AdGuard Safari Base, AdGuard Popups,
    /// and uBlock Badware lists and convert them in a background task.
    static func updateFilters(chunkSize: Int = 25_000) async throws -> (chunks: [String], report: ConversionReport) {
        let sources = try await fetchLatestLists()
        return try await Task.detached(priority: .utility) {
            try convertSources(sources, chunkSize: chunkSize)
        }.value
    }

    private static func fetchLatestLists() async throws -> [FilterSource] {
        async let agBase = fetchString(from: adGuardSafariBaseURL, fallback: nil)
        async let agTracking = fetchString(from: adGuardTrackingURL, fallback: nil)
        async let agAnnoyances = fetchString(from: adGuardAnnoyancesURL, fallback: nil)

        var sources: [FilterSource] = []
        if let agBaseText = try? await agBase, !agBaseText.isEmpty {
            sources.append(FilterSource(name: "adguard_safari_base", content: agBaseText, isBadware: false))
        }
        if let agTrackingText = try? await agTracking, !agTrackingText.isEmpty {
            sources.append(FilterSource(name: "adguard_tracking", content: agTrackingText, isBadware: false))
        }
        if let agAnnoyancesText = try? await agAnnoyances, !agAnnoyancesText.isEmpty {
            sources.append(FilterSource(name: "adguard_annoyances", content: agAnnoyancesText, isBadware: false))
        }

        guard !sources.isEmpty else {
            throw NSError(domain: "AdblockEngine", code: 4, userInfo: [
                NSLocalizedDescriptionKey: "Could not fetch any filter lists"
            ])
        }

        return sources
    }

    private static func fetchString(from url: URL, fallback: URL?) async throws -> String {
        var request = URLRequest(url: url)
        request.timeoutInterval = 25
        request.setValue("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15", forHTTPHeaderField: "User-Agent")

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            if let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode),
               let str = String(data: data, encoding: .utf8) {
                return str
            }
        } catch {
            // Try fallback
        }

        if let fallback {
            var fbReq = URLRequest(url: fallback)
            fbReq.timeoutInterval = 25
            fbReq.setValue("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15", forHTTPHeaderField: "User-Agent")
            let (data, response) = try await URLSession.shared.data(for: fbReq)
            if let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode),
               let str = String(data: data, encoding: .utf8) {
                return str
            }
        }

        throw NSError(domain: "AdblockEngine", code: 4, userInfo: [
            NSLocalizedDescriptionKey: "Could not fetch filter list from \(url.absoluteString)"
        ])
    }
}
