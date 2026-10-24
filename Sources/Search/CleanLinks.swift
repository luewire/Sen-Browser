import Foundation

/// Removes known marketing, tracking and analytics parameters from URLs
/// and provides safe scheme upgrades without DOM injection or background polling.
enum CleanLinks {
    /// Common tracking query parameters stripped from navigation URLs in O(1) time.
    static let trackingParameters: Set<String> = [
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
        "fbclid",
        "gclid",
        "dclid",
        "msclkid",
        "twclid",
        "mc_eid",
        "_hsenc",
        "_hsmi",
        "igshid",
    ]

    /// Checks if a query item key represents tracking data for the target host.
    static func isTracking(name: String, host: String?) -> Bool {
        let lower = name.lowercased()
        if lower == "si" {
            guard let host = host?.lowercased() else { return false }
            return host == "youtube.com" || host.hasSuffix(".youtube.com") || host == "youtu.be" || host.hasSuffix(".youtu.be")
        }
        return trackingParameters.contains(lower)
    }

    /// Strips tracking parameters from an HTTP/HTTPS address.
    /// Returns the cleaned URL if any parameter was removed, or nil if unchanged.
    static func strip(_ url: URL) -> URL? {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return nil
        }
        guard let queryItems = components.queryItems, !queryItems.isEmpty else {
            return nil
        }

        let host = components.host
        var changed = false
        let filtered = queryItems.filter { item in
            if isTracking(name: item.name, host: host) {
                changed = true
                return false
            }
            return true
        }

        guard changed else { return nil }

        components.queryItems = filtered.isEmpty ? nil : filtered
        return components.url
    }

    /// Upgrades an unencrypted HTTP URL to HTTPS, excluding local development servers.
    static func upgradeToHTTPS(_ url: URL) -> URL? {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == "http" else {
            return nil
        }
        if let host = components.host?.lowercased() {
            // Keep local servers and intranet addresses on plain HTTP
            if host == "localhost" || host == "127.0.0.1" || host == "0.0.0.0"
                || host.hasSuffix(".local") || host.hasSuffix(".internal")
                || host.contains(":")
                || host.split(separator: ".").allSatisfy({ UInt8($0) != nil }) {
                return nil
            }
        }
        components.scheme = "https"
        return components.url
    }
}
