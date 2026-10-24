import Foundation
import Network
import WebKit

/// The DNS resolver used for all browsing when Secure DNS is turned on.
enum DNSProvider: String, CaseIterable, Identifiable, Sendable {
    case system
    case cloudflare
    case adguard
    case quad9
    case custom

    var id: String { rawValue }

    var title: String {
        switch self {
        case .system: return "System"
        case .cloudflare: return "Cloudflare (1.1.1.1)"
        case .adguard: return "AdGuard"
        case .quad9: return "Quad9 (9.9.9.9)"
        case .custom: return "Custom"
        }
    }

    var dohURL: URL? {
        switch self {
        case .system:
            return nil
        case .cloudflare:
            return URL(string: "https://cloudflare-dns.com/dns-query")
        case .adguard:
            return URL(string: "https://dns.adguard-dns.com/dns-query")
        case .quad9:
            return URL(string: "https://dns.quad9.net/dns-query")
        case .custom:
            return nil
        }
    }

    var serverAddresses: [NWEndpoint] {
        switch self {
        case .cloudflare:
            return [
                .hostPort(host: "1.1.1.1", port: 443),
                .hostPort(host: "1.0.0.1", port: 443),
            ]
        case .adguard:
            return [
                .hostPort(host: "94.140.14.14", port: 443),
                .hostPort(host: "94.140.15.15", port: 443),
            ]
        case .quad9:
            return [
                .hostPort(host: "9.9.9.9", port: 443),
                .hostPort(host: "149.112.112.112", port: 443),
            ]
        case .system, .custom:
            return []
        }
    }
}

/// Routes WebKit's network requests through an in-process SOCKS5 loopback
/// proxy so that domain name resolutions happen exclusively over encrypted
/// DNS-over-HTTPS (DoH) via Network.framework's PrivacyContext.
@MainActor
final class SecureDNS {
    static let shared = SecureDNS()

    private let server = SOCKS5Server()
    private(set) var activeProxyConfigurations: [ProxyConfiguration] = []
    private var currentProvider: DNSProvider = .system
    private var currentCustomURL: String = ""

    private init() {}

    /// Applies the current DoH proxy configuration to a website data store.
    func apply(to store: WKWebsiteDataStore) {
        store.proxyConfigurations = activeProxyConfigurations
    }

    /// Re-evaluates the active provider and starts or stops the local bridge.
    func update(provider: DNSProvider, customURL: String?) {
        let cleanCustom = (customURL ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if provider == currentProvider && cleanCustom == currentCustomURL {
            return
        }
        currentProvider = provider
        currentCustomURL = cleanCustom

        guard provider != .system else {
            activeProxyConfigurations = []
            server.stop()
            applyToAllStores()
            return
        }

        let targetURL: URL?
        let servers: [NWEndpoint]
        if provider == .custom {
            if let parsed = URL(string: cleanCustom), parsed.scheme == "https", parsed.host != nil {
                targetURL = parsed
                servers = []
            } else {
                // Incomplete or invalid custom URL: disable proxy until a valid HTTPS URL is entered
                activeProxyConfigurations = []
                server.stop()
                applyToAllStores()
                return
            }
        } else {
            targetURL = provider.dohURL
            servers = provider.serverAddresses
        }

        guard let dohURL = targetURL else {
            activeProxyConfigurations = []
            server.stop()
            applyToAllStores()
            return
        }

        server.start(dohURL: dohURL, serverAddresses: servers) { [weak self] port in
            Task { @MainActor [weak self] in
                guard let self = self else { return }
                if let port = port {
                    let endpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!)
                    self.activeProxyConfigurations = [ProxyConfiguration(socksv5Proxy: endpoint)]
                } else {
                    self.activeProxyConfigurations = []
                }
                self.applyToAllStores()
            }
        }
    }

    /// Pushes the proxy configuration to every data store across all spaces and tabs.
    func applyToAllStores() {
        for store in Spaces.everyStore {
            apply(to: store)
        }
        for browser in Browsers.all {
            for tab in browser.tabs {
                apply(to: tab.store)
            }
        }
    }
}

/// An ephemeral local SOCKS5 listener that mediates WebKit requests and sends
/// them out through Network.framework NWConnections configured with a DoH PrivacyContext.
final class SOCKS5Server: @unchecked Sendable {
    private let queue = DispatchQueue(label: "search.securedns.server", qos: .userInitiated)
    private var listener: NWListener?
    private var privacyContext: NWParameters.PrivacyContext?
    private var sessions: [SOCKS5Session] = []

    func start(dohURL: URL, serverAddresses: [NWEndpoint], completion: @escaping @Sendable (UInt16?) -> Void) {
        queue.async { [weak self] in
            guard let self = self else { return }
            self.stopInternal()

            let ctx = NWParameters.PrivacyContext(description: "SearchDoHPrivacyContext")
            ctx.requireEncryptedNameResolution(true, fallbackResolver: .https(dohURL, serverAddresses: serverAddresses))
            self.privacyContext = ctx

            do {
                let params = NWParameters.tcp
                let listener = try NWListener(using: params)
                self.listener = listener

                listener.newConnectionHandler = { [weak self] inbound in
                    self?.accept(inbound)
                }

                listener.stateUpdateHandler = { [weak self, weak listener] state in
                    guard let self = self, let listener = listener else { return }
                    switch state {
                    case .ready:
                        if let port = listener.port?.rawValue {
                            completion(port)
                        }
                    case .failed, .cancelled:
                        self.stopInternal()
                        completion(nil)
                    default:
                        break
                    }
                }

                listener.start(queue: self.queue)
            } catch {
                completion(nil)
            }
        }
    }

    func stop() {
        queue.async { [weak self] in
            self?.stopInternal()
        }
    }

    private func stopInternal() {
        listener?.cancel()
        listener = nil
        privacyContext = nil
        for session in sessions {
            session.close()
        }
        sessions.removeAll()
    }

    private func accept(_ inbound: NWConnection) {
        guard let ctx = privacyContext else {
            inbound.cancel()
            return
        }
        let session = SOCKS5Session(inbound: inbound, queue: queue, privacyContext: ctx)
        sessions.append(session)
        session.onClose = { [weak self, weak session] in
            guard let self = self, let session = session else { return }
            self.sessions.removeAll { $0 === session }
        }
        session.start()
    }
}

/// Handles the SOCKS5 handshake (RFC 1928) for an individual incoming connection
/// and relays raw TCP data to the outbound NWConnection.
final class SOCKS5Session: @unchecked Sendable {
    private let inbound: NWConnection
    private var outbound: NWConnection?
    private let queue: DispatchQueue
    private let privacyContext: NWParameters.PrivacyContext
    private var buffer = Data()
    var onClose: (@Sendable () -> Void)?

    init(inbound: NWConnection, queue: DispatchQueue, privacyContext: NWParameters.PrivacyContext) {
        self.inbound = inbound
        self.queue = queue
        self.privacyContext = privacyContext
    }

    func start() {
        inbound.start(queue: queue)
        readGreeting()
    }

    private func readGreeting() {
        inbound.receive(minimumIncompleteLength: 1, maximumLength: 1024) { [weak self] data, _, isComplete, error in
            guard let self = self else { return }
            if let data = data, !data.isEmpty {
                self.buffer.append(data)
                self.processGreeting()
            } else if isComplete || error != nil {
                self.close()
            }
        }
    }

    private func processGreeting() {
        guard buffer.count >= 2 else {
            readGreeting()
            return
        }
        guard buffer[0] == 0x05 else {
            close()
            return
        }
        let nmethods = Int(buffer[1])
        guard buffer.count >= 2 + nmethods else {
            readGreeting()
            return
        }
        buffer.removeSubrange(0..<(2 + nmethods))
        let reply = Data([0x05, 0x00]) // No authentication required
        inbound.send(content: reply, completion: .contentProcessed { [weak self] error in
            guard let self = self, error == nil else {
                self?.close()
                return
            }
            self.readRequest()
        })
    }

    private func readRequest() {
        inbound.receive(minimumIncompleteLength: 1, maximumLength: 1024) { [weak self] data, _, isComplete, error in
            guard let self = self else { return }
            if let data = data, !data.isEmpty {
                self.buffer.append(data)
                self.processRequest()
            } else if isComplete || error != nil {
                self.close()
            }
        }
    }

    private func processRequest() {
        guard buffer.count >= 4 else {
            readRequest()
            return
        }
        // VER = 0x05, CMD = 0x01 (CONNECT)
        guard buffer[0] == 0x05, buffer[1] == 0x01 else {
            let rep = Data([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]) // Command not supported
            inbound.send(content: rep, completion: .contentProcessed { [weak self] _ in self?.close() })
            return
        }
        let atyp = buffer[3]
        var needed = 4
        if atyp == 0x01 { // IPv4
            needed += 4 + 2
        } else if atyp == 0x03 { // Domain name
            guard buffer.count >= 5 else { readRequest(); return }
            needed += 1 + Int(buffer[4]) + 2
        } else if atyp == 0x04 { // IPv6
            needed += 16 + 2
        } else {
            let rep = Data([0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]) // Address type not supported
            inbound.send(content: rep, completion: .contentProcessed { [weak self] _ in self?.close() })
            return
        }

        guard buffer.count >= needed else {
            readRequest()
            return
        }

        var host = ""
        var port: UInt16 = 0
        if atyp == 0x01 {
            host = "\(buffer[4]).\(buffer[5]).\(buffer[6]).\(buffer[7])"
            port = (UInt16(buffer[8]) << 8) | UInt16(buffer[9])
        } else if atyp == 0x03 {
            let len = Int(buffer[4])
            host = String(data: buffer[5..<(5 + len)], encoding: .utf8) ?? ""
            let p = 5 + len
            port = (UInt16(buffer[p]) << 8) | UInt16(buffer[p + 1])
        } else if atyp == 0x04 {
            var sin6 = in6_addr()
            _ = withUnsafeMutableBytes(of: &sin6) { ptr in
                buffer.copyBytes(to: ptr, from: 4..<20)
            }
            var strBuf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            inet_ntop(AF_INET6, &sin6, &strBuf, socklen_t(INET6_ADDRSTRLEN))
            host = String(cString: strBuf)
            port = (UInt16(buffer[20]) << 8) | UInt16(buffer[21])
        }

        buffer.removeSubrange(0..<needed)
        let leftover = buffer
        buffer.removeAll()

        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            close()
            return
        }

        connectOutbound(host: host, port: nwPort, leftover: leftover)
    }

    private func connectOutbound(host: String, port: NWEndpoint.Port, leftover: Data) {
        let params = NWParameters.tcp
        params.setPrivacyContext(privacyContext)
        let out = NWConnection(host: NWEndpoint.Host(host), port: port, using: params)
        self.outbound = out

        out.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            switch state {
            case .ready:
                let rep = Data([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]) // Succeeded
                self.inbound.send(content: rep, completion: .contentProcessed { [weak self] err in
                    guard let self = self, err == nil else {
                        self?.close()
                        return
                    }
                    if !leftover.isEmpty {
                        out.send(content: leftover, completion: .idempotent)
                    }
                    self.startRelay()
                })
            case .failed, .cancelled:
                let rep = Data([0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]) // Connection refused
                self.inbound.send(content: rep, completion: .contentProcessed { [weak self] _ in
                    self?.close()
                })
            default:
                break
            }
        }
        out.start(queue: queue)
    }

    private func startRelay() {
        guard let out = outbound else { return }
        pipe(from: inbound, to: out)
        pipe(from: out, to: inbound)
    }

    private func pipe(from src: NWConnection, to dst: NWConnection) {
        src.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self, weak src, weak dst] data, _, isComplete, error in
            guard let self = self, let dst = dst, let src = src else { return }
            if let data = data, !data.isEmpty {
                dst.send(content: data, completion: .contentProcessed { [weak self, weak src, weak dst] sendErr in
                    guard let self = self, let src = src, let dst = dst, sendErr == nil else {
                        self?.close()
                        return
                    }
                    self.pipe(from: src, to: dst)
                })
            } else {
                self.close()
            }
        }
    }

    func close() {
        inbound.cancel()
        outbound?.cancel()
        outbound = nil
        onClose?()
        onClose = nil
    }
}
