import SwiftUI

// Lightweight Shield UI & Controller:
// - Designed specifically for video streaming site compatibility and low CPU/memory overhead.
// - Provides a one-click action to disable protection and reload if a video player fails to load.
// - Displays estimated blocked item count without continuous background scripts.

struct ShieldButton: View {
    @Environment(\.greys) private var greys
    @ObservedObject var browser: Browser
    @ObservedObject var shield = Shield.shared
    @State private var showing = false
    @State private var hovering = false
    var arrowEdge: Edge = .bottom

    private var currentTab: Tab? { browser.active }
    private var host: String? { currentTab?.address?.host().map(Shield.normalizedHost) }
    private var isActive: Bool { shield.isActive(on: host) && browser.prefs.shielded }
    private var blockedCount: Int {
        currentTab?.blockedPopups.count ?? 0
    }

    private static let shieldOrange = Color(red: 1.0, green: 0.38, blue: 0.14)

    var body: some View {
        Button {
            showing.toggle()
        } label: {
            HStack(spacing: 3) {
                Image(systemName: isActive ? "shield.fill" : "shield.slash.fill")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(isActive ? ShieldButton.shieldOrange : Palette.muted)

                if isActive && blockedCount > 0 {
                    Text("\(blockedCount)")
                        .font(.system(size: 9, weight: .bold, design: .rounded))
                        .foregroundStyle(ShieldButton.shieldOrange)
                        .padding(.horizontal, 3)
                        .padding(.vertical, 1)
                        .background(
                            Capsule().fill(ShieldButton.shieldOrange.opacity(0.16))
                        )
                }
            }
            .frame(minWidth: 26, minHeight: 26)
            .padding(.horizontal, blockedCount > 0 ? 5 : 0)
            .contentShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .background(
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(showing ? greys.wash : (hovering ? greys.hover : Color.clear))
            )
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .help(!browser.prefs.shielded || !shield.enabled
            ? "Shield dimatikan secara global"
            : (isActive ? "Shield aktif (\(blockedCount) pop-up dicegah)" : "Shield dimatikan untuk situs ini"))
        .popover(isPresented: $showing, arrowEdge: arrowEdge) {
            if let tab = currentTab {
                ShieldPopoverCard(browser: browser, tab: tab, host: host ?? "Situs Ini")
            } else {
                Text("Tidak ada halaman aktif")
                    .padding()
            }
        }
    }
}

struct ShieldPopoverCard: View {
    @ObservedObject var browser: Browser
    @ObservedObject var tab: Tab
    @ObservedObject var shield = Shield.shared
    let host: String

    private var cleanHost: String { Shield.normalizedHost(host) }
    private var isGlobalEnabled: Bool { shield.enabled && browser.prefs.shielded }
    private var isSitePaused: Bool { shield.isPaused(on: cleanHost) }
    private var isActive: Bool { isGlobalEnabled && !isSitePaused }
    private var blockedPopups: Int { tab.blockedPopups.count }

    private static let shieldOrange = Color(red: 1.0, green: 0.38, blue: 0.14)

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            // Header
            HStack(spacing: 10) {
                ZStack {
                    Circle()
                        .fill((isActive ? ShieldPopoverCard.shieldOrange : Color.gray).opacity(0.15))
                        .frame(width: 32, height: 32)
                    Image(systemName: isActive ? "shield.fill" : "shield.slash.fill")
                        .font(.system(size: 15, weight: .bold))
                        .foregroundStyle(isActive ? ShieldPopoverCard.shieldOrange : Color.gray)
                }

                VStack(alignment: .leading, spacing: 2) {
                    Text(cleanHost)
                        .font(.system(size: 13, weight: .semibold))
                        .lineLimit(1)
                    Text(!isGlobalEnabled ? "Shield nonaktif (Global)" : (isSitePaused ? "Shield dimatikan" : "Perlindungan aktif"))
                        .font(.system(size: 11))
                        .foregroundStyle(isActive ? ShieldPopoverCard.shieldOrange : Palette.muted)
                }

                Spacer(minLength: 8)

                // Quick Switch
                Toggle("", isOn: Binding(
                    get: { isActive },
                    set: { active in
                        if active {
                            if !browser.prefs.shielded {
                                browser.prefs.shielded = true
                            }
                            if !shield.enabled {
                                shield.enabled = true
                            }
                            shield.pause(cleanHost, false)
                        } else {
                            shield.pause(cleanHost, true)
                        }
                        tab.reload()
                    }
                ))
                .toggleStyle(.switch)
                .tint(ShieldPopoverCard.shieldOrange)
            }

            Divider()

            // Statistics (Estimated)
            VStack(spacing: 7) {
                HStack {
                    Label {
                        Text("Pop-up & redirect dicegah")
                            .font(.system(size: 11.5))
                    } icon: {
                        Image(systemName: "hand.raised.fill")
                            .font(.system(size: 11))
                            .foregroundStyle(isActive ? ShieldPopoverCard.shieldOrange : Palette.muted)
                    }
                    Spacer()
                    Text("\(blockedPopups)")
                        .font(.system(size: 12, weight: .bold, design: .rounded))
                        .foregroundStyle(isActive ? Palette.ink : Palette.muted)
                }
            }
            .padding(.vertical, 2)

            Divider()

            // Actions & Explanations
            VStack(alignment: .leading, spacing: 6) {
                if isActive {
                    Button {
                        shield.pause(cleanHost, true)
                        tab.reload()
                    } label: {
                        HStack(spacing: 6) {
                            Image(systemName: "arrow.clockwise")
                                .font(.system(size: 11, weight: .semibold))
                            Text("Matikan Shield & Muat Ulang")
                                .font(.system(size: 11.5, weight: .medium))
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 6)
                        .background(Palette.hover)
                        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                    }
                    .buttonStyle(.plain)

                    Text("Jika situs mengalami kendala tampilan atau fungsi macet, matikan Shield khusus untuk situs ini.")
                        .font(.system(size: 9.5))
                        .foregroundStyle(Palette.muted)
                        .lineSpacing(1.5)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    Button {
                        if !browser.prefs.shielded {
                            browser.prefs.shielded = true
                        }
                        if !shield.enabled {
                            shield.enabled = true
                        }
                        shield.pause(cleanHost, false)
                        tab.reload()
                    } label: {
                        HStack(spacing: 6) {
                            Image(systemName: "shield.fill")
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundStyle(ShieldPopoverCard.shieldOrange)
                            Text("Aktifkan Kembali Shield")
                                .font(.system(size: 11.5, weight: .medium))
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 6)
                        .background(Palette.hover)
                        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                    }
                    .buttonStyle(.plain)

                    Text(!isGlobalEnabled
                        ? "Shield saat ini dinonaktifkan secara global di Pengaturan."
                        : "Shield saat ini dinonaktifkan khusus untuk situs ini.")
                        .font(.system(size: 9.5))
                        .foregroundStyle(Palette.muted)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(.top, 2)
        }
        .padding(13)
        .frame(width: 290)
    }
}

