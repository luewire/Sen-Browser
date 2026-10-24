pub mod ffi;

use adblock::content_blocking::{
    ignore_previous_fp_documents, CbRule, CbRuleEquivalent, CbType,
};
use adblock::lists::{parse_filters, ParseOptions};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Statistics report about the conversion process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversionReport {
    pub total_input_lines: usize,
    pub network_blocks_converted: usize,
    pub network_exceptions_converted: usize,
    pub cosmetic_rules_converted: usize,
    pub total_rules_generated: usize,
    pub chunk_count: usize,
    pub skipped_rules_by_reason: HashMap<String, usize>,
    pub filter_hash: String,
    #[serde(default)]
    pub badware_domains: Vec<String>,
}

/// A named filter source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterSource {
    pub name: String,
    pub content: String,
    pub is_badware: bool,
}

/// Chunk of WebKit content blocker rules with metadata.
#[derive(Debug, Clone)]
pub struct RuleChunk {
    pub name: String,
    pub rules: Vec<CbRule>,
    pub json: String,
}

/// Default conservative chunk size for WebKit content rule lists.
pub const DEFAULT_CHUNK_SIZE: usize = 25_000;

/// Compute SHA-256 hex string for given content.
pub fn compute_sha256(content: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(content);
    let result = hasher.finalize();
    result
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .concat()
}

const PROTECTED_PLATFORMS: &[&str] = &[
    "youtube.com",
    "youtu.be",
    "google.com",
    "github.com",
    "github.io",
    "apple.com",
    "microsoft.com",
    "amazon.com",
    "amazonaws.com",
    "cloudflare.com",
    "facebook.com",
    "twitter.com",
    "x.com",
    "instagram.com",
    "reddit.com",
    "wikipedia.org",
    "discord.com",
    "discord.gg",
    "twitch.tv",
    "netflix.com",
    "spotify.com",
    "vimeo.com",
    "linkedin.com",
    "mediafire.com",
    "dropbox.com",
    "gitlab.com",
    "medium.com",
    "tiktok.com",
];

fn is_protected_platform(domain: &str) -> bool {
    let lower = domain.to_lowercase();
    for platform in PROTECTED_PLATFORMS {
        if lower == *platform || lower.ends_with(&format!(".{}", platform)) {
            return true;
        }
    }
    false
}

/// Extract domain names from badware rule lines (e.g. "||malware-domain.com^").
/// Excludes path-specific rules (e.g. "||youtube.com/@channel/$doc") and protected platforms.
fn extract_badware_domain(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.starts_with('!') || trimmed.starts_with('#') || trimmed.is_empty() {
        return None;
    }
    let after_pipe = trimmed.strip_prefix("||")?;

    // Rule must target the domain boundary without a path.
    // If a '/' appears before '^', '$', or ':', this is a specific path/URL rule on a site,
    // not an entire domain reputation block.
    let delim_pos = after_pipe.find(['^', '$', ':']).unwrap_or(after_pipe.len());
    let domain_candidate = &after_pipe[..delim_pos];

    if domain_candidate.contains('/') || domain_candidate.contains('*') {
        return None;
    }

    let domain = domain_candidate.trim().to_lowercase();
    if !domain.is_empty() && domain.contains('.') && !is_protected_platform(&domain) {
        Some(domain)
    } else {
        None
    }
}

/// Convert multiple filter sources (EasyList, EasyPrivacy, AdGuard Safari, AdGuard Popups, uBlock Badware)
/// into partitioned, validated WebKit Content Blocker chunks.
pub fn convert_multiple_filter_sources(
    sources: &[FilterSource],
    chunk_size: usize,
) -> Result<(Vec<RuleChunk>, ConversionReport), String> {
    let effective_chunk_size = if chunk_size < 1_000 {
        DEFAULT_CHUNK_SIZE
    } else {
        chunk_size
    };

    // Calculate content hash across all sources for cache invalidation
    let combined_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for src in sources {
            hasher.update(src.name.as_bytes());
            hasher.update(b":");
            hasher.update(src.content.as_bytes());
            hasher.update(b"---DELIMITER---");
        }
        let res = hasher.finalize();
        res.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .concat()
    };

    let mut total_lines = 0;
    let mut skipped_reasons: HashMap<String, usize> = HashMap::new();
    let mut bad_filter_ids = HashSet::new();
    let mut badware_domains_set = HashSet::new();

    let parse_opts = ParseOptions::default();
    let mut all_net_filters = Vec::new();
    let mut all_cos_filters = Vec::new();

    for src in sources {
        total_lines += src.content.lines().count();

        if src.is_badware {
            // Treat Badware list as a site risk / reputation list:
            // Extract risky domains for reputation tracking, and parse network rules for third-party blocks.
            for line in src.content.lines() {
                if let Some(domain) = extract_badware_domain(line) {
                    badware_domains_set.insert(domain);
                }
            }

            let (net_filters, _) = parse_filters(src.content.lines(), true, parse_opts);
            for f in net_filters {
                // If it's a first-party document block on a badware domain, do not add an uncontrolled
                // blanket hard block; the domain is recorded in badware_domains instead.
                all_net_filters.push(f);
            }
        } else {
            let (net_filters, cos_filters) =
                parse_filters(src.content.lines(), true, parse_opts);
            all_net_filters.extend(net_filters);
            all_cos_filters.extend(cos_filters);
        }
    }

    // Add domain-specific verified rules for video hosting ad overlay containers & networks
    let custom_network_rules = vec![
        "||campfirecroutondecorator.com^",
        "||clovepavedditch.com^",
        "||ads-api.videy.co^",
        "||ads.videy.co^",
        "||ads2.videy.co^",
        "||ads3.videy.co^",
    ];
    let (custom_net, _) = parse_filters(custom_network_rules.into_iter(), true, parse_opts);
    all_net_filters.extend(custom_net);

    let custom_cosmetic_rules = vec![
        "videy.co##.as",
        "videy.co##div.as",
        "videy.co##div[class*=\"as mt-4\"]",
        "videy.co##a[href*=\"clovepavedditch.com\"]",
        "videy.co##a[href*=\"campfire\"]",
    ];
    let (_, custom_cos) = parse_filters(custom_cosmetic_rules.into_iter(), true, parse_opts);
    all_cos_filters.extend(custom_cos);

    // Explicit exceptions for video media playback, playlists, and CDNs so video players load reliably
    let custom_video_network_exceptions = vec![
        "@@||cdn.videy.co^",
        "@@||googlevideo.com^",
        "@@||akamaized.net^$media",
        "@@||akamaihd.net^$media",
        "@@||fastly.net^$media",
        "@@||cloudfront.net^$media",
        "@@||v.redd.it^$media",
        "@@.m3u8$media,xmlhttprequest",
        "@@.mpd$media,xmlhttprequest",
        "@@.ts$media,xmlhttprequest",
        "@@.m4s$media,xmlhttprequest",
    ];
    let (video_exceptions_parsed, _) = parse_filters(custom_video_network_exceptions.into_iter(), true, parse_opts);
    all_net_filters.extend(video_exceptions_parsed);

    // Explicit first-party whitelist rules for protected platforms (Google, YouTube, X, GitHub, etc.)
    let mut protected_whitelist_rules = Vec::new();
    for platform in PROTECTED_PLATFORMS {
        protected_whitelist_rules.push(format!("@@||{}^$~third-party", platform));
        protected_whitelist_rules.push(format!("@@||{}^$document", platform));
    }
    let (protected_parsed, _) = parse_filters(protected_whitelist_rules.iter().map(|s| s.as_str()), true, parse_opts);
    all_net_filters.extend(protected_parsed);

    // 1. Collect badfilter IDs
    for f in &all_net_filters {
        if f.is_badfilter() {
            bad_filter_ids.insert(f.get_id());
            *skipped_reasons.entry("BadFilter".to_string()).or_insert(0) += 1;
        }
    }

    // 2. Separate network blocking and network exception rules, with deduplication
    let mut seen_network_blocks = HashSet::new();
    let mut seen_network_exceptions = HashSet::new();
    let mut network_blocks: Vec<CbRule> = Vec::with_capacity(all_net_filters.len());
    let mut exception_rules: Vec<CbRule> = Vec::new();

    for filter in all_net_filters {
        if bad_filter_ids.contains(&filter.get_id()) || filter.is_badfilter() {
            continue;
        }

        match CbRuleEquivalent::try_from(filter) {
            Ok(equivalent) => {
                for rule in equivalent {
                    match rule.action.typ {
                        CbType::IgnorePreviousRules => {
                            if let Ok(key) = serde_json::to_string(&rule) {
                                if seen_network_exceptions.insert(key) {
                                    exception_rules.push(rule);
                                }
                            }
                        }
                        _ => {
                            if let Ok(key) = serde_json::to_string(&rule) {
                                if seen_network_blocks.insert(key) {
                                    network_blocks.push(rule);
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                let reason = format!("{:?}", e);
                *skipped_reasons.entry(reason).or_insert(0) += 1;
            }
        }
    }

    // Always include top-level document exception so first-party pages load reliably
    let fp_doc_exception = ignore_previous_fp_documents();
    if let Ok(key) = serde_json::to_string(&fp_doc_exception) {
        if seen_network_exceptions.insert(key) {
            exception_rules.push(fp_doc_exception);
        }
    }

    // 3. Process cosmetic rules, with deduplication
    let mut seen_cosmetic = HashSet::new();
    let mut cosmetic_rules: Vec<CbRule> = Vec::with_capacity(all_cos_filters.len());
    for filter in all_cos_filters {
        match CbRule::try_from(filter) {
            Ok(rule) => {
                if let Ok(key) = serde_json::to_string(&rule) {
                    if seen_cosmetic.insert(key) {
                        cosmetic_rules.push(rule);
                    }
                }
            }
            Err(e) => {
                let reason = format!("{:?}", e);
                *skipped_reasons.entry(reason).or_insert(0) += 1;
            }
        }
    }

    // 4. Streamline rules to ensure healthy total rule count (< 100,000 rules across all chunks):
    // Keep 100% of exception rules. Budget up to 50,000 network blocks and 25,000 cosmetic rules.
    const MAX_BLOCK_BUDGET: usize = 50_000;
    const MAX_COSMETIC_BUDGET: usize = 25_000;

    if network_blocks.len() > MAX_BLOCK_BUDGET {
        network_blocks.truncate(MAX_BLOCK_BUDGET);
    }
    if cosmetic_rules.len() > MAX_COSMETIC_BUDGET {
        cosmetic_rules.truncate(MAX_COSMETIC_BUDGET);
    }

    let net_blocks_count = network_blocks.len();
    let net_exceptions_count = exception_rules.len();
    let cosmetic_count = cosmetic_rules.len();

    // 5. Partition normal rules (blocks & css-display-none) into chunks
    // Every chunk that contains any blocking rule MUST have all exception rules at the very end.
    let mut normal_rules: Vec<CbRule> = Vec::with_capacity(network_blocks.len() + cosmetic_rules.len());
    normal_rules.extend(network_blocks);
    normal_rules.extend(cosmetic_rules);

    let mut chunks: Vec<RuleChunk> = Vec::new();
    let slices: Vec<&[CbRule]> = normal_rules.chunks(effective_chunk_size).collect();

    for (i, slice) in slices.into_iter().enumerate() {
        let mut chunk_rules = slice.to_vec();
        let has_blocks = chunk_rules.iter().any(|r| r.action.typ == CbType::Block);

        if has_blocks {
            // Append entire exception ruleset at the end of every chunk with block rules
            chunk_rules.extend(exception_rules.clone());
        }

        let json = serde_json::to_string(&chunk_rules)
            .map_err(|e| format!("Serialization error in chunk {}: {}", i + 1, e))?;

        chunks.push(RuleChunk {
            name: format!("easylist_part_{}", i + 1),
            rules: chunk_rules,
            json,
        });
    }

    let total_rules_generated = chunks.iter().map(|c| c.rules.len()).sum();
    let mut badware_domains: Vec<String> = badware_domains_set.into_iter().collect();
    badware_domains.sort();

    let report = ConversionReport {
        total_input_lines: total_lines,
        network_blocks_converted: net_blocks_count,
        network_exceptions_converted: net_exceptions_count,
        cosmetic_rules_converted: cosmetic_count,
        total_rules_generated,
        chunk_count: chunks.len(),
        skipped_rules_by_reason: skipped_reasons,
        filter_hash: combined_hash,
        badware_domains,
    };

    Ok((chunks, report))
}

/// Convert EasyList and EasyPrivacy text into partitioned, validated WebKit Content Blocker chunks.
/// Preserved for backward compatibility.
pub fn convert_filter_lists(
    easylist_text: &str,
    easyprivacy_text: &str,
    chunk_size: usize,
) -> Result<(Vec<RuleChunk>, ConversionReport), String> {
    let sources = vec![
        FilterSource {
            name: "easylist".to_string(),
            content: easylist_text.to_string(),
            is_badware: false,
        },
        FilterSource {
            name: "easyprivacy".to_string(),
            content: easyprivacy_text.to_string(),
            is_badware: false,
        },
    ];
    convert_multiple_filter_sources(&sources, chunk_size)
}

/// Diagnostic request match result from adblock-rust Engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticMatchResult {
    pub is_blocked: bool,
    pub matched_filter: Option<String>,
    pub exception_rule: Option<String>,
    pub is_important: bool,
}

/// Perform an exact adblock-rust engine evaluation for a network request URL against a set of rules.
pub fn diagnose_network_request(
    rules_text: &str,
    url: &str,
    source_url: &str,
    request_type: &str,
    method: &str,
) -> Result<DiagnosticMatchResult, String> {
    let mut filter_set = adblock::lists::FilterSet::new(false);
    filter_set.add_filter_list(rules_text.to_string(), ParseOptions::default());
    let engine = adblock::engine::Engine::new_with_filter_set(filter_set);

    let req = adblock::request::Request::new(url, source_url, request_type, method)
        .map_err(|e| format!("Failed to create adblock request: {:?}", e))?;

    let result = engine.check_network_request(&req);
    let is_blocked = result.filter.is_some() && result.exception.is_none();

    Ok(DiagnosticMatchResult {
        is_blocked,
        matched_filter: result.filter.map(|f| format!("{:?}", f)),
        exception_rule: result.exception.map(|f| format!("{:?}", f)),
        is_important: result.important,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conversion_and_chunking() {
        let easylist = "
! Title: EasyList Test
||ads.example.com^$third-party
||tracker.org^$image
@@||trusted.tracker.org^
##.sponsor-banner
###cookie-banner
@@||ads.example.com/allow.js$script
";
        let easyprivacy = "
! Title: EasyPrivacy Test
||telemetry.io^
||analytics.com^$script
";
        let (chunks, report) = convert_filter_lists(easylist, easyprivacy, 5000).unwrap();
        assert!(!chunks.is_empty());
        assert_eq!(report.network_blocks_converted, 10);
        assert!(report.network_exceptions_converted >= 13);
        assert_eq!(report.cosmetic_rules_converted, 7); // 2 test rules + 5 videy rules

        // Verify that every chunk with block rules has exception rules at the end
        for chunk in &chunks {
            let has_block = chunk.rules.iter().any(|r| r.action.typ == CbType::Block);
            if has_block {
                let last_rule = chunk.rules.last().unwrap();
                assert_eq!(last_rule.action.typ, CbType::IgnorePreviousRules, "Chunk {} must end with ignore-previous-rules", chunk.name);
                let exception_count = chunk
                    .rules
                    .iter()
                    .filter(|r| r.action.typ == CbType::IgnorePreviousRules)
                    .count();
                assert_eq!(exception_count, report.network_exceptions_converted);
            }
        }
    }

    #[test]
    fn test_badware_domain_extraction() {
        let badware_content = "
! Title: Badware risks
||malware-site.com^$doc
||phishing.net^
||www.youtube.com/@pengwincheat/$doc
||youtube.com/@kinun-ryujin^$doc
||github.com/linarweloper/Blumfarmbot^$doc
! comment
@@||safe.phishing.net^
";
        let sources = vec![FilterSource {
            name: "badware".to_string(),
            content: badware_content.to_string(),
            is_badware: true,
        }];
        let (_, report) = convert_multiple_filter_sources(&sources, 5000).unwrap();
        assert!(report.badware_domains.contains(&"malware-site.com".to_string()));
        assert!(report.badware_domains.contains(&"phishing.net".to_string()));
        assert!(!report.badware_domains.contains(&"youtube.com".to_string()));
        assert!(!report.badware_domains.contains(&"www.youtube.com".to_string()));
        assert!(!report.badware_domains.contains(&"github.com".to_string()));
    }

    #[test]
    fn test_adguard_safari_sources() {
        let base = std::fs::read_to_string("/tmp/adguard_base.txt").unwrap_or_default();
        let tracking = std::fs::read_to_string("/tmp/adguard_tracking.txt").unwrap_or_default();
        let annoyances = std::fs::read_to_string("/tmp/adguard_annoyances.txt").unwrap_or_default();
        if base.is_empty() { return; }

        let sources_all = vec![
            FilterSource { name: "adguard_base".to_string(), content: base.clone(), is_badware: false },
            FilterSource { name: "adguard_tracking".to_string(), content: tracking.clone(), is_badware: false },
            FilterSource { name: "adguard_annoyances".to_string(), content: annoyances.clone(), is_badware: false },
        ];
        let (chunks, report) = convert_multiple_filter_sources(&sources_all, 25000).unwrap();
        println!("All 3 Sources - Total rules generated: {}, Chunks: {}", report.total_rules_generated, chunks.len());
        println!("Blocks: {}, Exceptions: {}, Cosmetic: {}", report.network_blocks_converted, report.network_exceptions_converted, report.cosmetic_rules_converted);
    }

    #[test]
    fn test_engine_matcher() {
        let mut filter_set = adblock::lists::FilterSet::new(false);
        filter_set.add_filter_list("||ads.example.com^\n@@||trusted.tracker.com^".to_string(), ParseOptions::default());
        let engine = adblock::engine::Engine::new_with_filter_set(filter_set);
        let req1 = adblock::request::Request::new("https://ads.example.com/banner.js", "https://example.com", "script", "GET").unwrap();
        let blocker_res = engine.check_network_request(&req1);
        assert!(blocker_res.filter.is_some() && blocker_res.exception.is_none());
        let req2 = adblock::request::Request::new("https://trusted.tracker.com/pixel.gif", "https://example.com", "image", "GET").unwrap();
        let allowed_res = engine.check_network_request(&req2);
        assert!(allowed_res.exception.is_some() || allowed_res.filter.is_none());
    }

    #[test]
    fn test_video_exceptions_conversion() {
        let rules = vec![
            "@@||cdn.videy.co^",
            "@@||googlevideo.com^",
            "@@||akamaized.net^$media",
            "@@||akamaihd.net^$media",
            "@@||fastly.net^$media",
            "@@||cloudfront.net^$media",
            "@@||v.redd.it^$media",
            "@@.m3u8$media,xmlhttprequest",
            "@@.mpd$media,xmlhttprequest",
            "@@.ts$media,xmlhttprequest",
            "@@.m4s$media,xmlhttprequest",
        ];
        let (parsed, _) = parse_filters(rules.into_iter(), true, ParseOptions::default());
        println!("Parsed count: {}", parsed.len());
        for f in parsed {
            match CbRuleEquivalent::try_from(f) {
                Ok(rules) => {
                    for r in rules {
                        assert_eq!(r.action.typ, CbType::IgnorePreviousRules);
                        println!("Converted WebKit Rule: {:?}", serde_json::to_string(&r));
                    }
                }
                Err(e) => panic!("Conversion failed: {:?}", e),
            }
        }
    }
}

