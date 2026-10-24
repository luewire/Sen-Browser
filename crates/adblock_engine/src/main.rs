use adblock_engine::{convert_multiple_filter_sources, FilterSource, DEFAULT_CHUNK_SIZE};
use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

const DEFAULT_ADGUARD_BASE_URL: &str = "https://filters.adtidy.org/extension/safari/filters/2.txt";
const DEFAULT_ADGUARD_TRACKING_URL: &str = "https://filters.adtidy.org/extension/safari/filters/3.txt";
const DEFAULT_ADGUARD_ANNOYANCES_URL: &str = "https://filters.adtidy.org/extension/safari/filters/19.txt";

fn fetch_or_read_cached(source: &str, cache_name: &str, fallback: Option<&str>) -> Result<String, String> {
    let p = Path::new(source);
    if p.exists() {
        println!("[*] Reading from local file: {}", source);
        return fs::read_to_string(p).map_err(|e| format!("Failed to read {}: {}", source, e));
    }

    // Check disk cache in crates/adblock_engine/cache and crates/adblock_engine/.cache
    let cache_dirs = [
        PathBuf::from("crates/adblock_engine/cache"),
        PathBuf::from("crates/adblock_engine/.cache"),
    ];
    let possible_names = [
        format!("{}.txt", cache_name),
        format!("{}.txt", cache_name.replace("adguard_safari_base", "adguard_base")),
        format!("{}.txt", cache_name.replace("adguard_safari_base", "adguard_safari")),
    ];

    for dir in &cache_dirs {
        for name in &possible_names {
            let cache_file = dir.join(name);
            if cache_file.exists() {
                if let Ok(content) = fs::read_to_string(&cache_file) {
                    if !content.trim().is_empty() {
                        println!("[*] Using cached filter from {:?} ({} bytes)", cache_file, content.len());
                        return Ok(content);
                    }
                }
            }
        }
    }

    println!("[*] Downloading filter from: {}", source);
    let cache_dir = PathBuf::from("crates/adblock_engine/.cache");
    let cache_file = cache_dir.join(format!("{}.txt", cache_name));
    let mut urls = vec![source];
    if let Some(fb) = fallback {
        urls.push(fb);
    }

    let client = ureq::builder()
        .timeout(std::time::Duration::from_secs(35))
        .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15")
        .build();

    let mut last_err = String::new();
    for url in urls {
        match client.get(url).call() {
            Ok(resp) => {
                let mut reader = resp.into_reader();
                let mut text = String::new();
                if let Ok(bytes) = reader.read_to_string(&mut text) {
                    println!("[+] Successfully downloaded {} ({} bytes)", url, bytes);
                    let _ = fs::create_dir_all(&cache_dir);
                    let _ = fs::write(&cache_file, &text);
                    return Ok(text);
                }
            }
            Err(e) => {
                eprintln!("[!] Warning: failed to fetch from {}: {}", url, e);
                last_err = format!("{}", e);
            }
        }
    }

    // If fetch failed but old cache exists, use old cache
    if cache_file.exists() {
        if let Ok(content) = fs::read_to_string(&cache_file) {
            if !content.is_empty() {
                eprintln!("[!] Fetch failed, falling back to existing cache for {}", cache_name);
                return Ok(content);
            }
        }
    }

    Err(format!("Could not fetch {}: {}", source, last_err))
}

fn print_usage() {
    println!(
        "Usage: adblock_engine [OPTIONS]\n\n\
        Options:\n  \
          --adguard-base <path-or-url>       Path or URL to AdGuard Safari Base (2.txt)\n  \
          --adguard-tracking <path-or-url>   Path or URL to AdGuard Tracking Protection (3.txt)\n  \
          --adguard-annoyances <path-or-url> Path or URL to AdGuard Annoyances/Popups (19.txt)\n  \
          --output-dir <dir>                 Output directory for JSON chunks (default: Sources/Search/Resources/Filters)\n  \
          --chunk-size <num>                 Maximum rules per chunk (default: {})\n  \
          --help                             Print this help message",
        DEFAULT_CHUNK_SIZE
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut adguard_base_src = DEFAULT_ADGUARD_BASE_URL.to_string();
    let mut adguard_tracking_src = DEFAULT_ADGUARD_TRACKING_URL.to_string();
    let mut adguard_annoyances_src = DEFAULT_ADGUARD_ANNOYANCES_URL.to_string();
    let mut output_dir = PathBuf::from("Sources/Search/Resources/Filters");
    let mut chunk_size = DEFAULT_CHUNK_SIZE;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--adguard-base" | "--easylist" => {
                if i + 1 < args.len() {
                    adguard_base_src = args[i + 1].clone();
                    i += 1;
                }
            }
            "--adguard-tracking" | "--easyprivacy" => {
                if i + 1 < args.len() {
                    adguard_tracking_src = args[i + 1].clone();
                    i += 1;
                }
            }
            "--adguard-annoyances" | "--adguard-popups" => {
                if i + 1 < args.len() {
                    adguard_annoyances_src = args[i + 1].clone();
                    i += 1;
                }
            }
            "--output-dir" => {
                if i + 1 < args.len() {
                    output_dir = PathBuf::from(&args[i + 1]);
                    i += 1;
                }
            }
            "--chunk-size" => {
                if i + 1 < args.len() {
                    if let Ok(val) = args[i + 1].parse::<usize>() {
                        chunk_size = val;
                    }
                    i += 1;
                }
            }
            "--help" | "-h" => {
                print_usage();
                return;
            }
            other => {
                output_dir = PathBuf::from(other);
            }
        }
        i += 1;
    }

    println!("============================================================");
    println!(" Search Shield - AdGuard Safari Optimized Filter Compiler");
    println!("============================================================");

    let mut sources = Vec::new();

    // 1. AdGuard Base Filter (Safari 2.txt)
    if !adguard_base_src.is_empty() {
        match fetch_or_read_cached(&adguard_base_src, "adguard_safari_base", None) {
            Ok(c) => sources.push(FilterSource { name: "adguard_safari_base".to_string(), content: c, is_badware: false }),
            Err(e) => eprintln!("[!] Warning: failed to fetch AdGuard Safari Base: {}", e),
        }
    }

    // 2. AdGuard Tracking Protection (Safari 3.txt)
    if !adguard_tracking_src.is_empty() {
        match fetch_or_read_cached(&adguard_tracking_src, "adguard_tracking", None) {
            Ok(c) => sources.push(FilterSource { name: "adguard_tracking".to_string(), content: c, is_badware: false }),
            Err(e) => eprintln!("[!] Warning: failed to fetch AdGuard Tracking: {}", e),
        }
    }

    // 3. AdGuard Annoyances/Popups (Safari 19.txt)
    if !adguard_annoyances_src.is_empty() {
        match fetch_or_read_cached(&adguard_annoyances_src, "adguard_annoyances", None) {
            Ok(c) => sources.push(FilterSource { name: "adguard_annoyances".to_string(), content: c, is_badware: false }),
            Err(e) => eprintln!("[!] Warning: failed to fetch AdGuard Annoyances: {}", e),
        }
    }

    if sources.is_empty() {
        eprintln!("[!] Error: No filter sources available for compilation.");
        std::process::exit(1);
    }

    println!("[*] Processing {} filter sources with adblock-rust...", sources.len());
    let (chunks, report) = match convert_multiple_filter_sources(&sources, chunk_size) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("[!] Conversion error: {}", e);
            std::process::exit(1);
        }
    };

    println!("\nConversion Statistics:");
    println!("------------------------------------------------------------");
    println!("Total input lines:          {:>8}", report.total_input_lines);
    println!("Network blocks converted:   {:>8}", report.network_blocks_converted);
    println!("Network exceptions converted:{:>7}", report.network_exceptions_converted);
    println!("Cosmetic rules converted:   {:>8}", report.cosmetic_rules_converted);
    println!("Total rules generated:      {:>8}", report.total_rules_generated);
    println!("Number of chunks:           {:>8}", report.chunk_count);
    println!("Badware domains indexed:    {:>8}", report.badware_domains.len());
    println!("Filter hash (SHA256):       {}", report.filter_hash);
    println!("\nSkipped rule categories:");
    let mut skipped: Vec<_> = report.skipped_rules_by_reason.iter().collect();
    skipped.sort_by(|a, b| b.1.cmp(a.1));
    for (reason, count) in skipped {
        println!("  - {:<45} : {:>6}", reason, count);
    }
    println!("------------------------------------------------------------");

    if let Err(e) = fs::create_dir_all(&output_dir) {
        eprintln!("[!] Failed to create output directory {:?}: {}", output_dir, e);
        std::process::exit(1);
    }

    // Clean old chunk files in output directory
    if let Ok(entries) = fs::read_dir(&output_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with("easylist_") && name.ends_with(".json") {
                    let _ = fs::remove_file(path);
                }
            }
        }
    }

    // Write chunk files
    for (idx, chunk) in chunks.iter().enumerate() {
        let filename = format!("easylist_part_{}.json", idx + 1);
        let chunk_path = output_dir.join(&filename);
        if let Err(e) = fs::write(&chunk_path, &chunk.json) {
            eprintln!("[!] Failed to write {:?}: {}", chunk_path, e);
            std::process::exit(1);
        }
        let size_kb = chunk.json.len() as f64 / 1024.0;
        println!("  -> Wrote {} ({} rules, {:.1} KB)", filename, chunk.rules.len(), size_kb);
    }

    // Write metadata manifest
    let manifest_path = output_dir.join("manifest.json");
    if let Ok(manifest_json) = serde_json::to_string_pretty(&report) {
        let _ = fs::write(manifest_path, manifest_json);
    }

    println!("\n[+] Filter compilation completed successfully!");
}
