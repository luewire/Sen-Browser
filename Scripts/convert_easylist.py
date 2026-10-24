#!/usr/bin/env python3
"""
EasyList to WebKit Content Blocker Converter.

Downloads EasyList, parses ABP (Adblock Plus) syntax rules, and converts
compatible network and cosmetic rules into partitioned, minified JSON chunks
for WebKit's WKContentRuleListStore.

Design Choices & Limitations:
1. WebKit Content Blocker Regex Engine Constraints:
   - WebKit's regex engine does NOT support disjunctions ('|' / '(?:a|b)').
     Any rule with alternation is rejected with 'Disjunctions are not supported yet'.
   - Backreferences (\\1) and lookarounds (?=, ?!) are unsupported.
   - ABP separator '^' is mapped to [^a-zA-Z0-9_.-] or anchored [:/] for domains.
2. Cosmetic Exceptions (#@#):
   - WebKit has no 'css-display-unhide' action. Emitting #@# cannot undo a
     declarative 'css-display-none' rule. These rules are safely skipped.
3. Procedural / Extended CSS:
   - Scriptlets (##+js(...)), HTML filters (##^), and procedural selectors
     (#?#, :-abp-has, :has-text) are unsupported by WebKit and safely skipped.
4. Exception Rules (ignore-previous-rules):
   - WebKit's 'ignore-previous-rules' action only applies to rules compiled
     within the SAME content rule list. It cannot undo rules across chunks.
   - Network exception rules (@@) are therefore only mapped when safe.
5. Chunk Sizing:
   - Rules are split into conservative chunks (default 25,000 rules) to ensure
     low peak memory during compilation and prevent hitting internal WebKit limits.
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

DEFAULT_URL = "https://easylist.to/easylist/easylist.txt"
FALLBACK_URL = "https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_block.txt"
DEFAULT_OUTPUT_DIR = "Sources/Search/Resources/Filters"
DEFAULT_CHUNK_SIZE = 25000

USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"

# WebKit resource types
WEBKIT_RESOURCE_TYPES = {
    "script": "script",
    "image": "image",
    "stylesheet": "style-sheet",
    "xmlhttprequest": "raw",
    "subdocument": "document",
    "font": "font",
    "media": "media",
    "websocket": "websocket",
    "popup": "popup",
    "other": "other",
}

# Modifiers not supported declaratively by WebKit Content Blockers
UNSUPPORTED_MODIFIERS = {
    "csp", "rewrite", "badfilter", "generichide", "genericblock",
    "replace", "redirect", "redirect-rule", "header", "empty", "mp4"
}

# Extended CSS pseudoclasses not supported by standard WebKit CSS engines
EXTENDED_CSS_PATTERNS = [
    ":-abp-", ":has-text(", ":matches-path(", ":xpath(",
    "[-ext-", ":upward(", ":remove(", ":watch-attr(",
    ":contains(", ":matches-css(", ":matches-attr("
]


def download_rules(source: str) -> str:
    """Download rules from URL or read from local file."""
    if os.path.isfile(source):
        print(f"[*] Reading rules from local file: {source}")
        with open(source, "r", encoding="utf-8", errors="replace") as f:
            return f.read()

    print(f"[*] Downloading EasyList from: {source}")
    urls_to_try = [source]
    if source == DEFAULT_URL and FALLBACK_URL != source:
        urls_to_try.append(FALLBACK_URL)

    last_error = None
    for url in urls_to_try:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = resp.read().decode("utf-8", errors="replace")
                print(f"[+] Download successful ({len(data):,} bytes)")
                return data
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
            last_error = e
            print(f"[!] Warning: Failed to download from {url}: {e}")

    raise RuntimeError(f"Could not download EasyList from any source. Error: {last_error}")


def abp_pattern_to_regex(pattern: str) -> str | None:
    """
    Translates an ABP pattern into a WebKit compatible regex.
    Returns None if pattern cannot be safely converted, is overly broad,
    or contains disjunctions (|) which WebKit explicitly rejects.
    """
    if not pattern:
        return None

    # Exact regex in ABP: /regex/
    if len(pattern) >= 2 and pattern.startswith("/") and pattern.endswith("/"):
        raw = pattern[1:-1]
        # WebKit content extensions only accept simple ASCII regexes with *, +, ?, ^, $, and character sets [...]
        # WebKit specifically rejects:
        # - Disjunctions (|)
        # - Shorthand character classes (\w, \d, \s, \b)
        # - Bounded / arbitrary repetitions ({n,m})
        # - Lookarounds (?=, ?!) and backreferences
        if (
            "|" in raw or "{" in raw or "}" in raw
            or "(?=" in raw or "(?!" in raw or "(?<" in raw
            or any(sh in raw for sh in [r"\w", r"\W", r"\d", r"\D", r"\s", r"\S", r"\b", r"\B"])
            or any(f"\\{d}" in raw for d in "123456789")
        ):
            return None
        try:
            re.compile(raw)
            return raw
        except re.error:
            return None

    # Overly broad checks
    if pattern in ("*", ".*", "^", "$", "http://*", "https://*", "||", "||*"):
        return None

    is_domain_anchored = False
    is_start_anchored = False
    is_end_anchored = False

    if pattern.startswith("||"):
        is_domain_anchored = True
        pattern = pattern[2:]
    elif pattern.startswith("|"):
        is_start_anchored = True
        pattern = pattern[1:]

    if pattern.endswith("|"):
        is_end_anchored = True
        pattern = pattern[:-1]

    ends_with_separator = False
    if pattern.endswith("^"):
        ends_with_separator = True
        pattern = pattern[:-1]

    # Convert pattern characters
    tokens = []
    for ch in pattern:
        if ch == "*":
            tokens.append(".*")
        elif ch == "^":
            # WebKit regex: separator character class without disjunction
            tokens.append(r"[^a-zA-Z0-9_.-]")
        else:
            tokens.append(re.escape(ch))

    regex = "".join(tokens)

    if is_domain_anchored:
        # Match beginning of domain (subdomains allowed)
        if ends_with_separator:
            # Matches domain followed by port or path separator
            regex = r"^https?://([^/]+\.)?" + regex + r"[:/]"
        else:
            regex = r"^https?://([^/]+\.)?" + regex
    elif is_start_anchored:
        regex = r"^" + regex
        if ends_with_separator:
            regex = regex + r"[^a-zA-Z0-9_.-]"
    else:
        if ends_with_separator:
            regex = regex + r"[^a-zA-Z0-9_.-]"

    if is_end_anchored:
        regex = regex + r"$"

    # Overly broad regex check
    if regex in (r".*", r"^.*", r"^https?://", r"^https?://([^/]+\.)?", r"^https?://([^/]+\.)?[:/]"):
        return None

    # Crucial: WebKit throws 'Disjunctions are not supported yet' if '|' exists
    if "|" in regex:
        return None

    try:
        re.compile(regex)
        return regex
    except re.error:
        return None


def parse_cosmetic_rule(line: str) -> dict | None:
    """Parses standard element hiding rules: [domains]##selector."""
    if "##+js(" in line or "##^" in line or "#?#" in line or "#$#" in line or "#@?#" in line or "#@$#" in line:
        return None  # Procedural scriptlets / HTML filtering not supported

    for ext in EXTENDED_CSS_PATTERNS:
        if ext in line:
            return None  # Non-standard extended CSS selector

    parts = line.split("##", 1)
    if len(parts) != 2:
        return None

    domain_part, selector = parts[0].strip(), parts[1].strip()
    if not selector:
        return None

    # Basic CSS selector sanity check (no unclosed braces or script injections)
    if "{" in selector or "}" in selector:
        return None

    trigger = {"url-filter": ".*"}

    if domain_part:
        if_domains = []
        unless_domains = []
        for d in domain_part.split(","):
            d = d.strip()
            if not d:
                continue
            if d.startswith("~"):
                clean = d[1:].strip()
                if clean:
                    unless_domains.append("*" + clean if not clean.startswith("*") else clean)
            else:
                if_domains.append("*" + d if not d.startswith("*") else d)

        if if_domains:
            trigger["if-domain"] = if_domains
        if unless_domains:
            trigger["unless-domain"] = unless_domains

    return {
        "trigger": trigger,
        "action": {
            "type": "css-display-none",
            "selector": selector
        }
    }


def parse_network_rule(line: str) -> dict | None:
    """Parses network blocking and exception rules."""
    is_exception = False
    if line.startswith("@@"):
        is_exception = True
        line = line[2:]

    pattern = line
    options_str = None
    if "$" in line:
        parts = line.split("$", 1)
        pattern = parts[0]
        options_str = parts[1]

    regex = abp_pattern_to_regex(pattern)
    if not regex:
        return None

    trigger = {"url-filter": regex}
    if is_exception:
        action = {"type": "ignore-previous-rules"}
    else:
        action = {"type": "block"}

    if options_str:
        options = [opt.strip() for opt in options_str.split(",") if opt.strip()]
        res_types = set()
        load_types = set()
        if_domains = []
        unless_domains = []

        for opt in options:
            opt_lower = opt.lower()

            # Check for unsupported modifiers
            prefix = opt_lower.split("=")[0]
            if prefix in UNSUPPORTED_MODIFIERS:
                return None

            if opt_lower == "third-party":
                load_types.add("third-party")
            elif opt_lower == "~third-party":
                load_types.add("first-party")
            elif opt_lower in WEBKIT_RESOURCE_TYPES:
                res_types.add(WEBKIT_RESOURCE_TYPES[opt_lower])
            elif opt_lower.startswith("domain="):
                domains_str = opt[len("domain="):]
                for d in domains_str.split("|"):
                    d = d.strip()
                    if not d:
                        continue
                    if d.startswith("~"):
                        clean = d[1:].strip()
                        if clean:
                            unless_domains.append("*" + clean if not clean.startswith("*") else clean)
                    else:
                        if_domains.append("*" + d if not d.startswith("*") else d)
            elif opt_lower.startswith("~"):
                # Inverted resource types (~script, ~image) cannot be mapped directly to WebKit's positive resource-type list
                continue

        if res_types:
            trigger["resource-type"] = sorted(list(res_types))
        if load_types:
            trigger["load-type"] = sorted(list(load_types))
        if if_domains:
            trigger["if-domain"] = if_domains
        if unless_domains:
            trigger["unless-domain"] = unless_domains

    return {"trigger": trigger, "action": action}


def main():
    parser = argparse.ArgumentParser(description="Convert EasyList to WebKit Content Blocker JSON chunks")
    parser.add_argument("source", nargs="?", default=DEFAULT_URL, help="URL or path to EasyList file")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Output directory for JSON chunks")
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE, help="Maximum rules per JSON chunk")
    args = parser.parse_args()

    content = download_rules(args.source)
    lines = content.splitlines()

    stats = {
        "total_lines": len(lines),
        "comments": 0,
        "empty": 0,
        "cosmetic_rules": 0,
        "cosmetic_exceptions_skipped": 0,
        "extended_css_skipped": 0,
        "network_block_rules": 0,
        "network_exceptions": 0,
        "unsupported_modifier_skipped": 0,
        "invalid_regex_skipped": 0,
        "total_converted": 0
    }

    converted_rules = []

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            stats["empty"] += 1
            continue
        if line.startswith("!") or line.startswith("["):
            stats["comments"] += 1
            continue

        # Handle cosmetic exceptions: #@#, #@?#, #@$#
        if "#@#" in line or "#@?#" in line or "#@$#" in line:
            stats["cosmetic_exceptions_skipped"] += 1
            continue

        # Skip procedural element hiding rules: #?#, #$#
        if "#?#" in line or "#$#" in line:
            stats["extended_css_skipped"] += 1
            continue

        # Handle standard cosmetic rules: ##
        if "##" in line:
            rule = parse_cosmetic_rule(line)
            if rule:
                stats["cosmetic_rules"] += 1
                converted_rules.append(rule)
            else:
                stats["extended_css_skipped"] += 1
            continue

        # If line contains any '#' (not in a regex /.../), skip as non-standard cosmetic rule
        if "#" in line and not (line.startswith("/") and line.endswith("/")):
            stats["extended_css_skipped"] += 1
            continue

        # Network rule (blocking or exception @@)
        rule = parse_network_rule(line)
        if rule:
            if rule["action"]["type"] == "ignore-previous-rules":
                stats["network_exceptions"] += 1
            else:
                stats["network_block_rules"] += 1
            converted_rules.append(rule)
        else:
            stats["invalid_regex_skipped"] += 1

    stats["total_converted"] = len(converted_rules)

    print("\n" + "=" * 50)
    print("EasyList Conversion Summary")
    print("=" * 50)
    print(f"Total lines parsed:              {stats['total_lines']:,}")
    print(f"Empty lines skipped:             {stats['empty']:,}")
    print(f"Comments skipped:                {stats['comments']:,}")
    print(f"Cosmetic exceptions skipped:     {stats['cosmetic_exceptions_skipped']:,}")
    print(f"Extended/Procedural CSS skipped: {stats['extended_css_skipped']:,}")
    print(f"Unsupported regex/mods skipped:  {stats['invalid_regex_skipped']:,}")
    print(f"Cosmetic rules converted:        {stats['cosmetic_rules']:,}")
    print(f"Network block rules converted:   {stats['network_block_rules']:,}")
    print(f"Network exceptions converted:    {stats['network_exceptions']:,}")
    print(f"Total rules converted:           {stats['total_converted']:,}")
    print("=" * 50)

    # Output chunks
    os.makedirs(args.output_dir, exist_ok=True)

    # Clean old chunk files in output directory
    for fname in os.listdir(args.output_dir):
        if fname.startswith("easylist_part_") and fname.endswith(".json"):
            os.remove(os.path.join(args.output_dir, fname))

    # Separate normal rules (block & css-display-none) from exception rules (ignore-previous-rules)
    normal_rules = []
    exception_rules = []

    for rule in converted_rules:
        if rule.get("action", {}).get("type") == "ignore-previous-rules":
            exception_rules.append(rule)
        else:
            normal_rules.append(rule)

    # Top-level document exception so first-party pages always load
    fp_doc_rule = {
        "trigger": {
            "url-filter": ".*",
            "resource-type": ["document"],
            "load-type": ["first-party"]
        },
        "action": {
            "type": "ignore-previous-rules"
        }
    }
    if fp_doc_rule not in exception_rules:
        exception_rules.append(fp_doc_rule)

    # First-party whitelists for protected platforms (Google, YouTube, X, GitHub, etc.)
    for platform in ["google.com", "youtube.com", "x.com", "twitter.com", "github.com", "apple.com"]:
        escaped = platform.replace(".", "\\.")
        p_rule = {
            "trigger": {
                "url-filter": f"^https?://([^/]+\\.)?{escaped}[:/]",
                "load-type": ["first-party"]
            },
            "action": {
                "type": "ignore-previous-rules"
            }
        }
        if p_rule not in exception_rules:
            exception_rules.append(p_rule)

    chunk_size = max(1000, args.chunk_size)
    chunks = []
    for i in range(0, len(normal_rules), chunk_size):
        chunk = list(normal_rules[i:i + chunk_size])
        has_block = any(r.get("action", {}).get("type") == "block" for r in chunk)
        if has_block:
            chunk.extend(exception_rules)
        chunks.append(chunk)

    print(f"\nWriting {len(chunks)} JSON chunk files (max {chunk_size:,} normal rules + {len(exception_rules):,} exceptions each) to {args.output_dir}:")
    for idx, chunk in enumerate(chunks, 1):
        filename = f"easylist_part_{idx}.json"
        filepath = os.path.join(args.output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(chunk, f, separators=(",", ":"))
        filesize_mb = os.path.getsize(filepath) / (1024 * 1024)
        print(f"  -> {filename}: {len(chunk):,} rules ({filesize_mb:.2f} MB)")

    print("\n[+] Conversion completed successfully!")


if __name__ == "__main__":
    main()
