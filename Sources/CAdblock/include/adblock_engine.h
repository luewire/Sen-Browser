#ifndef ADBLOCK_ENGINE_H
#define ADBLOCK_ENGINE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Result of converting Adblock Plus filters to WebKit Content Blocker chunks.
typedef struct {
    /// Array of null-terminated UTF-8 JSON strings, each representing a WKContentRuleList chunk.
    char** chunk_json_strings;
    /// Number of chunk JSON strings in the array.
    uint32_t chunk_count;
    /// Null-terminated UTF-8 JSON string detailing conversion statistics and skipped rules.
    char* report_json;
    /// Null-terminated UTF-8 error string if conversion failed; NULL on success.
    char* error_message;
} AdblockConversionResult;

/// Representation of a named filter source.
typedef struct {
    const char* name;
    const char* content;
    bool is_badware;
} CFilterSource;

/// Convert multiple filter sources (EasyList, EasyPrivacy, AdGuard, Badware) into WebKit Content Blocker chunks.
AdblockConversionResult adblock_convert_sources(
    const CFilterSource* sources,
    uint32_t source_count,
    uint32_t chunk_size
);

/// Parse EasyList and EasyPrivacy text rules, convert them to WebKit content blocking rules,
/// and partition them into ordered chunks where exceptions are properly handled.
AdblockConversionResult adblock_convert_filter_lists(
    const char* easylist_content,
    const char* easyprivacy_content,
    uint32_t chunk_size
);

/// Free memory allocated for an AdblockConversionResult.
void adblock_free_conversion_result(AdblockConversionResult result);

/// Diagnostic match result from adblock-rust Engine.
typedef struct {
    bool is_blocked;
    bool is_important;
    char* matched_filter;
    char* exception_rule;
    char* error_message;
} AdblockDiagnosticResult;

/// Perform an exact adblock-rust engine match diagnosis for a network request URL.
AdblockDiagnosticResult adblock_diagnose_request(
    const char* rules,
    const char* url,
    const char* source_url,
    const char* request_type,
    const char* method
);

/// Free memory allocated for an AdblockDiagnosticResult.
void adblock_free_diagnostic_result(AdblockDiagnosticResult result);

#ifdef __cplusplus
}
#endif

#endif /* ADBLOCK_ENGINE_H */
