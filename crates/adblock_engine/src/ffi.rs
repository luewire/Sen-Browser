use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

#[repr(C)]
pub struct AdblockConversionResult {
    pub chunk_json_strings: *mut *mut c_char,
    pub chunk_count: u32,
    pub report_json: *mut c_char,
    pub error_message: *mut c_char,
}

impl Default for AdblockConversionResult {
    fn default() -> Self {
        Self {
            chunk_json_strings: ptr::null_mut(),
            chunk_count: 0,
            report_json: ptr::null_mut(),
            error_message: ptr::null_mut(),
        }
    }
}

/// Helper to allocate a CString on heap as *mut c_char.
fn string_to_c_char(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// C-compatible representation of a filter source.
#[repr(C)]
pub struct CFilterSource {
    pub name: *const c_char,
    pub content: *const c_char,
    pub is_badware: bool,
}

/// Convert multiple filter sources to WebKit content blocking JSON chunks.
///
/// SAFETY:
/// - `sources_ptr` must point to an array of `source_count` valid `CFilterSource` structs.
/// - The caller MUST free the returned struct with `adblock_free_conversion_result`.
#[no_mangle]
pub unsafe extern "C" fn adblock_convert_sources(
    sources_ptr: *const CFilterSource,
    source_count: u32,
    chunk_size: u32,
) -> AdblockConversionResult {
    let result = std::panic::catch_unwind(|| {
        if sources_ptr.is_null() || source_count == 0 {
            return AdblockConversionResult {
                error_message: string_to_c_char("No filter sources provided".to_string()),
                ..Default::default()
            };
        }

        let slice = std::slice::from_raw_parts(sources_ptr, source_count as usize);
        let mut rust_sources = Vec::with_capacity(slice.len());

        for (idx, src) in slice.iter().enumerate() {
            let name = if !src.name.is_null() {
                match CStr::from_ptr(src.name).to_str() {
                    Ok(s) => s.to_string(),
                    Err(e) => format!("source_{}: invalid name ({})", idx, e),
                }
            } else {
                format!("source_{}", idx)
            };

            let content = if !src.content.is_null() {
                match CStr::from_ptr(src.content).to_str() {
                    Ok(s) => s.to_string(),
                    Err(e) => {
                        return AdblockConversionResult {
                            error_message: string_to_c_char(format!("Invalid UTF-8 in source {}: {}", name, e)),
                            ..Default::default()
                        };
                    }
                }
            } else {
                String::new()
            };

            rust_sources.push(crate::FilterSource {
                name,
                content,
                is_badware: src.is_badware,
            });
        }

        match crate::convert_multiple_filter_sources(&rust_sources, chunk_size as usize) {
            Ok((chunks, report)) => {
                let report_json_str = serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string());
                let report_json = string_to_c_char(report_json_str);

                let mut chunk_ptrs: Vec<*mut c_char> = Vec::with_capacity(chunks.len());
                for chunk in chunks {
                    chunk_ptrs.push(string_to_c_char(chunk.json));
                }

                let chunk_count = chunk_ptrs.len() as u32;
                let chunk_json_strings = chunk_ptrs.as_mut_ptr();
                std::mem::forget(chunk_ptrs);

                AdblockConversionResult {
                    chunk_json_strings,
                    chunk_count,
                    report_json,
                    error_message: ptr::null_mut(),
                }
            }
            Err(e) => AdblockConversionResult {
                error_message: string_to_c_char(e),
                ..Default::default()
            },
        }
    });

    match result {
        Ok(res) => res,
        Err(_) => AdblockConversionResult {
            error_message: string_to_c_char("Panic occurred in adblock_convert_sources".to_string()),
            ..Default::default()
        },
    }
}

/// Convert EasyList and EasyPrivacy text to WebKit content blocking JSON chunks.
/// Preserved for backward compatibility.
///
/// SAFETY:
/// - Any non-null pointers must point to valid null-terminated UTF-8 strings.
/// - The caller MUST free the returned struct with `adblock_free_conversion_result`.
#[no_mangle]
pub unsafe extern "C" fn adblock_convert_filter_lists(
    easylist_ptr: *const c_char,
    easyprivacy_ptr: *const c_char,
    chunk_size: u32,
) -> AdblockConversionResult {
    let name_el = CString::new("easylist").unwrap();
    let name_ep = CString::new("easyprivacy").unwrap();
    let sources = [
        CFilterSource {
            name: name_el.as_ptr(),
            content: easylist_ptr,
            is_badware: false,
        },
        CFilterSource {
            name: name_ep.as_ptr(),
            content: easyprivacy_ptr,
            is_badware: false,
        },
    ];
    adblock_convert_sources(sources.as_ptr(), 2, chunk_size)
}

/// Free all heap memory associated with an `AdblockConversionResult`.
#[no_mangle]
pub unsafe extern "C" fn adblock_free_conversion_result(result: AdblockConversionResult) {
    if !result.error_message.is_null() {
        drop(CString::from_raw(result.error_message));
    }
    if !result.report_json.is_null() {
        drop(CString::from_raw(result.report_json));
    }
    if !result.chunk_json_strings.is_null() && result.chunk_count > 0 {
        let chunk_slice = std::slice::from_raw_parts(result.chunk_json_strings, result.chunk_count as usize);
        for &ptr in chunk_slice {
            if !ptr.is_null() {
                drop(CString::from_raw(ptr));
            }
        }
        drop(Vec::from_raw_parts(
            result.chunk_json_strings,
            result.chunk_count as usize,
            result.chunk_count as usize,
        ));
    }
}

#[repr(C)]
pub struct AdblockDiagnosticResult {
    pub is_blocked: bool,
    pub is_important: bool,
    pub matched_filter: *mut c_char,
    pub exception_rule: *mut c_char,
    pub error_message: *mut c_char,
}

impl Default for AdblockDiagnosticResult {
    fn default() -> Self {
        Self {
            is_blocked: false,
            is_important: false,
            matched_filter: ptr::null_mut(),
            exception_rule: ptr::null_mut(),
            error_message: ptr::null_mut(),
        }
    }
}

/// Perform an exact adblock-rust engine match diagnosis for a network request URL.
///
/// SAFETY:
/// - Any non-null pointers must point to valid null-terminated UTF-8 strings.
/// - The caller MUST free the returned struct with `adblock_free_diagnostic_result`.
#[no_mangle]
pub unsafe extern "C" fn adblock_diagnose_request(
    rules_ptr: *const c_char,
    url_ptr: *const c_char,
    source_url_ptr: *const c_char,
    request_type_ptr: *const c_char,
    method_ptr: *const c_char,
) -> AdblockDiagnosticResult {
    let result = std::panic::catch_unwind(|| {
        if rules_ptr.is_null() || url_ptr.is_null() {
            return AdblockDiagnosticResult {
                error_message: string_to_c_char("Null rules or URL pointer provided".to_string()),
                ..Default::default()
            };
        }

        let rules = match CStr::from_ptr(rules_ptr).to_str() {
            Ok(s) => s,
            Err(e) => {
                return AdblockDiagnosticResult {
                    error_message: string_to_c_char(format!("Invalid UTF-8 in rules: {}", e)),
                    ..Default::default()
                };
            }
        };

        let url = match CStr::from_ptr(url_ptr).to_str() {
            Ok(s) => s,
            Err(e) => {
                return AdblockDiagnosticResult {
                    error_message: string_to_c_char(format!("Invalid UTF-8 in URL: {}", e)),
                    ..Default::default()
                };
            }
        };

        let source_url = if !source_url_ptr.is_null() {
            CStr::from_ptr(source_url_ptr).to_str().unwrap_or("")
        } else {
            ""
        };

        let request_type = if !request_type_ptr.is_null() {
            CStr::from_ptr(request_type_ptr).to_str().unwrap_or("other")
        } else {
            "other"
        };

        let method = if !method_ptr.is_null() {
            CStr::from_ptr(method_ptr).to_str().unwrap_or("GET")
        } else {
            "GET"
        };

        match crate::diagnose_network_request(rules, url, source_url, request_type, method) {
            Ok(diag) => AdblockDiagnosticResult {
                is_blocked: diag.is_blocked,
                is_important: diag.is_important,
                matched_filter: diag.matched_filter.map(string_to_c_char).unwrap_or(ptr::null_mut()),
                exception_rule: diag.exception_rule.map(string_to_c_char).unwrap_or(ptr::null_mut()),
                error_message: ptr::null_mut(),
            },
            Err(e) => AdblockDiagnosticResult {
                error_message: string_to_c_char(e),
                ..Default::default()
            },
        }
    });

    match result {
        Ok(res) => res,
        Err(_) => AdblockDiagnosticResult {
            error_message: string_to_c_char("Panic in adblock_diagnose_request".to_string()),
            ..Default::default()
        },
    }
}

/// Free all heap memory associated with an `AdblockDiagnosticResult`.
#[no_mangle]
pub unsafe extern "C" fn adblock_free_diagnostic_result(result: AdblockDiagnosticResult) {
    if !result.matched_filter.is_null() {
        drop(CString::from_raw(result.matched_filter));
    }
    if !result.exception_rule.is_null() {
        drop(CString::from_raw(result.exception_rule));
    }
    if !result.error_message.is_null() {
        drop(CString::from_raw(result.error_message));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffi_roundtrip() {
        let easylist = CString::new("||doubleclick.net^$third-party\n##.advert").unwrap();
        let easyprivacy = CString::new("||analytics.google.com^\n").unwrap();

        unsafe {
            let res = adblock_convert_filter_lists(easylist.as_ptr(), easyprivacy.as_ptr(), 5000);
            assert!(res.error_message.is_null());
            assert!(!res.report_json.is_null());
            assert!(res.chunk_count > 0);
            assert!(!res.chunk_json_strings.is_null());

            let slice = std::slice::from_raw_parts(res.chunk_json_strings, res.chunk_count as usize);
            for &json_ptr in slice {
                assert!(!json_ptr.is_null());
                let json_str = CStr::from_ptr(json_ptr).to_str().unwrap();
                assert!(!json_str.is_empty());
            }

            adblock_free_conversion_result(res);
        }
    }

    #[test]
    fn test_ffi_diagnose_request() {
        let rules = CString::new("||ads-api.videy.co^\n@@||cdn.videy.co^\n").unwrap();
        let blocked_url = CString::new("https://ads-api.videy.co/load.js").unwrap();
        let allowed_url = CString::new("https://cdn.videy.co/video.mp4").unwrap();
        let source_url = CString::new("https://videy.co/v?id=123").unwrap();
        let req_type_script = CString::new("script").unwrap();
        let req_type_media = CString::new("media").unwrap();
        let method = CString::new("GET").unwrap();

        unsafe {
            let res_blocked = adblock_diagnose_request(
                rules.as_ptr(),
                blocked_url.as_ptr(),
                source_url.as_ptr(),
                req_type_script.as_ptr(),
                method.as_ptr(),
            );
            assert!(res_blocked.error_message.is_null());
            assert!(res_blocked.is_blocked);
            assert!(!res_blocked.matched_filter.is_null());
            adblock_free_diagnostic_result(res_blocked);

            let res_allowed = adblock_diagnose_request(
                rules.as_ptr(),
                allowed_url.as_ptr(),
                source_url.as_ptr(),
                req_type_media.as_ptr(),
                method.as_ptr(),
            );
            assert!(res_allowed.error_message.is_null());
            assert!(!res_allowed.is_blocked);
            adblock_free_diagnostic_result(res_allowed);

            // Test explicit exception overriding block rule
            let rules_override = CString::new("||videy.co^\n@@||cdn.videy.co^\n").unwrap();
            let res_override = adblock_diagnose_request(
                rules_override.as_ptr(),
                allowed_url.as_ptr(),
                source_url.as_ptr(),
                req_type_media.as_ptr(),
                method.as_ptr(),
            );
            assert!(res_override.error_message.is_null());
            assert!(!res_override.is_blocked);
            assert!(!res_override.exception_rule.is_null());
            adblock_free_diagnostic_result(res_override);
        }
    }
}
