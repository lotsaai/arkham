#![forbid(unsafe_code)]
#![allow(deprecated)]
#![allow(macro_expanded_macro_exports_accessed_by_absolute_paths)]

include!(concat!(env!("OUT_DIR"), "/entry.rs"));
