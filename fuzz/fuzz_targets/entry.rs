#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| lonca_fuzz::entry::check(data));
