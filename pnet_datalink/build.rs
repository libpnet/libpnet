fn main() {
    let npcap_enabled = std::env::var("CARGO_FEATURE_WINPCAP").is_ok();
    let winpkfilter_enabled = std::env::var("CARGO_FEATURE_WINPKFILTER").is_ok();

    if npcap_enabled && winpkfilter_enabled {
        panic!(
            "Features `npcap` and `winpkfilter` are mutually exclusive. Please enable only one."
        );
    }
}
