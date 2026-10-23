//! Link search path for the pinned frida-core devkit (feature `frida`).
//!
//! `frida-sys` emits `rustc-link-lib=frida-core` without a search path when
//! its `auto-download` feature is off. The devkit comes from
//! `scripts/fetch-frida-devkit.sh`, never from the network during the build.
fn main() {
    println!("cargo:rerun-if-env-changed=REA_FRIDA_DEVKIT_DIR");
    if std::env::var_os("CARGO_FEATURE_FRIDA").is_none() {
        return;
    }
    let Some(directory) = std::env::var_os("REA_FRIDA_DEVKIT_DIR") else {
        panic!(
            "feature `frida` needs the pinned frida-core devkit: run \
             `eval \"$(native/crates/tools/rea-tools-debug/scripts/fetch-frida-devkit.sh --env)\"` first"
        );
    };
    let directory = std::path::PathBuf::from(directory);
    if !directory.join("libfrida-core.a").is_file() || !directory.join("frida-core.h").is_file() {
        panic!(
            "REA_FRIDA_DEVKIT_DIR={} is not a verified frida-core devkit",
            directory.display()
        );
    }
    println!("cargo:rustc-link-search=native={}", directory.display());
}
