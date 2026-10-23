//! Relocatable platform identity for the shared C ABI library.
fn main() {
    // Consumers locate the installed library through their own rpath. A build
    // directory is not an install identity (and may have come from a cache).
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo::rustc-cdylib-link-arg=-Wl,-install_name,@rpath/librea_ffi.dylib");
    }
}
