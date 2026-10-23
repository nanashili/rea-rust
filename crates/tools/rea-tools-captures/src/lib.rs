//! External-tool captures: TShark, sigrok, pcap, binwalk/unblob, objdump, rizin, pwntools and Flutter.
use rea_mcp::Registry;

mod artifact;
mod errors;
mod limits;
mod node;
mod process;
mod producer;
mod resources;
mod runtime;
mod validation;

#[cfg(feature = "firmware")]
mod firmware;
#[cfg(feature = "flutter")]
mod flutter;
#[cfg(feature = "pcap")]
mod pcap;
#[cfg(feature = "pwntools")]
mod pwntools;
#[cfg(feature = "reverse")]
mod reverse;
#[cfg(feature = "sigrok")]
mod sigrok;
#[cfg(feature = "tshark")]
mod tshark;

/// Bind every tool owned by this family to its exact catalog contract.
pub fn register(registry: &mut Registry) {
    #[cfg(feature = "tshark")]
    tshark::register(registry);
    #[cfg(feature = "sigrok")]
    sigrok::register(registry);
    #[cfg(feature = "pcap")]
    pcap::register(registry);
    #[cfg(feature = "firmware")]
    firmware::register(registry);
    #[cfg(feature = "reverse")]
    reverse::register(registry);
    #[cfg(feature = "pwntools")]
    pwntools::register(registry);
    #[cfg(feature = "flutter")]
    flutter::register(registry);
    let _ = registry;
}
