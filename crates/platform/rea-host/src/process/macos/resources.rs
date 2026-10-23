//! macOS owned-process resource boundary.
//!
//! REA's existing contract only enforces whole-process-tree memory limits
//! through the Windows Job Object launcher. macOS therefore reports an
//! explicit unsupported setup outcome rather than silently applying a
//! process-local limit.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacosResourceLimits {
    pub memory_limit_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MacosResourceSetup {
    Unsupported { reason: &'static str },
}

pub fn prepare_owned_resource_limits(_limits: MacosResourceLimits) -> MacosResourceSetup {
    MacosResourceSetup::Unsupported {
        reason: "owned process memory limits require the Windows Job Object launcher",
    }
}

#[cfg(target_os = "macos")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_process_local_limit_for_owned_family_request() {
        assert_eq!(
            prepare_owned_resource_limits(MacosResourceLimits {
                memory_limit_bytes: 1024,
            }),
            MacosResourceSetup::Unsupported {
                reason: "owned process memory limits require the Windows Job Object launcher",
            }
        );
    }
}
