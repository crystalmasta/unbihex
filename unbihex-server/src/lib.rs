//! The server's own parts: the Xray-compatible management API and the `api` command.

pub mod api;
pub mod cli_api;

/// Code generated from `proto/`: Xray's packages, nested the same way.
#[allow(missing_docs, clippy::all, clippy::pedantic, clippy::unwrap_used)]
pub mod proto {
    pub mod xray {
        pub mod common {
            pub mod serial {
                tonic::include_proto!("xray.common.serial");
            }
            pub mod protocol {
                tonic::include_proto!("xray.common.protocol");
            }
        }
        pub mod core {
            tonic::include_proto!("xray.core");
        }
        pub mod proxy {
            pub mod vless {
                tonic::include_proto!("xray.proxy.vless");
            }
        }
        pub mod app {
            pub mod stats {
                pub mod command {
                    tonic::include_proto!("xray.app.stats.command");
                }
            }
            pub mod proxyman {
                pub mod command {
                    tonic::include_proto!("xray.app.proxyman.command");
                }
            }
        }
    }
}
