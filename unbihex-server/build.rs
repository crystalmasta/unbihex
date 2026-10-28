//! Generates the gRPC API code from proto/ (a subset of Xray's protos).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let files = [
        "typed_message.proto",
        "user.proto",
        "vless.proto",
        "core.proto",
        "stats.proto",
        "handler.proto",
    ];
    for f in files {
        println!("cargo:rerun-if-changed=proto/{f}");
    }
    let fds = protox::compile(files, ["proto"])?;
    tonic_prost_build::configure().compile_fds(fds)?;
    Ok(())
}
