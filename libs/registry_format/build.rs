fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    let mut config = prost_build::Config::new();
    config.btree_map(["."]);
    config.compile_protos(&["proto/registry.proto"], &["proto"])?;

    println!("cargo:rerun-if-changed=proto/registry.proto");
    Ok(())
}
