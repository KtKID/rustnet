fn main() {
    #[cfg(target_os = "macos")]
    {
        cc::Build::new()
            .file("src/bpf_reader.c")
            .warnings(true)
            .compile("rustnet_bpf_reader");
        println!("cargo:rerun-if-changed=src/bpf_reader.c");
    }
}
