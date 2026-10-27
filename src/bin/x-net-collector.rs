fn main() -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        rustnet_monitor::collector::main()
    }
    #[cfg(not(target_os = "macos"))]
    {
        anyhow::bail!("x-net-collector currently supports macOS")
    }
}
