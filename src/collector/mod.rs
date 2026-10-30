//! The single-process local collector: configuration, storage and lifecycle.

mod auxiliary;
mod codec;
pub mod config;
mod delegation;
mod lifecycle;
mod listeners;
mod live;
mod session;

pub(crate) use auxiliary::Auxiliary;
pub(crate) use lifecycle::{Paths, initialize_logger};
pub(crate) use live::LiveServer;
pub(crate) use session::{Session, SessionWriter};

pub fn main() -> anyhow::Result<()> {
    lifecycle::main()
}

/// Diagnostic adapter injected into the independent security pipeline.
pub(crate) fn record_security_failure(directory: &std::path::Path, message: &str) {
    session::diagnostic(directory, "security", "pipeline_failed", message, "error");
}
