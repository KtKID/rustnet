//! The single-process local collector: configuration, storage and lifecycle.

mod auxiliary;
mod codec;
pub mod config;
mod delegation;
mod lifecycle;
mod listeners;
mod session;

pub(crate) use auxiliary::Auxiliary;
pub(crate) use lifecycle::{Paths, initialize_logger};
pub(crate) use session::{Session, SessionWriter};

pub fn main() -> anyhow::Result<()> {
    lifecycle::main()
}
