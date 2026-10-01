//! Persistent administrator weekly/monthly report snapshots and mail delivery.
pub mod period;
pub(crate) mod statistics;
pub(crate) mod storage;
mod worker;
pub use worker::run_worker;

#[cfg(test)]
mod tests;
