//! The Veilway core: config version 1 and the engine that runs it.
pub mod config;
pub mod engine;

pub use engine::{start, DnsTotals, Engine, Options, Reason, Totals};
