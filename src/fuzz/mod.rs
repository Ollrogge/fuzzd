//! Fuzzing module facade: keeps campaign management and status rendering split behind `run`.

mod manage;
mod status;

pub use manage::run;
