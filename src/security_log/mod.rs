// src/security_log/mod.rs

mod api;
mod model;
mod store;

pub use api::{
    record_best_effort_platform_failure, record_best_effort_platform_failures,
    record_intentional_security_event, take_best_effort_warn_pending,
};

pub use model::{SecurityEvent, SecurityEventClass};

pub use store::SecurityLog;
