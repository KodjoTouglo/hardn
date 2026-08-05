//! Core trait and value types for the gli configuration engine.
//!
//! Owns the [`Module`] trait, the [`Context`] passed to every call, and the
//! [`Status`]/[`Change`]/[`Report`] vocabulary used to describe work.

#![forbid(unsafe_code)]

/// ASCII wordmark, shown in CLI help and the TUI header.
pub const BANNER: &str = r"       _ _
  __ _| (_)
 / _` | | |
| (_| | | |
 \__, |_|_|
 |___/     ";

mod catalog;
mod config;
mod context;
mod error;
mod fs;
mod inventory;
mod module;
mod platform;
pub mod recipes;
mod runner;
mod types;

pub use catalog::ModuleCatalog;
pub use config::{
    AppConfig, AppDatabase, AppRuntime, CaddyConfig, CaddySite, Config, DockerConfig,
    Fail2banConfig, FirewallBackend, FirewallConfig, Framework, MonitoringBackend,
    MonitoringConfig, Policy, PostgresConfig, Profile, RedisConfig, SshConfig, SystemConfig,
    TailscaleConfig, UpdatesConfig, UserConfig,
};
pub use context::Context;
pub use error::{Error, Result};
pub use fs::{FileSystem, LocalFs};
pub use inventory::{Inventory, Server};
pub use module::{Category, Module};
pub use platform::{DistroFamily, Platform};
pub use runner::{CommandRunner, Output, SystemRunner};
pub use types::{Change, ChangeKind, Report, State, Status};
