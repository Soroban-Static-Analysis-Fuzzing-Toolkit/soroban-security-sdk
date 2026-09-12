//! Error type for the SDK.

use std::path::PathBuf;

/// Errors produced while loading or analysing a Soroban project.
///
/// Parse failures for individual source files are *not* fatal: they are collected
/// into [`crate::AnalysisReport::diagnostics`] so that a single unparseable file
/// does not hide findings in the rest of the project. This type covers the
/// failures that make analysis impossible or that the caller asked to be fatal.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An I/O operation failed.
    #[error("i/o error at `{path}`: {source}")]
    Io {
        /// Path that was being accessed.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },

    /// A Cargo manifest could not be parsed.
    #[error("failed to parse Cargo manifest `{path}`: {message}")]
    Manifest {
        /// Manifest path.
        path: PathBuf,
        /// Parser message.
        message: String,
    },

    /// A `.soroban-sec.toml` configuration file could not be parsed.
    #[error("failed to parse config `{path}`: {message}")]
    Config {
        /// Config path.
        path: PathBuf,
        /// Parser message.
        message: String,
    },

    /// A WebAssembly module could not be parsed.
    #[error("failed to parse wasm module `{path}`: {message}")]
    Wasm {
        /// Wasm path.
        path: PathBuf,
        /// Parser message.
        message: String,
    },

    /// No Soroban contract code was found at the requested location.
    #[error("no Soroban contract sources found under `{path}`")]
    NoContracts {
        /// Root that was searched.
        path: PathBuf,
    },

    /// The requested path does not exist.
    #[error("path `{path}` does not exist")]
    NotFound {
        /// Missing path.
        path: PathBuf,
    },

    /// A string was not a valid rule id.
    #[error("`{0}` is not a valid rule id (expected e.g. `SSDK001`)")]
    InvalidRuleId(String),

    /// A rule id was configured or requested that no detector provides.
    #[error("unknown rule `{0}`")]
    UnknownRule(String),

    /// One or more source files failed to parse and strict mode was requested.
    #[error("{0} source file(s) failed to parse")]
    Parse(usize),
}

impl Error {
    pub(crate) fn io(path: impl Into<PathBuf>) -> impl FnOnce(std::io::Error) -> Self {
        let path = path.into();
        move |source| Error::Io { path, source }
    }
}

/// Convenience alias used throughout the SDK.
pub type Result<T> = std::result::Result<T, Error>;
