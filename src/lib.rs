#![doc = include_str!("../README.md")]

pub mod audit;
pub mod outdated;

use thiserror::Error;

/// Error type for npm_parser
#[derive(Debug, Error)]
pub enum Error {
    /// This means something went wrong when we were parsing the JSON output
    /// of the program
    #[error("Error parsing JSON: {0}")]
    SerdeJsonError(#[from] serde_json::Error),
    /// This is a wrapped serde_json error which provides a path to the location
    /// where the error occurred
    #[error("Error parsing JSON (with path): {0}")]
    SerdePathError(#[from] serde_path_to_error::Error<serde_json::Error>),
    /// This means the output of the program contained some string that was not
    /// valid UTF-8
    #[error("Error interpreting program output as UTF-8: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),
    /// This is likely to be an error when executing the program using std::process
    #[error("I/O Error: {0}")]
    StdIoError(#[from] std::io::Error),
}
