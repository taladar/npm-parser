//! This parses the outdated of composer-outdated
use thiserror::Error;

use std::collections::BTreeMap;
use std::process::Command;
use std::str::from_utf8;
use tracing::{debug, warn};

/// Error type for npm_parser
#[derive(Debug, Error)]
pub enum Error {
    /// This means something went wrong when we were parsing the JSON output
    /// of the program
    #[error("Error parsing JSON: {0}")]
    SerdeJsonError(#[from] serde_json::Error),
    /// This means the output of the program contained some string that was not
    /// valid UTF-8
    #[error("Error interpreting program output as UTF-8: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),
    /// This is likely to be an error when executing the program using std::process
    #[error("I/O Error: {0}")]
    StdIoError(#[from] std::io::Error),
}

/// Outer structure for parsing npm-outdated output
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct NpmOutdatedData(BTreeMap<String, PackageStatus>);

/// Inner, per-package structure when parsing npm-outdated output
///
/// Meaning of the fields is from [npm-outdated](https://docs.npmjs.com/cli/v7/commands/npm-outdated)
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PackageStatus {
    /// wanted is the maximum version of the package that satisfies the
    /// semver range specified in package.json. If there's no available
    /// semver range (i.e. you're running npm outdated --global, or
    /// the package isn't included in package.json), then wanted shows
    /// the currently-installed version.
    pub wanted: String,
    /// latest is the version of the package tagged as latest in the registry.
    /// Running npm publish with no special configuration will publish the
    /// package with a dist-tag of latest. This may or may not be the maximum
    /// version of the package, or the most-recently published version of the
    /// package, depending on how the package's developer manages the latest
    /// dist-tag.
    pub latest: String,
    /// where in the physical tree the package is located.
    pub location: Option<String>,
    /// shows which package depends on the displayed dependency
    pub dependent: String,
    /// tells you whether this package is a dependency or a dev/peer/optional
    /// dependency. Packages not included in package.json are always marked
    /// dependencies.
    #[serde(rename = "type")]
    pub package_type: String,
    /// the homepage value contained in the package's packument
    pub homepage: String,
}

/// What the exit code indicated about required updates
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum IndicatedUpdateRequirement {
    /// No update is required
    UpToDate,
    /// An update is required
    UpdateRequired,
}

impl std::fmt::Display for IndicatedUpdateRequirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IndicatedUpdateRequirement::UpToDate => {
                write!(f, "up-to-date")
            }
            IndicatedUpdateRequirement::UpdateRequired => {
                write!(f, "update-required")
            }
        }
    }
}

/// main entry point for the npm-oudated call
pub fn outdated() -> Result<(IndicatedUpdateRequirement, NpmOutdatedData), Error> {
    let mut cmd = Command::new("npm");

    cmd.args(["outdated", "--json", "--long"]);

    let output = cmd.output()?;

    if !output.status.success() {
        warn!(
            "npm outdated did not return with a successful exit code: {}",
            output.status
        );
        debug!("stdout:\n{}", from_utf8(&output.stdout)?);
        if !output.stderr.is_empty() {
            warn!("stderr:\n{}", from_utf8(&output.stderr)?);
        }
    }

    let update_requirement = if output.status.success() {
        IndicatedUpdateRequirement::UpdateRequired
    } else {
        IndicatedUpdateRequirement::UpToDate
    };

    let json_str = from_utf8(&output.stdout)?;
    let data: NpmOutdatedData = serde_json::from_str(json_str)?;
    Ok((update_requirement, data))
}

#[cfg(test)]
mod test {
    use super::*;

    /// this test requires a composer.json and composer.lock in the main crate
    /// directory (working dir of the tests)
    #[test]
    fn test_run_composer_outdated() -> Result<(), Error> {
        outdated()?;
        Ok(())
    }
}
