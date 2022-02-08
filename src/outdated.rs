//! This parses the output of composer-outdated
use std::collections::BTreeMap;
use std::process::Command;
use std::str::from_utf8;
use tracing::{debug, warn};

/// Outer structure for parsing npm-outdated output
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct NpmOutdatedData(pub BTreeMap<String, PackageStatus>);

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
    ///
    /// optional since it is new between npm version 6 and 8
    pub dependent: Option<String>,
    /// tells you whether this package is a dependency or a dev/peer/optional
    /// dependency. Packages not included in package.json are always marked
    /// dependencies.
    #[serde(rename = "type")]
    pub package_type: String,
    /// the homepage value contained in the package's packument
    ///
    /// optional since it is not included in all npm versions
    pub homepage: Option<String>,
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
pub fn outdated() -> Result<(IndicatedUpdateRequirement, NpmOutdatedData), crate::Error> {
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
        IndicatedUpdateRequirement::UpToDate
    } else {
        IndicatedUpdateRequirement::UpdateRequired
    };

    let json_str = from_utf8(&output.stdout)?;
    let jd = &mut serde_json::Deserializer::from_str(json_str);
    let data: NpmOutdatedData = serde_path_to_error::deserialize(jd)?;
    Ok((update_requirement, data))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Error;

    /// this test requires a package.json and package-lock.json in the main crate
    /// directory (working dir of the tests)
    #[test]
    fn test_run_npm_outdated() -> Result<(), Error> {
        outdated()?;
        Ok(())
    }
}
