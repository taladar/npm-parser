//! This parses the output of npm-audit
//!
//! [npm-audit](https://docs.npmjs.com/cli/v7/commands/npm-audit)

use std::collections::BTreeMap;
use std::process::Command;
use std::str::from_utf8;
use tracing::{debug, warn};

/// Outer structure for parsing npm-audit output
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NpmAuditData {
    /// version of the audit report
    audit_report_version: u32,
    /// Vulnerabilities found in dependencies
    vulnerabilities: BTreeMap<String, VulnerablePackage>,
    /// vulnerability and dependency counts
    metadata: Metadata,
}

/// Severity of vulnerabilities
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Severity {
    /// no need to take action
    None,
    /// just informational
    Info,
    /// low severity
    Low,
    /// moderate severity
    Moderate,
    /// high severity
    High,
    /// critical severity
    Critical,
}

/// The details for a single vulnerable package
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VulnerablePackage {
    /// Package name
    name: String,
    /// The severity of the vulnerabilities
    severity: Severity,
    /// is this a direct dependency
    is_direct: bool,
    /// the vulnerabilities that make this a vulnerable package
    via: Vec<Vulnerability>,
    /// not sure what htis means
    effects: Vec<String>,
    /// affected version range
    range: String,
    /// not sure what this means
    nodes: Vec<String>,
    /// is there a fix available
    fix_available: Fix,
}

/// a single vulnerability
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", untagged)]
pub enum Vulnerability {
    /// some vulnerabilities in the via list are only a name
    NameOnly(String),
    /// and some contain full details
    Full {
        /// numeric id, not sure what it means
        source: u64,
        /// the name of the vulnerability, or if none exists the vulnerable package
        name: String,
        /// the name of the dependency which is vulnerable
        dependency: String,
        /// the human readable title of the vulnerability
        title: String,
        /// an URL explaining the vulnerability
        url: String,
        /// the severity of this vulnerability
        severity: Severity,
        /// the affected version range
        range: String,
    },
}

/// a single fix
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum Fix {
    /// some packages only indicate whether a fix is available or not
    BoolOnly(bool),
    /// others provide more details
    #[serde(rename_all = "camelCase")]
    Full {
        /// the fixed package name
        name: String,
        /// the fixed package version
        version: String,
        /// is this a semver major update
        is_sem_ver_major: bool,
    },
}

/// The vulnerability and dependency counts returned by npm-audit
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Metadata {
    /// Vulnerability counts
    vulnerabilities: VulnerabilityCounts,
    /// Dependency counts
    dependencies: DependencyCounts,
}

/// The vulnerability and dependency counts returned by npm-audit
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct VulnerabilityCounts {
    /// Number of total vulnerabilities
    total: u32,
    /// Number of info level vulnerabilities
    info: u32,
    /// Number of low level vulnerabilities
    low: u32,
    /// Number of moderate level vulnerabilities
    moderate: u32,
    /// Number of high level vulnerabilities
    high: u32,
    /// Number of critical level vulnerabilities
    critical: u32,
}

/// The vulnerability and dependency counts returned by npm-audit
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyCounts {
    /// Total number of dependencies
    total: u32,
    /// Number of production dependencies
    prod: u32,
    /// Number of development dependencies
    dev: u32,
    /// Number of optional dependencies
    optional: u32,
    /// Number of peer dependencies
    ///
    /// see <https://nodejs.org/es/blog/npm/peer-dependencies/>
    peer: u32,
    /// Number of optional peer dependencies
    peer_optional: u32,
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

/// main entry point for the npm-audit call
pub fn audit() -> Result<(IndicatedUpdateRequirement, NpmAuditData), crate::Error> {
    let mut cmd = Command::new("npm");

    cmd.args(["audit", "--json"]);

    let output = cmd.output()?;

    if !output.status.success() {
        warn!(
            "npm audit did not return with a successful exit code: {}",
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
    let jd = &mut serde_json::Deserializer::from_str(json_str);
    let data: NpmAuditData = serde_path_to_error::deserialize(jd)?;
    Ok((update_requirement, data))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Error;
    use tracing_test::traced_test;

    /// this test requires a package.json and package-lock.json in the main crate
    /// directory (working dir of the tests)
    #[traced_test]
    #[test]
    fn test_run_npm_audit() -> Result<(), Error> {
        audit()?;
        Ok(())
    }
}
