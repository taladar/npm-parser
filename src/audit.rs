//! This parses the output of npm-audit
//!
//! [npm-audit](https://docs.npmjs.com/cli/v7/commands/npm-audit)

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::process::Command;
use std::str::from_utf8;
use tracing::{debug, warn};

/// This is used to return the data from audit()
/// but not used for parsing since we can not easily tell
/// serde how to decide which to use and the untagged union
/// error messages are not great
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", untagged)]
pub enum NpmAuditData {
    /// audit report version 1 (npm 6 or below)
    Version1(NpmAuditDataV1),
    /// audit report version 2 (npm 8)
    Version2(NpmAuditDataV2),
}

/// audit report version 1
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NpmAuditDataV1 {
    /// UUID identitying the run of npm-audit
    ///
    /// only included in some versions of npm
    pub run_id: Option<String>,
    /// actions to perform to fix vulnerabilities
    pub actions: Vec<Action>,
    /// advisories by id
    pub advisories: BTreeMap<String, Advisory>,
    /// list of muted packages
    ///
    /// only included in some versions of npm audit
    pub muted: Option<Vec<String>>,
}

/// helper to parse module paths
pub fn deserialize_module_path<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;

    Ok(s.split('>').map(|s| s.to_string()).collect())
}

/// helper to serialize module paths
pub fn serialize_module_path<S>(xs: &[String], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let s = xs.join(">");

    s.serialize(serializer)
}

/// helper to parse Vec of module paths
pub fn deserialize_module_path_vec<'de, D>(deserializer: D) -> Result<Vec<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let xs = <Vec<String>>::deserialize(deserializer)?;

    Ok(xs
        .into_iter()
        .map(|x| x.split('>').map(|s| s.to_string()).collect())
        .collect())
}

/// helper to serialize Vec of module paths
pub fn serialize_module_path_vec<S>(xxs: &[Vec<String>], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let v: Vec<String> = xxs.iter().map(|xs| xs.join(">")).collect();

    v.serialize(serializer)
}

/// helper to parse created in the correct format
/// (default time serde implementation seems to use a different format)
pub fn deserialize_rfc3339<'de, D>(deserializer: D) -> Result<time::OffsetDateTime, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;

    time::OffsetDateTime::parse(&s, &time::format_description::well_known::Rfc3339)
        .map_err(serde::de::Error::custom)
}

/// helper to serialize created in the correct format
/// (default time serde implementation seems to use a different format)
pub fn serialize_rfc3339<S>(t: &time::OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let s = t
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(serde::ser::Error::custom)?;

    s.serialize(serializer)
}

/// helper to parse updated and deleted in the correct format
/// (default time serde implementation seems to use a different format)
pub fn deserialize_optional_rfc3339<'de, D>(
    deserializer: D,
) -> Result<Option<time::OffsetDateTime>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = <Option<String> as Deserialize<'de>>::deserialize(deserializer)?;

    if let Some(s) = s {
        Ok(Some(
            time::OffsetDateTime::parse(&s, &time::format_description::well_known::Rfc3339)
                .map_err(serde::de::Error::custom)?,
        ))
    } else {
        Ok(None)
    }
}

/// helper to serialize updated and deleted in the correct format
/// (default time serde implementation seems to use a different format)
pub fn serialize_optional_rfc3339<S>(
    t: &Option<time::OffsetDateTime>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if let Some(t) = t {
        let s = t
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(serde::ser::Error::custom)?;

        s.serialize(serializer)
    } else {
        let n: Option<String> = None;
        n.serialize(serializer)
    }
}

/// advisory in report version 1
///
/// there is a field metadata in the output here but since I could not find
/// information on its structure it is not parsed (was always null for me)
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Advisory {
    /// numeric id
    pub id: u64,
    /// human readable title
    pub title: String,
    /// where was the module affected by this advisory found in the dependency
    /// tree
    pub findings: Vec<Finding>,
    /// which versions of the affected module are vulnerable
    pub vulnerable_versions: Option<String>,
    /// name of the affected node module
    pub module_name: Option<String>,
    /// how severe is the issue
    pub severity: Severity,
    /// GitHub advisory Id
    pub github_advisory_id: Option<String>,
    /// CVE numbers
    pub cves: Option<Vec<String>>,
    /// if this advisory is public
    pub access: String,
    /// which versions of the affected package are patched
    pub patched_versions: Option<String>,
    /// a human readable recommendation on how to fix this
    pub recommendation: String,
    /// a CWE (common weakness enumeration) identifier
    pub cwe: Option<String>,
    /// who found this security issue
    pub found_by: Option<String>,
    /// who reported this security issue
    pub reported_by: Option<String>,
    /// when was this advisory created
    #[serde(
        serialize_with = "serialize_rfc3339",
        deserialize_with = "deserialize_rfc3339"
    )]
    pub created: time::OffsetDateTime,
    /// when was this advisory last updated
    #[serde(
        serialize_with = "serialize_optional_rfc3339",
        deserialize_with = "deserialize_optional_rfc3339"
    )]
    pub updated: Option<time::OffsetDateTime>,
    /// when was this deleted
    #[serde(
        serialize_with = "serialize_optional_rfc3339",
        deserialize_with = "deserialize_optional_rfc3339"
    )]
    pub deleted: Option<time::OffsetDateTime>,
    /// external references, all in one String, with newlines
    pub references: Option<String>,
    /// npm advisory id
    pub npm_advisory_id: Option<String>,
    /// human-readable description
    pub overview: String,
    /// URL to learn more
    pub url: String,
}

/// findings in advisory in report version 1
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// dependency version found
    version: String,
    /// paths from current module to dependency
    #[serde(
        serialize_with = "serialize_module_path_vec",
        deserialize_with = "deserialize_module_path_vec"
    )]
    paths: Vec<Vec<String>>,
}

/// audit report version 2
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NpmAuditDataV2 {
    /// version of the audit report
    ///
    /// not all versions of npm produce this field
    pub audit_report_version: Option<u32>,
    /// Vulnerabilities found in dependencies
    pub vulnerabilities: BTreeMap<String, VulnerablePackage>,
    /// vulnerability and dependency counts
    pub metadata: MetadataV2,
}

/// Actions to perform to fix security issues
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", tag = "action")]
pub enum Action {
    /// install a new package
    #[serde(rename_all = "camelCase")]
    Install {
        /// which advisories will this action resolve
        resolves: Vec<Resolves>,
        /// which package do we need to install
        module: String,
        /// how deep in our dependency tree is this package
        depth: Option<u32>,
        /// which version of the package do we need to install
        target: String,
        /// is this a major version
        is_major: bool,
    },
    /// update a package
    #[serde(rename_all = "camelCase")]
    Update {
        /// which advisories will this action resolve
        resolves: Vec<Resolves>,
        /// which package do we need to update
        module: String,
        /// how deep in our dependency tree is this package
        depth: Option<u32>,
        /// which version of the package do we need to update to
        target: String,
    },
    /// review code using a package
    #[serde(rename_all = "camelCase")]
    Review {
        /// which advisories will this action resolve
        resolves: Vec<Resolves>,
        /// which package do we need to review
        module: String,
        /// how deep in our dependency tree is this package
        depth: Option<u32>,
    },
}

/// Which advisories are resolved by an action
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resolves {
    /// advisory id
    pub id: u64,
    /// path of depedencies from current module to affected module
    #[serde(
        serialize_with = "serialize_module_path",
        deserialize_with = "deserialize_module_path"
    )]
    pub path: Vec<String>,
    /// is this due to a dev dependency of the current package
    pub dev: bool,
    /// is this due to an optional dependency of the current package
    pub optional: bool,
    /// is this due to a bundled dependency of the current package
    pub bundled: bool,
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
    pub name: String,
    /// The severity of the vulnerabilities
    pub severity: Severity,
    /// is this a direct dependency
    pub is_direct: bool,
    /// the vulnerabilities that make this a vulnerable package
    pub via: Vec<Vulnerability>,
    /// not sure what htis means
    pub effects: Vec<String>,
    /// affected version range
    pub range: String,
    /// not sure what this means
    pub nodes: Vec<String>,
    /// is there a fix available
    pub fix_available: Fix,
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

/// The vulnerability and dependency counts returned by npm-audit in report
/// version 1
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataV1 {
    /// Vulnerability counts (without total)
    pub vulnerabilities: VulnerabilityCountsV1,
    /// Number of production dependencies
    pub dependencies: u32,
    /// Number of development dependencies
    pub dev_dependencies: u32,
    /// Number of optional dependencies
    pub optional_dependencies: u32,
    /// Total number of dependencies
    pub total_dependencies: u32,
}

/// The vulnerability and dependency counts returned by npm-audit in report
/// version 2
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataV2 {
    /// Vulnerability counts
    pub vulnerabilities: VulnerabilityCountsV2,
    /// Dependency counts
    pub dependencies: DependencyCounts,
}

/// The vulnerability and dependency counts returned by npm-audit in report
/// version 1
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct VulnerabilityCountsV1 {
    /// Number of info level vulnerabilities
    pub info: u32,
    /// Number of low level vulnerabilities
    pub low: u32,
    /// Number of moderate level vulnerabilities
    pub moderate: u32,
    /// Number of high level vulnerabilities
    pub high: u32,
    /// Number of critical level vulnerabilities
    pub critical: u32,
}

/// The vulnerability and dependency counts returned by npm-audit in report
/// version 2
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct VulnerabilityCountsV2 {
    /// Number of total vulnerabilities
    pub total: u32,
    /// Number of info level vulnerabilities
    pub info: u32,
    /// Number of low level vulnerabilities
    pub low: u32,
    /// Number of moderate level vulnerabilities
    pub moderate: u32,
    /// Number of high level vulnerabilities
    pub high: u32,
    /// Number of critical level vulnerabilities
    pub critical: u32,
}

/// The vulnerability and dependency counts returned by npm-audit
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyCounts {
    /// Total number of dependencies
    pub total: u32,
    /// Number of production dependencies
    pub prod: u32,
    /// Number of development dependencies
    pub dev: u32,
    /// Number of optional dependencies
    pub optional: u32,
    /// Number of peer dependencies
    ///
    /// see <https://nodejs.org/es/blog/npm/peer-dependencies/>
    pub peer: u32,
    /// Number of optional peer dependencies
    pub peer_optional: u32,
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
    let mut version_cmd = Command::new("npm");

    version_cmd.args(["--version"]);

    let version_output = version_cmd.output()?;

    let version = from_utf8(&version_output.stdout)?.trim();

    debug!("Got version string {} from npm --version", version);

    let report_format = match versions::Versioning::new(version) {
        Some(version) => {
            debug!("Got version {} from npm --version", version);
            let audit_report_change = versions::Versioning::new("7.0.0").unwrap();
            if version < audit_report_change {
                debug!(
                    "Dealing with npm before version {}, using report format 1",
                    audit_report_change
                );
                1
            } else {
                debug!(
                    "Dealing with npm version {} or above, using report format 2",
                    audit_report_change
                );
                2
            }
        }
        None => {
            // if --version already fails I do not have high hopes for
            // parsing anything but we might as well assume we are dealing with a
            // newer version since audit only appeared in npm version 6
            debug!("Could not parse npm version, defaulting to report format 2");
            2
        }
    };
    debug!("Using report format {}", report_format);

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
        IndicatedUpdateRequirement::UpToDate
    } else {
        IndicatedUpdateRequirement::UpdateRequired
    };

    let json_str = from_utf8(&output.stdout)?;
    let jd = &mut serde_json::Deserializer::from_str(json_str);
    let data: NpmAuditData = match report_format {
        1 => NpmAuditData::Version1(serde_path_to_error::deserialize::<_, NpmAuditDataV1>(jd)?),
        2 => NpmAuditData::Version2(serde_path_to_error::deserialize::<_, NpmAuditDataV2>(jd)?),
        _ => {
            panic!("Unknown report version")
        }
    };
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
