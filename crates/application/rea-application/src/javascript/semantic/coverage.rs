//! Coverage contracts and resource-limit projection for JavaScript semantics.

use serde::{Deserialize, Serialize};

use super::value_types::ResourceLimit;
use crate::javascript::contracts::static_analysis::SourceRange;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SemanticCoverageStatus {
    Complete,
    Partial,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticCoverage {
    pub status: SemanticCoverageStatus,
    pub omitted_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_limits: Vec<ResourceLimit>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub widened_returned_references: Vec<SourceRange>,
}

impl SemanticCoverage {
    pub fn complete() -> Self {
        Self {
            status: SemanticCoverageStatus::Complete,
            omitted_count: Some(0),
            resource_limits: Vec::new(),
            widened_returned_references: Vec::new(),
        }
    }

    pub fn from_observations(
        parser_partial: bool,
        resource_limits: Vec<ResourceLimit>,
        widened_returned_references: Vec<SourceRange>,
    ) -> Self {
        let partial = parser_partial
            || !resource_limits.is_empty()
            || !widened_returned_references.is_empty();
        Self {
            status: if partial {
                SemanticCoverageStatus::Partial
            } else {
                SemanticCoverageStatus::Complete
            },
            omitted_count: if resource_limits.is_empty() {
                Some(0)
            } else {
                None
            },
            resource_limits,
            widened_returned_references,
        }
    }

    pub fn failed() -> Self {
        Self {
            status: SemanticCoverageStatus::Failed,
            omitted_count: None,
            resource_limits: Vec::new(),
            widened_returned_references: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        match self.status {
            SemanticCoverageStatus::Failed if self.omitted_count.is_some() => {
                Err("failed semantic coverage must omit omittedCount")
            }
            SemanticCoverageStatus::Complete if self.omitted_count != Some(0) => {
                Err("complete semantic coverage must use omittedCount=0")
            }
            SemanticCoverageStatus::Partial
                if self.omitted_count != Some(0) && self.omitted_count != None =>
            {
                Err("partial semantic coverage must use omittedCount=0 or null")
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SemanticReturnCoverageStatus {
    Complete,
    Partial,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticReturnCoverage {
    pub status: SemanticReturnCoverageStatus,
    pub retained_count: usize,
    pub omitted_count: Option<usize>,
}

impl SemanticReturnCoverage {
    pub fn new(retained_count: usize, parser_partial: bool) -> Self {
        Self {
            status: if parser_partial {
                SemanticReturnCoverageStatus::Partial
            } else {
                SemanticReturnCoverageStatus::Complete
            },
            retained_count,
            omitted_count: Some(0),
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if matches!(self.status, SemanticReturnCoverageStatus::Complete)
            && self.omitted_count != Some(0)
        {
            return Err("complete return coverage must use omittedCount=0");
        }
        if matches!(self.status, SemanticReturnCoverageStatus::Partial)
            && self.omitted_count != Some(0)
            && self.omitted_count != None
        {
            return Err("partial return coverage must use omittedCount=0 or null");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_constructors_preserve_typescript_omission_states() {
        assert_eq!(SemanticCoverage::complete().omitted_count, Some(0));
        assert_eq!(SemanticCoverage::failed().omitted_count, None);
        let partial = SemanticCoverage::from_observations(true, Vec::new(), Vec::new());
        assert_eq!(partial.status, SemanticCoverageStatus::Partial);
        assert!(partial.validate().is_ok());
    }

    #[test]
    fn invalid_failed_coverage_is_rejected_by_validation() {
        let invalid = SemanticCoverage {
            status: SemanticCoverageStatus::Failed,
            omitted_count: Some(0),
            resource_limits: Vec::new(),
            widened_returned_references: Vec::new(),
        };
        assert_eq!(
            invalid.validate(),
            Err("failed semantic coverage must omit omittedCount")
        );
    }

    #[test]
    fn resource_limited_partial_coverage_omits_count() {
        let coverage = SemanticCoverage::from_observations(
            false,
            vec![ResourceLimit::PrimitiveBytes],
            Vec::new(),
        );
        assert_eq!(coverage.status, SemanticCoverageStatus::Partial);
        assert_eq!(coverage.omitted_count, None);
    }
}
