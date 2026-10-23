//! Bounded managed parse failures and issue bookkeeping.
//!
//! Port of `src/dotnet/ManagedReaderFailure.ts`. A [`ManagedReaderFailure`]
//! carries one [`ManagedParseIssue`] at an exact byte location. The reader
//! retains independent malformed items as issues while letting the caller
//! read the rest of a structure.

use std::collections::BTreeSet;

/// One bounded format failure retained as caller-visible managed coverage.
///
/// Fields mirror the `ManagedParseIssue` object literal exactly, in schema
/// order: `code`, `scope`, `offset`, `detail`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ManagedParseIssue {
    pub code: &'static str,
    pub scope: String,
    pub offset: Option<u64>,
    pub detail: String,
}

impl ManagedParseIssue {
    /// Build the issue's JSON object in its schema key order.
    pub fn to_value(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert("code".into(), serde_json::Value::from(self.code));
        map.insert("scope".into(), serde_json::Value::from(self.scope.clone()));
        map.insert(
            "offset".into(),
            match self.offset {
                Some(offset) => serde_json::Value::from(offset),
                None => serde_json::Value::Null,
            },
        );
        map.insert(
            "detail".into(),
            serde_json::Value::from(self.detail.clone()),
        );
        serde_json::Value::Object(map)
    }
}

/// A bounded managed parse failure that escaped a read operation.
#[derive(Debug, Clone)]
pub struct ManagedReaderFailure {
    pub issue: ManagedParseIssue,
}

impl ManagedReaderFailure {
    pub fn new(issue: ManagedParseIssue) -> Self {
        Self { issue }
    }
}

/// Construct a typed managed parse failure at an exact byte location.
pub fn managed_failure(
    code: &'static str,
    scope: impl Into<String>,
    detail: impl Into<String>,
    offset: Option<u64>,
) -> ManagedReaderFailure {
    ManagedReaderFailure::new(ManagedParseIssue {
        code,
        scope: scope.into(),
        offset,
        detail: detail.into(),
    })
}

/// A thrown failure that is not a [`ManagedReaderFailure`]: a `TypeError`,
/// `RangeError`, or other internal condition the TS code would rethrow.
#[derive(Debug, Clone)]
pub struct InternalFailure(pub String);

/// The reader's error algebra. `Reader` holds a bounded parse issue; `Internal`
/// holds any other thrown failure whose message is preserved verbatim.
#[derive(Debug, Clone)]
pub enum ReadError {
    Reader(ManagedReaderFailure),
    Internal(InternalFailure),
}

impl From<ManagedReaderFailure> for ReadError {
    fn from(value: ManagedReaderFailure) -> Self {
        ReadError::Reader(value)
    }
}

impl From<InternalFailure> for ReadError {
    fn from(value: InternalFailure) -> Self {
        ReadError::Internal(value)
    }
}

/// A read that either produces a value or a [`ReadError`].
pub type ReadResult<T> = Result<T, ReadError>;

/// `readManagedValue`: retain one malformed item's location while allowing
/// independent items to be read.
///
/// A [`ManagedReaderFailure`] that is **not** `resource-limit` is captured as
/// an issue and the call yields `None`. A `resource-limit` failure and every
/// non-reader failure propagate.
pub fn read_managed_value<T>(
    operation: impl FnOnce() -> ReadResult<T>,
    issues: &mut Vec<ManagedParseIssue>,
) -> ReadResult<Option<T>> {
    match operation() {
        Ok(value) => Ok(Some(value)),
        Err(ReadError::Reader(failure)) => {
            if failure.issue.code == "resource-limit" {
                Err(ReadError::Reader(failure))
            } else {
                issues.push(failure.issue);
                Ok(None)
            }
        }
        Err(other) => Err(other),
    }
}

/// `uniqueManagedParseIssues`: preserve issue order while collapsing the same
/// malformed producer fact across facets.
///
/// JS keys the `Map` by `JSON.stringify(issue)`; the equivalent key here is the
/// issue's own structural identity, which is one-to-one with its JSON form.
pub fn unique_managed_parse_issues(issues: &[ManagedParseIssue]) -> Vec<ManagedParseIssue> {
    let mut seen: BTreeSet<(&'static str, &str, Option<u64>, &str)> = BTreeSet::new();
    let mut out = Vec::new();
    for issue in issues {
        let key = (
            issue.code,
            issue.scope.as_str(),
            issue.offset,
            issue.detail.as_str(),
        );
        if seen.insert(key) {
            out.push(issue.clone());
        }
    }
    out
}

/// `appendManagedParseIssues`: append issue lists one issue at a time.
pub fn append_managed_parse_issues(
    target: &mut Vec<ManagedParseIssue>,
    found: &[&[ManagedParseIssue]],
) {
    for list in found {
        for issue in list.iter() {
            target.push(issue.clone());
        }
    }
}
