//! Shared owners for views that read retained web-network request lines.
//!
//! Compatibility owners: `src/domain/recordedTransportUrl.ts`,
//! `src/domain/analysisView/webNetworkRouteTemplates.ts`,
//! `src/domain/analysisView/WebNetworkProjectionAccumulator.ts`,
//! `src/domain/analysisView/analysisViewDataAdmission.ts` and
//! `src/domain/unicodeCodePointOrder.ts`.
pub mod budget;
pub mod capture;
pub mod ordering;
pub mod routes;
pub mod url;
