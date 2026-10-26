//! A file-local semantic IR view for graph projection.
//!
//! The worker keeps the producer's typed facts and converts one record at a
//! time. Existing JSON callers use the same projection passes without another
//! interpretation of their facts. Clones share immutable backing storage; the
//! conversion context retains static field names, never converted records.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use serde::Serialize;

use super::direct_serializer::JsonConversion;
use super::json::{Json, Obj};
use super::leaves::ValueRef;
use crate::javascript::contracts::semantic_ir::{SemanticBinding, SemanticCallable, SemanticIr};
use crate::javascript::semantic::value_types::JsString;

#[derive(Clone, Copy)]
pub(crate) enum SemanticCollection {
    References,
    ModuleLinks,
    CallSites,
    ArgumentFlows,
    CallReturnFlows,
    CallResultFlows,
    ClosureCaptures,
    PromiseOperations,
    EventOperations,
    TimerOperations,
    ChildProcessSpawns,
    ChildProcessInteractions,
    ConfigurationOperations,
    RequestOperations,
    BoundaryOperations,
    ResourceOperations,
    ObjectOperations,
    FunctionFingerprints,
    Frontiers,
}

impl SemanticCollection {
    fn key(self) -> &'static str {
        match self {
            Self::References => "references",
            Self::ModuleLinks => "moduleLinks",
            Self::CallSites => "callSites",
            Self::ArgumentFlows => "argumentFlows",
            Self::CallReturnFlows => "callReturnFlows",
            Self::CallResultFlows => "callResultFlows",
            Self::ClosureCaptures => "closureCaptures",
            Self::PromiseOperations => "promiseOperations",
            Self::EventOperations => "eventOperations",
            Self::TimerOperations => "timerOperations",
            Self::ChildProcessSpawns => "childProcessSpawns",
            Self::ChildProcessInteractions => "childProcessInteractions",
            Self::ConfigurationOperations => "configurationOperations",
            Self::RequestOperations => "requestOperations",
            Self::BoundaryOperations => "boundaryOperations",
            Self::ResourceOperations => "resourceOperations",
            Self::ObjectOperations => "objectOperations",
            Self::FunctionFingerprints => "functionFingerprints",
            Self::Frontiers => "frontiers",
        }
    }
}

#[derive(Clone)]
enum SemanticBacking {
    Typed(Rc<SemanticIr>),
    Serialized(Json),
}

#[derive(Clone)]
pub(crate) struct SemanticIrView {
    backing: SemanticBacking,
    conversion: JsonConversion,
}

impl SemanticIrView {
    pub(crate) fn from_typed(ir: SemanticIr) -> Self {
        Self {
            backing: SemanticBacking::Typed(Rc::new(ir)),
            conversion: JsonConversion::default(),
        }
    }

    pub(crate) fn from_json(ir: &Json) -> Self {
        Self {
            backing: SemanticBacking::Serialized(ir.clone()),
            conversion: JsonConversion::default(),
        }
    }

    /// Iterate in producer order without retaining a collection's JSON records.
    pub(crate) fn records(
        &self,
        collection: SemanticCollection,
    ) -> Box<dyn ExactSizeIterator<Item = Json> + '_> {
        match &self.backing {
            SemanticBacking::Serialized(ir) => {
                Box::new(ir.at(collection.key()).arr().iter().cloned())
            }
            SemanticBacking::Typed(ir) => match collection {
                SemanticCollection::References => self.serialized_records(&ir.references),
                SemanticCollection::ModuleLinks => self.serialized_records(&ir.module_links),
                SemanticCollection::CallSites => self.serialized_records(&ir.call_sites),
                SemanticCollection::ArgumentFlows => self.serialized_records(&ir.argument_flows),
                SemanticCollection::CallReturnFlows => {
                    self.serialized_records(&ir.call_return_flows)
                }
                SemanticCollection::CallResultFlows => {
                    self.serialized_records(&ir.call_result_flows)
                }
                SemanticCollection::ClosureCaptures => {
                    self.serialized_records(&ir.closure_captures)
                }
                SemanticCollection::PromiseOperations => {
                    self.serialized_records(&ir.promise_operations)
                }
                SemanticCollection::EventOperations => {
                    self.serialized_records(&ir.event_operations)
                }
                SemanticCollection::TimerOperations => {
                    self.serialized_records(&ir.timer_operations)
                }
                SemanticCollection::ChildProcessSpawns => {
                    self.serialized_records(&ir.child_process_spawns)
                }
                SemanticCollection::ChildProcessInteractions => {
                    self.serialized_records(&ir.child_process_interactions)
                }
                SemanticCollection::ConfigurationOperations => {
                    self.serialized_records(&ir.configuration_operations)
                }
                SemanticCollection::RequestOperations => {
                    self.serialized_records(&ir.request_operations)
                }
                SemanticCollection::BoundaryOperations => {
                    self.serialized_records(&ir.boundary_operations)
                }
                SemanticCollection::ResourceOperations => {
                    self.serialized_records(&ir.resource_operations)
                }
                SemanticCollection::ObjectOperations => {
                    self.serialized_records(&ir.object_operations)
                }
                SemanticCollection::FunctionFingerprints => {
                    self.serialized_records(&ir.function_fingerprints)
                }
                SemanticCollection::Frontiers => self.serialized_records(&ir.frontiers),
            },
        }
    }

    /// Iterate over the binding fields needed before a value is selected.
    ///
    /// Typed IR leaves initializer values in the producer representation and
    /// handles provenance separately for module metadata. JSON callers retain
    /// their original record so permissive metadata remains available here.
    pub(crate) fn binding_headers(&self) -> Box<dyn ExactSizeIterator<Item = Json> + '_> {
        match &self.backing {
            SemanticBacking::Serialized(ir) => Box::new(ir.at("bindings").arr().iter().cloned()),
            SemanticBacking::Typed(ir) => Box::new(
                ir.bindings
                    .iter()
                    .map(|binding| self.binding_header(binding)),
            ),
        }
    }

    /// Iterate over callable identity, location, and return-site metadata.
    /// Return values remain in the typed producer; only linked callables need
    /// their complete return facts converted for module metadata.
    pub(crate) fn callable_headers(&self) -> Box<dyn ExactSizeIterator<Item = Json> + '_> {
        match &self.backing {
            SemanticBacking::Serialized(ir) => Box::new(ir.at("callables").arr().iter().cloned()),
            SemanticBacking::Typed(ir) => Box::new(
                ir.callables
                    .iter()
                    .map(|callable| self.callable_header(callable)),
            ),
        }
    }

    /// Read a value by producer position. This differs from identity lookup:
    /// repeated binding IDs still project each occurrence's original value.
    pub(crate) fn binding_value_at(&self, index: usize) -> Option<Json> {
        match &self.backing {
            SemanticBacking::Typed(ir) => ir
                .bindings
                .get(index)
                .map(|binding| self.convert(&binding.value)),
            SemanticBacking::Serialized(ir) => ir
                .at("bindings")
                .arr()
                .get(index)
                .map(|binding| binding.at("value").clone()),
        }
    }

    /// Project module metadata without expanding initializer values.
    pub(crate) fn module_bindings(&self) -> Box<dyn ExactSizeIterator<Item = Json> + '_> {
        match &self.backing {
            SemanticBacking::Serialized(ir) => Box::new(ir.at("bindings").arr().iter().cloned()),
            SemanticBacking::Typed(ir) => Box::new(ir.bindings.iter().map(|binding| {
                Obj::new()
                    .with_static("name", self.convert(&binding.name))
                    .with_static("scopeId", self.convert(&binding.scope_id))
                    .with_static("provenance", self.convert(&binding.provenance))
                    .into()
            })),
        }
    }

    /// Only linked callables need complete return facts in parent metadata.
    pub(crate) fn module_callables<'ir>(
        &'ir self,
        ids: &'ir HashSet<JsString>,
    ) -> Box<dyn Iterator<Item = Json> + 'ir> {
        match &self.backing {
            SemanticBacking::Serialized(ir) => Box::new(
                ir.at("callables")
                    .arr()
                    .iter()
                    .filter(|callable| {
                        callable
                            .at("callableId")
                            .as_js_string()
                            .is_some_and(|id| ids.contains(id))
                    })
                    .cloned(),
            ),
            SemanticBacking::Typed(ir) => Box::new(
                ir.callables
                    .iter()
                    .filter(|callable| ids.contains(&JsString::from(callable.callable_id.as_str())))
                    .map(|callable| self.convert(callable)),
            ),
        }
    }

    pub(crate) fn program_scopes(&self) -> Box<dyn Iterator<Item = Json> + '_> {
        match &self.backing {
            SemanticBacking::Serialized(ir) => Box::new(
                ir.at("scopes")
                    .arr()
                    .iter()
                    .filter(|scope| scope.at("kind").str() == "program")
                    .cloned(),
            ),
            SemanticBacking::Typed(ir) => Box::new(
                ir.scopes
                    .iter()
                    .filter(|scope| scope.kind == "program")
                    .map(|scope| {
                        Obj::new()
                            .with_static("kind", self.convert(&scope.kind))
                            .with_static("scopeId", self.convert(&scope.scope_id))
                            .with_static("location", self.convert(&scope.location))
                            .into()
                    }),
            ),
        }
    }

    pub(crate) fn collection_len(&self, collection: SemanticCollection) -> usize {
        self.records(collection).len()
    }

    pub(crate) fn coverage(&self) -> Json {
        match &self.backing {
            SemanticBacking::Typed(ir) => self.convert(&ir.coverage),
            SemanticBacking::Serialized(ir) => ir.at("coverage").clone(),
        }
    }

    pub(crate) fn limitations(&self) -> Json {
        match &self.backing {
            SemanticBacking::Typed(ir) => self.convert(&ir.limitations),
            SemanticBacking::Serialized(ir) => ir.at("limitations").clone(),
        }
    }

    /// Index binding identities while leaving their potentially large values
    /// in the producer-owned representation. Duplicate IDs retain the last
    /// value, matching the existing graph lookup's assignment semantics.
    pub(crate) fn binding_values(&self) -> BindingValueLookup<'_> {
        let indices = match &self.backing {
            SemanticBacking::Typed(ir) => ir
                .bindings
                .iter()
                .enumerate()
                .map(|(index, binding)| (binding.binding_id.as_str(), index))
                .collect(),
            SemanticBacking::Serialized(ir) => ir
                .at("bindings")
                .arr()
                .iter()
                .enumerate()
                .map(|(index, binding)| (binding.at("bindingId").str(), index))
                .collect(),
        };

        BindingValueLookup { ir: self, indices }
    }

    fn serialized_records<'ir, T: Serialize + 'ir>(
        &'ir self,
        records: &'ir [T],
    ) -> Box<dyn ExactSizeIterator<Item = Json> + 'ir> {
        Box::new(records.iter().map(|record| self.convert(record)))
    }

    fn convert<T: ?Sized + Serialize>(&self, value: &T) -> Json {
        self.conversion
            .serialize(value)
            .expect("semantic IR contract is serializable and valid JSON")
    }

    fn binding_header(&self, binding: &SemanticBinding) -> Json {
        Obj::new()
            .with_static("bindingId", self.convert(&binding.binding_id))
            .with_static("kind", self.convert(&binding.kind))
            .with_static("name", self.convert(&binding.name))
            .with_static("definitions", self.convert(&binding.definitions))
            .into()
    }

    fn callable_header(&self, callable: &SemanticCallable) -> Json {
        let return_sites = Json::array(
            callable
                .return_sites
                .iter()
                .map(|site| {
                    Obj::new()
                        .with_static("returnSiteId", self.convert(&site.return_site_id))
                        .with_static("location", self.convert(&site.location))
                        .with_static(
                            "identityReferenceLocation",
                            self.convert(&site.identity_reference_location),
                        )
                        .into()
                })
                .collect(),
        );
        Obj::new()
            .with_static("callableId", self.convert(&callable.callable_id))
            .with_static("kind", self.convert(&callable.kind))
            .with_static("name", self.convert(&callable.name))
            .with_static("location", self.convert(&callable.location))
            .with_static("returnSites", return_sites)
            .into()
    }
}

pub(crate) struct BindingValueLookup<'ir> {
    ir: &'ir SemanticIrView,
    indices: HashMap<&'ir str, usize>,
}

impl BindingValueLookup<'_> {
    pub(crate) fn value(&self, binding_id: &str) -> Option<ValueRef<'_>> {
        let index = *self.indices.get(binding_id)?;
        match &self.ir.backing {
            SemanticBacking::Typed(ir) => Some(ValueRef::Typed(&ir.bindings[index].value)),
            SemanticBacking::Serialized(ir) => {
                Some(ValueRef::Json(ir.at("bindings").arr()[index].at("value")))
            }
        }
    }
}
