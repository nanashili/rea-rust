//! Frozen public contracts: the single source of truth for the native runtime.
//!
//! `contracts/catalog/*.json` is generated from the original runtime's live
//! `tools/list`, prompt and initialize responses plus its contract metadata.
//! Handlers bind by exact tool name; catalog order only drives listing order.
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::OnceLock;

const TOOLS: &str = include_str!("../contracts/catalog/mcp-tools.json");
const PROMPTS: &str = include_str!("../contracts/catalog/mcp-prompts.json");
const SERVER: &str = include_str!("../contracts/catalog/mcp-server.json");
const CLI: &str = include_str!("../contracts/catalog/cli-commands.json");

/// One advertised MCP tool and its runtime metadata.
#[derive(Debug)]
pub struct ToolContract {
    pub name: String,
    /// Exact advertised definition, including `outputSchema`.
    pub advertised: Value,
    /// Adapter family (`session`, `official-proxy`, ...).
    pub kind: String,
    /// Results can carry analysis-target text and are marked untrusted.
    pub returns_target_content: bool,
    pub effects: Value,
    pub examples: Value,
}

impl ToolContract {
    pub fn input_schema(&self) -> &Value {
        &self.advertised["inputSchema"]
    }

    pub fn output_schema(&self) -> Option<&Value> {
        self.advertised.get("outputSchema")
    }

    /// Session tools wrap successful plain values as `{ result }`.
    pub fn is_session(&self) -> bool {
        self.kind == "session"
    }

    /// Advertisement for tools/list with optional output schemas.
    pub fn listing(&self, include_output_schema: bool) -> Value {
        let mut tool = self.advertised.clone();
        if !include_output_schema && let Some(object) = tool.as_object_mut() {
            object.remove("outputSchema");
        }
        tool
    }
}

/// One guided prompt contract.
#[derive(Debug)]
pub struct PromptContract {
    pub name: String,
    pub title: String,
    pub description: String,
    pub objective: String,
    /// Ordered argument name, description, required, completion kind.
    pub arguments: Vec<PromptArgument>,
    pub steps: Vec<PromptStep>,
    pub advertised: Value,
}

#[derive(Debug)]
pub struct PromptArgument {
    pub name: String,
    pub description: String,
    pub required: bool,
    pub completion: Option<String>,
}

#[derive(Debug)]
pub struct PromptStep {
    pub tools: Vec<String>,
    pub instruction: String,
}

/// Complete frozen catalog.
#[derive(Debug)]
pub struct Catalog {
    pub tools: Vec<ToolContract>,
    by_name: HashMap<String, usize>,
    pub prompts: Vec<PromptContract>,
    pub protocol_version: String,
    pub server_name: String,
    pub server_version: String,
    pub capabilities: Value,
    pub instructions: Option<String>,
    pub cli: Value,
}

impl Catalog {
    pub fn tool(&self, name: &str) -> Option<&ToolContract> {
        self.by_name.get(name).map(|index| &self.tools[*index])
    }

    pub fn prompt(&self, name: &str) -> Option<&PromptContract> {
        self.prompts.iter().find(|prompt| prompt.name == name)
    }

    /// Whether a tool's results carry analysis-target content.
    pub fn returns_target_content(&self, name: &str) -> bool {
        self.tool(name)
            .is_some_and(|tool| tool.returns_target_content)
    }
}

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// The process-wide catalog, parsed once on first use.
pub fn catalog() -> &'static Catalog {
    static CATALOG: OnceLock<Catalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        let tools_document: Value =
            serde_json::from_str(TOOLS).expect("frozen tool catalog is valid JSON");
        let mut tools = Vec::new();
        for entry in tools_document["tools"].as_array().into_iter().flatten() {
            let advertised = entry["advertised"].clone();
            tools.push(ToolContract {
                name: text(&advertised, "name"),
                kind: text(entry, "kind"),
                returns_target_content: entry["returns_target_content"].as_bool().unwrap_or(true),
                effects: entry["effects"].clone(),
                examples: entry["examples"].clone(),
                advertised,
            });
        }
        let by_name = tools
            .iter()
            .enumerate()
            .map(|(index, tool)| (tool.name.clone(), index))
            .collect();

        let prompts_document: Value =
            serde_json::from_str(PROMPTS).expect("frozen prompt catalog is valid JSON");
        let advertised_prompts = prompts_document["prompts"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let mut prompts = Vec::new();
        for contract in prompts_document["contracts"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let name = text(contract, "name");
            let advertised = advertised_prompts
                .iter()
                .find(|prompt| prompt["name"] == Value::String(name.clone()))
                .cloned()
                .unwrap_or(Value::Null);
            let arguments = contract["arguments"]
                .as_object()
                .map(|arguments| {
                    arguments
                        .iter()
                        .map(|(name, argument)| PromptArgument {
                            name: name.clone(),
                            description: text(argument, "description"),
                            required: argument["required"].as_bool().unwrap_or(false),
                            completion: argument
                                .get("completion")
                                .and_then(Value::as_str)
                                .map(str::to_owned),
                        })
                        .collect()
                })
                .unwrap_or_default();
            let steps = contract["steps"]
                .as_array()
                .map(|steps| {
                    steps
                        .iter()
                        .map(|step| PromptStep {
                            tools: step["tools"]
                                .as_array()
                                .map(|tools| {
                                    tools
                                        .iter()
                                        .filter_map(Value::as_str)
                                        .map(str::to_owned)
                                        .collect()
                                })
                                .unwrap_or_default(),
                            instruction: text(step, "instruction"),
                        })
                        .collect()
                })
                .unwrap_or_default();
            prompts.push(PromptContract {
                title: text(contract, "title"),
                description: text(contract, "description"),
                objective: text(contract, "objective"),
                name,
                arguments,
                steps,
                advertised,
            });
        }

        let server: Value = serde_json::from_str(SERVER).expect("frozen server info is valid JSON");
        let cli: Value = serde_json::from_str(CLI).expect("frozen CLI catalog is valid JSON");
        Catalog {
            tools,
            by_name,
            prompts,
            protocol_version: text(&server, "protocol_version"),
            server_name: text(&server["server_info"], "name"),
            server_version: text(&server["server_info"], "version"),
            capabilities: server["capabilities"].clone(),
            instructions: server
                .get("instructions")
                .and_then(Value::as_str)
                .map(str::to_owned),
            cli,
        }
    })
}

/// Frozen compact-profile input schema advertisement for one tool.
pub fn compact_input_schema(name: &str) -> Option<&'static Value> {
    static COMPACT: OnceLock<Value> = OnceLock::new();
    COMPACT
        .get_or_init(|| {
            serde_json::from_str(include_str!("../contracts/catalog/mcp-input-compact.json"))
                .expect("frozen compact schemas are valid JSON")
        })
        .get(name)
}

/// CLI command contract by exact primary name.
pub fn cli_command(name: &str) -> Option<&'static Value> {
    catalog()
        .cli
        .get("commands")
        .and_then(Value::as_array)
        .and_then(|commands| commands.iter().find(|command| command["name"] == name))
}

/// Ordered CLI command names.
pub fn cli_command_names() -> Vec<&'static str> {
    catalog()
        .cli
        .get("commands")
        .and_then(Value::as_array)
        .map(|commands| {
            commands
                .iter()
                .filter_map(|command| command["name"].as_str())
                .collect()
        })
        .unwrap_or_default()
}

/// Helper used by handlers to build parameter maps.
pub fn object(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    let mut map = Map::new();
    for (key, value) in entries {
        map.insert(key.to_owned(), value);
    }
    Value::Object(map)
}
