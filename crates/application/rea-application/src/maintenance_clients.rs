//! Canonical client locations shared by maintenance and diagnostics.
//!
//! This module resolves where a client may read configuration. It does not
//! inspect or mutate those files; parsing and transactions have their own
//! owner.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientPlatform {
    Macos,
    Linux,
    Windows,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientConfigurationFormat {
    Json,
    Jsonc,
    Toml,
    Yaml,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientResolutionContext {
    pub home: PathBuf,
    pub cwd: PathBuf,
    pub platform: ClientPlatform,
    pub environment: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientSkillDirectoryError {
    UnknownClient { client: String },
}

impl std::fmt::Display for ClientSkillDirectoryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownClient { client } => write!(formatter, "unknown skill client: {client}"),
        }
    }
}

impl std::error::Error for ClientSkillDirectoryError {}

impl ClientResolutionContext {
    pub fn new(
        home: impl Into<PathBuf>,
        cwd: impl Into<PathBuf>,
        platform: ClientPlatform,
        environment: BTreeMap<String, String>,
    ) -> Self {
        Self {
            home: home.into(),
            cwd: cwd.into(),
            platform,
            environment,
        }
    }
}

/// A possible configuration location. Presence is only evidence, never an
/// assertion that the client is installed or that REA is configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRegistrationTarget {
    pub id: String,
    pub display_name: String,
    pub path: PathBuf,
    pub evidence_paths: Vec<PathBuf>,
    pub marker_path: PathBuf,
    pub format: ClientConfigurationFormat,
    pub server_key: &'static str,
    pub config_path_error: Option<String>,
    pub quit_before_setup: bool,
    pub manual_registration: bool,
}

impl ClientRegistrationTarget {
    fn new(
        id: &str,
        display_name: &str,
        path: PathBuf,
        marker_path: PathBuf,
        format: ClientConfigurationFormat,
        server_key: &'static str,
    ) -> Self {
        let evidence_paths = unique_paths([path.clone(), marker_path.clone()]);
        Self {
            id: id.to_owned(),
            display_name: display_name.to_owned(),
            path,
            evidence_paths,
            marker_path,
            format,
            server_key,
            config_path_error: None,
            quit_before_setup: false,
            manual_registration: false,
        }
    }
}

pub fn supported_client_targets(
    context: &ClientResolutionContext,
) -> Vec<ClientRegistrationTarget> {
    let home = &context.home;
    let config = env_path(context, "XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config"));
    let mut targets = Vec::with_capacity(25);

    add(
        &mut targets,
        "claude_code",
        "Claude Code",
        claude_code_path(context),
        env_path(context, "CLAUDE_CONFIG_DIR").unwrap_or_else(|| home.join(".claude")),
        ClientConfigurationFormat::Json,
        "mcpServers",
    );
    add_special(
        &mut targets,
        "claude_desktop",
        "Claude Desktop",
        claude_desktop_path(context, &config),
        claude_desktop_marker(context, &config),
        ClientConfigurationFormat::Json,
        "mcpServers",
        true,
        false,
    );
    add(
        &mut targets,
        "codex",
        "Codex",
        env_path(context, "CODEX_HOME")
            .unwrap_or_else(|| home.join(".codex"))
            .join("config.toml"),
        env_path(context, "CODEX_HOME").unwrap_or_else(|| home.join(".codex")),
        ClientConfigurationFormat::Toml,
        "mcp_servers",
    );
    add(
        &mut targets,
        "cursor",
        "Cursor",
        home.join(".cursor/mcp.json"),
        home.join(".cursor"),
        ClientConfigurationFormat::Json,
        "mcpServers",
    );
    add(
        &mut targets,
        "gemini_cli",
        "Gemini CLI",
        env_path(context, "GEMINI_CLI_HOME")
            .unwrap_or_else(|| home.clone())
            .join(".gemini/settings.json"),
        env_path(context, "GEMINI_CLI_HOME")
            .unwrap_or_else(|| home.clone())
            .join(".gemini"),
        ClientConfigurationFormat::Json,
        "mcpServers",
    );
    add(
        &mut targets,
        "windsurf",
        "Windsurf",
        home.join(".codeium/windsurf/mcp_config.json"),
        home.join(".codeium/windsurf"),
        ClientConfigurationFormat::Json,
        "mcpServers",
    );
    let devin = if context.platform == ClientPlatform::Windows {
        app_data(context).join("devin")
    } else {
        config.join("devin")
    };
    add(
        &mut targets,
        "devin",
        "Devin",
        devin.join("mcp_config.json"),
        devin,
        ClientConfigurationFormat::Json,
        "mcpServers",
    );
    let (opencode, opencode_marker, evidence) = opencode_paths(context, &config);
    let mut target = ClientRegistrationTarget::new(
        "opencode",
        "OpenCode",
        opencode,
        opencode_marker,
        ClientConfigurationFormat::Json,
        "mcp",
    );
    target.evidence_paths = unique_paths(evidence);
    targets.push(target);
    add(
        &mut targets,
        "antigravity",
        "Antigravity",
        home.join(".gemini/config/mcp_config.json"),
        home.join(".gemini/config"),
        ClientConfigurationFormat::Json,
        "mcpServers",
    );
    let copilot = env_path(context, "COPILOT_HOME").unwrap_or_else(|| home.join(".copilot"));
    add(
        &mut targets,
        "copilot_cli",
        "GitHub Copilot CLI",
        copilot.join("mcp-config.json"),
        copilot,
        ClientConfigurationFormat::Json,
        "mcpServers",
    );
    let commandcode = home.join(".commandcode");
    add(
        &mut targets,
        "commandcode",
        "Command Code",
        commandcode.join("mcp.json"),
        commandcode,
        ClientConfigurationFormat::Json,
        "mcpServers",
    );
    let qwen = override_path(context, "QWEN_HOME").unwrap_or_else(|| home.join(".qwen"));
    add(
        &mut targets,
        "qwen_code",
        "Qwen Code",
        qwen.join("settings.json"),
        qwen,
        ClientConfigurationFormat::Json,
        "mcpServers",
    );
    let kimi = env_path(context, "KIMI_CODE_HOME").unwrap_or_else(|| home.join(".kimi-code"));
    add(
        &mut targets,
        "kimi",
        "Kimi Code",
        kimi.join("mcp.json"),
        kimi,
        ClientConfigurationFormat::Json,
        "mcpServers",
    );
    let vscode = editor_root(context, &config, "Code");
    add(
        &mut targets,
        "vscode",
        "VS Code",
        vscode.join("mcp.json"),
        vscode,
        ClientConfigurationFormat::Json,
        "servers",
    );
    let trae = editor_root(context, &config, "Trae");
    add(
        &mut targets,
        "trae",
        "Trae",
        trae.join("mcp.json"),
        trae,
        ClientConfigurationFormat::Json,
        "mcpServers",
    );
    let workbuddy = home.join(".workbuddy");
    add(
        &mut targets,
        "workbuddy",
        "WorkBuddy",
        workbuddy.join("mcp.json"),
        workbuddy,
        ClientConfigurationFormat::Json,
        "mcpServers",
    );
    let grok = env_path(context, "GROK_HOME").unwrap_or_else(|| home.join(".grok"));
    add(
        &mut targets,
        "grok_build",
        "Grok Build",
        grok.join("config.toml"),
        grok,
        ClientConfigurationFormat::Toml,
        "mcp_servers",
    );
    add(
        &mut targets,
        "omp",
        "OMP",
        omp_path(context),
        omp_marker(context),
        ClientConfigurationFormat::Json,
        "mcpServers",
    );
    let pi =
        override_path(context, "PI_CODING_AGENT_DIR").unwrap_or_else(|| home.join(".pi/agent"));
    add(
        &mut targets,
        "pi",
        "Pi",
        pi.join("mcp.json"),
        pi,
        ClientConfigurationFormat::Json,
        "mcpServers",
    );
    let hermes = env_path(context, "HERMES_HOME").unwrap_or_else(|| home.join(".hermes"));
    add(
        &mut targets,
        "hermes",
        "Hermes",
        hermes.join("config.yaml"),
        hermes,
        ClientConfigurationFormat::Yaml,
        "mcp_servers",
    );
    let qoder = env_path(context, "QODER_CONFIG_DIR").unwrap_or_else(|| home.join(".qoder"));
    add(
        &mut targets,
        "qoder",
        "Qoder",
        qoder.join("settings.json"),
        qoder,
        ClientConfigurationFormat::Json,
        "mcpServers",
    );
    let droid = home.join(".factory");
    add(
        &mut targets,
        "droid",
        "Factory Droid",
        droid.join("mcp.json"),
        droid,
        ClientConfigurationFormat::Json,
        "mcpServers",
    );
    let zcode = home.join(".zcode/cli");
    add(
        &mut targets,
        "zcode",
        "ZCode",
        zcode.join("config.json"),
        zcode,
        ClientConfigurationFormat::Json,
        "mcp",
    );
    let dsh = env_path(context, "DSH_HOME").unwrap_or_else(|| home.join(".dsh"));
    add(
        &mut targets,
        "dsh",
        "DeepSeek Harness",
        dsh.join("cordis.patch.yml"),
        dsh,
        ClientConfigurationFormat::Yaml,
        "servers",
    );
    let grokbot = env_path(context, "SAND_DATA_ROOT")
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| home.join(".grokbot"));
    add_special(
        &mut targets,
        "grok_bot",
        "Grok Bot",
        grokbot.join("mcp.json"),
        grokbot,
        ClientConfigurationFormat::Unsupported,
        "mcpServers",
        false,
        true,
    );
    targets
}

/// Resolve the project-scoped configuration location for a client.
///
/// Scope-specific paths belong to the client registry so adapters do not
/// reconstruct the formats and ownership rules independently.
pub fn project_registration_target(
    mut target: ClientRegistrationTarget,
    context: &ClientResolutionContext,
) -> Option<ClientRegistrationTarget> {
    let relative = project_config_path(&target.id)?;
    target.path = context.cwd.join(relative);
    target.marker_path = target.path.parent()?.to_path_buf();
    // The project directory is always present for a command running in that
    // project.  Treating it as client evidence would therefore select every
    // project-capable client during automatic discovery.  A project-scoped
    // registration is detected only by its client-specific configuration.
    target.evidence_paths = vec![target.path.clone()];
    Some(target)
}

pub fn supports_project_registration(client_id: &str) -> bool {
    project_config_path(client_id).is_some()
}

fn project_config_path(client_id: &str) -> Option<&'static str> {
    match client_id {
        "claude_code" | "copilot_cli" => Some(".mcp.json"),
        "codex" => Some(".codex/config.toml"),
        "cursor" => Some(".cursor/mcp.json"),
        "gemini_cli" => Some(".gemini/settings.json"),
        "windsurf" => Some(".windsurf/mcp_config.json"),
        "opencode" => Some("opencode.jsonc"),
        "kimi" => Some(".kimi-code/mcp.json"),
        "pi" => Some(".pi/mcp.json"),
        "vscode" => Some(".vscode/mcp.json"),
        "qwen_code" => Some(".qwen/settings.json"),
        "droid" => Some(".factory/mcp.json"),
        _ => None,
    }
}

pub fn canonical_client_skill_directories(
    context: &ClientResolutionContext,
    selected: Option<&[String]>,
) -> Result<Vec<(String, PathBuf)>, ClientSkillDirectoryError> {
    let names: Vec<String> = match selected {
        Some(items) if items.is_empty() => vec!["shared".to_owned()],
        Some(items) => items.to_owned(),
        None => [
            "shared",
            "claude_code",
            "gemini_cli",
            "antigravity",
            "trae",
            "workbuddy",
            "qoder",
            "droid",
            "zcode",
            "dsh",
            "hermes",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
    };
    let mut roots = names
        .into_iter()
        .map(|name| {
            let path = match name.as_str() {
                "shared" => context.home.join(".agents/skills"),
                "claude_code" => env_path(context, "CLAUDE_CONFIG_DIR")
                    .unwrap_or_else(|| context.home.join(".claude"))
                    .join("skills"),
                "gemini_cli" => env_path(context, "GEMINI_CLI_HOME")
                    .unwrap_or_else(|| context.home.clone())
                    .join(".agents/skills"),
                "antigravity" => context.home.join(".gemini/config/skills"),
                "trae" => {
                    editor_root(context, &context.home.join(".config"), "Trae").join("skills")
                }
                "workbuddy" => context.home.join(".workbuddy/skills"),
                "qoder" => env_path(context, "QODER_CONFIG_DIR")
                    .unwrap_or_else(|| context.home.join(".qoder"))
                    .join("skills"),
                "droid" => context.home.join(".factory/skills"),
                "zcode" => context.home.join(".zcode/skills"),
                "dsh" => env_path(context, "DSH_AGENTS_HOME")
                    .unwrap_or_else(|| context.home.join(".agents"))
                    .join("skills"),
                "hermes" => env_path(context, "HERMES_HOME")
                    .unwrap_or_else(|| context.home.join(".hermes"))
                    .join("skills"),
                _ => return Err(ClientSkillDirectoryError::UnknownClient { client: name }),
            };
            Ok((name, path))
        })
        .collect::<Result<Vec<_>, _>>()?;
    roots.sort_by(|left, right| left.1.cmp(&right.1));
    roots.dedup_by(|left, right| left.1 == right.1);
    let shared = context.home.join(".agents/skills");
    for (name, path) in &mut roots {
        if *path == shared {
            *name = "shared".to_owned();
        }
    }
    Ok(roots)
}

fn add(
    targets: &mut Vec<ClientRegistrationTarget>,
    id: &str,
    name: &str,
    path: PathBuf,
    marker: PathBuf,
    format: ClientConfigurationFormat,
    key: &'static str,
) {
    targets.push(ClientRegistrationTarget::new(
        id, name, path, marker, format, key,
    ));
}
fn add_special(
    targets: &mut Vec<ClientRegistrationTarget>,
    id: &str,
    name: &str,
    path: PathBuf,
    marker: PathBuf,
    format: ClientConfigurationFormat,
    key: &'static str,
    quit: bool,
    manual: bool,
) {
    let mut target = ClientRegistrationTarget::new(id, name, path, marker, format, key);
    target.quit_before_setup = quit;
    target.manual_registration = manual;
    targets.push(target);
}
fn env_path(context: &ClientResolutionContext, name: &str) -> Option<PathBuf> {
    context
        .environment
        .get(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}
fn override_path(context: &ClientResolutionContext, name: &str) -> Option<PathBuf> {
    let value = context.environment.get(name)?;
    let path = if value == "~" {
        context.home.clone()
    } else if let Some(rest) = value
        .strip_prefix("~/")
        .or_else(|| value.strip_prefix("~\\"))
    {
        context.home.join(rest)
    } else {
        PathBuf::from(value)
    };
    Some(if path.is_absolute() {
        path
    } else {
        context.cwd.join(path)
    })
}
fn app_data(context: &ClientResolutionContext) -> PathBuf {
    env_path(context, "APPDATA").unwrap_or_else(|| context.home.join("AppData/Roaming"))
}
fn editor_root(context: &ClientResolutionContext, config: &Path, name: &str) -> PathBuf {
    match context.platform {
        ClientPlatform::Windows => app_data(context).join(name).join("User"),
        ClientPlatform::Macos => context
            .home
            .join("Library/Application Support")
            .join(name)
            .join("User"),
        ClientPlatform::Linux => config.join(name).join("User"),
    }
}
fn claude_code_path(context: &ClientResolutionContext) -> PathBuf {
    env_path(context, "CLAUDE_CONFIG_DIR")
        .unwrap_or_else(|| context.home.clone())
        .join(".claude.json")
}
fn claude_desktop_marker(context: &ClientResolutionContext, config: &Path) -> PathBuf {
    match context.platform {
        ClientPlatform::Linux => config.join("Claude"),
        ClientPlatform::Macos => context.home.join("Library/Application Support/Claude"),
        ClientPlatform::Windows => app_data(context).join("Claude"),
    }
}
fn claude_desktop_path(context: &ClientResolutionContext, config: &Path) -> PathBuf {
    claude_desktop_marker(context, config).join("claude_desktop_config.json")
}
fn opencode_paths(
    context: &ClientResolutionContext,
    config: &Path,
) -> (PathBuf, PathBuf, Vec<PathBuf>) {
    let base = config.join("opencode");
    let selected = override_path(context, "OPENCODE_CONFIG_DIR")
        .map(|path| path.join("opencode.json"))
        .or_else(|| override_path(context, "OPENCODE_CONFIG"))
        .unwrap_or_else(|| base.join("opencode.json"));
    let mut evidence = vec![
        base.join("config.json"),
        base.join("opencode.json"),
        base.join("opencode.jsonc"),
    ];
    if let Some(path) = override_path(context, "OPENCODE_CONFIG") {
        evidence.push(path);
    }
    if let Some(path) = override_path(context, "OPENCODE_CONFIG_DIR") {
        evidence.extend([path.join("opencode.json"), path.join("opencode.jsonc")]);
    }
    (selected, base, unique_paths(evidence))
}
fn omp_marker(context: &ClientResolutionContext) -> PathBuf {
    context.home.join(
        context
            .environment
            .get("PI_CONFIG_DIR")
            .map(String::as_str)
            .unwrap_or(".omp"),
    )
}
fn omp_path(context: &ClientResolutionContext) -> PathBuf {
    let root = omp_marker(context);
    let profile = context
        .environment
        .get("OMP_PROFILE")
        .or_else(|| context.environment.get("PI_PROFILE"))
        .map(|value| value.trim())
        .filter(|value| !value.is_empty() && *value != "default");
    profile
        .map(|value| root.join("profiles").join(value).join("agent/mcp.json"))
        .unwrap_or_else(|| {
            override_path(context, "PI_CODING_AGENT_DIR")
                .unwrap_or_else(|| root.join("agent"))
                .join("mcp.json")
        })
}
fn unique_paths<I>(paths: I) -> Vec<PathBuf>
where
    I: IntoIterator<Item = PathBuf>,
{
    let mut unique = Vec::new();
    for path in paths {
        if !unique.contains(&path) {
            unique.push(path);
        }
    }
    unique
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> ClientResolutionContext {
        ClientResolutionContext::new(
            "/home/tester",
            "/workspace/project",
            ClientPlatform::Linux,
            BTreeMap::new(),
        )
    }

    #[test]
    fn resolves_the_complete_supported_client_inventory() {
        let targets = supported_client_targets(&context());

        assert_eq!(targets.len(), 25);
        assert_eq!(targets[0].id, "claude_code");
        assert!(targets.iter().any(|target| target.id == "grok_bot"));
        assert!(
            targets
                .iter()
                .all(|target| target.config_path_error.is_none())
        );
    }

    #[test]
    fn applies_explicit_environment_overrides_without_ambient_state() {
        let mut environment = BTreeMap::new();
        environment.insert("CODEX_HOME".to_owned(), "/tmp/codex".to_owned());
        environment.insert("QWEN_HOME".to_owned(), "~/qwen".to_owned());
        environment.insert(
            "OPENCODE_CONFIG".to_owned(),
            "configs/opencode.json".to_owned(),
        );
        let context = ClientResolutionContext::new(
            "/home/tester",
            "/workspace/project",
            ClientPlatform::Linux,
            environment,
        );
        let targets = supported_client_targets(&context);

        assert_eq!(
            targets
                .iter()
                .find(|target| target.id == "codex")
                .unwrap()
                .path,
            PathBuf::from("/tmp/codex/config.toml")
        );
        assert_eq!(
            targets
                .iter()
                .find(|target| target.id == "qwen_code")
                .unwrap()
                .path,
            PathBuf::from("/home/tester/qwen/settings.json")
        );
        assert_eq!(
            targets
                .iter()
                .find(|target| target.id == "opencode")
                .unwrap()
                .path,
            PathBuf::from("/workspace/project/configs/opencode.json")
        );
    }

    #[test]
    fn separates_skill_destinations_from_configuration_locations() {
        let destinations = canonical_client_skill_directories(&context(), None).expect("paths");

        assert!(
            destinations
                .iter()
                .any(|(name, path)| name == "shared" && path.ends_with(".agents/skills"))
        );
        assert!(
            !destinations
                .iter()
                .any(|(_, path)| path.ends_with("config.toml"))
        );
    }

    #[test]
    fn project_registration_evidence_requires_the_client_configuration() {
        let target = supported_client_targets(&context())
            .into_iter()
            .find(|target| target.id == "claude_code")
            .expect("claude code target");
        let project_target = project_registration_target(target, &context()).expect("project path");

        assert_eq!(
            project_target.path,
            PathBuf::from("/workspace/project/.mcp.json")
        );
        assert_eq!(
            project_target.evidence_paths,
            vec![project_target.path.clone()]
        );
        assert_eq!(
            project_target.marker_path,
            PathBuf::from("/workspace/project")
        );
    }
}
