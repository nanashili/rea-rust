//! Native streamable-HTTP MCP adapter.
//!
//! The MCP core remains the owner of catalog validation, Evidence delivery and
//! session recording. This module owns only listener configuration and the
//! rmcp/Axum transport boundary.

use crate::mcp_http_session::SingleSessionManager;
use axum::{Router, extract::Request, middleware, middleware::Next, response::Response};
use rea_core::cancellation::Cancellation;
use rea_mcp::{
    Composition, Progress,
    catalog::{catalog, compact_input_schema},
    protocol::Server as McpServer,
};
use rmcp::{
    ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, CompleteRequestParams,
        CompleteResult, GetPromptRequestParams, GetPromptResponse, Implementation,
        InitializeResult, ListPromptsResult, ListToolsResult, PaginatedRequestParams,
        ProgressNotificationParam, ProtocolVersion, ServerCapabilities, Tool,
    },
    service::{RequestContext, RoleServer},
    transport::{StreamableHttpServerConfig, StreamableHttpService},
};
use serde_json::{Value, value::RawValue};
use std::{
    collections::HashMap,
    future::IntoFuture,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 0;
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

pub fn run(arguments: &[String], composition: &dyn Composition) -> i32 {
    let command = match parse_arguments(arguments) {
        Ok(command) => command,
        Err(message) => {
            eprintln!("{message}");
            return 1;
        }
    };
    let HttpCommand::Serve { host, port } = command else {
        println!("{}", help_text());
        return 0;
    };
    if host.contains('%') {
        eprintln!("MCP HTTP does not support scoped IPv6 listener addresses");
        return 1;
    }
    let environment = std::env::vars().collect::<HashMap<_, _>>();
    if let Err(error) = rea_mcp::validate_configuration(&environment) {
        eprintln!("{}", error.user_message());
        return 1;
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("MCP HTTP runtime could not start: {error}");
            return 1;
        }
    };
    let result = runtime.block_on(serve(composition, environment, host, port));
    // A forced signal may leave a best-effort blocking cleanup task running;
    // do not let dropping the current-thread runtime wait for that task.
    runtime.shutdown_timeout(Duration::ZERO);
    result.unwrap_or_else(|error| {
        eprintln!("MCP HTTP server failed: {error}");
        1
    })
}

async fn serve(
    composition: &dyn Composition,
    environment: HashMap<String, String>,
    host: String,
    port: u16,
) -> Result<i32, String> {
    // Register signal listeners before either binding or constructing the core.
    let signals = SignalController::install().map_err(|error| error.to_string())?;
    let listener = TcpListener::bind((host.as_str(), port))
        .await
        .map_err(|error| error.to_string())?;
    let bound = listener.local_addr().map_err(|error| error.to_string())?;

    let progress_sink: rea_mcp::protocol::Sink = Arc::new(|_message: &RawValue| {});
    let server = rea_mcp::build(progress_sink, environment.clone(), composition)
        .map_err(|error| error.user_message())?;
    let completion = composition.completion(server.session());
    let capabilities = serde_json::from_value::<ServerCapabilities>(catalog().capabilities.clone())
        .map_err(|error| format!("MCP catalog capabilities are invalid: {error}"))?;
    let handler = Arc::new(HttpHandler {
        server,
        completion,
        capabilities,
        transport_stop: signals.graceful.clone(),
        active_calls: Arc::new(ActiveCalls::default()),
        include_output_schemas: rea_mcp::include_output_schemas(&environment)
            .map_err(|e| e.user_message())?,
        compact_input_schemas: rea_mcp::compact_input_schemas(&environment)
            .map_err(|e| e.user_message())?,
    });

    let config = http_config(&host, bound, signals.graceful.clone());
    let service_handler = Arc::clone(&handler);
    let sessions = Arc::new(SingleSessionManager::new(
        rmcp::transport::streamable_http_server::session::local::LocalSessionManager::default(),
    ));
    let service = StreamableHttpService::new(
        move || Ok((*service_handler).clone()),
        sessions.clone(),
        config,
    );
    let router = Router::new()
        .nest_service("/mcp", service)
        .layer(middleware::from_fn(normalize_delete_response));

    eprintln!(
        "{}",
        serde_json::json!({
            "transport": "streamable-http",
            "url": format!("http://{bound}/mcp"),
            "msg": "MCP transport listening"
        })
    );

    let serving = axum::serve(listener, router)
        .with_graceful_shutdown(signals.graceful.clone().cancelled_owned())
        .into_future();
    tokio::pin!(serving);
    let serving_result = tokio::select! {
        result = &mut serving => result.map_err(|error| error.to_string()),
        _ = signals.force.cancelled() => Err("MCP HTTP force shutdown requested".to_owned()),
    };
    signals.graceful.cancel();

    // A second signal is the force path. Return the signal status before any
    // cleanup can delay the process, matching the original CLI.
    if signals.force.is_cancelled() {
        return Ok(signals.exit_code());
    }

    let cleanup = cleanup_http(handler, sessions);
    tokio::pin!(cleanup);
    let cleanup_result = tokio::select! {
        result = &mut cleanup => result,
        _ = signals.force.cancelled() => return Ok(signals.exit_code()),
    };

    let mut failures = Vec::new();
    if let Err(error) = serving_result {
        failures.push(format!("serving failed: {error}"));
    }
    if let Err(error) = cleanup_result {
        failures.push(error);
    }
    if !failures.is_empty() {
        return Err(failures.join("; "));
    }
    Ok(signals.exit_code())
}

async fn cleanup_http(
    handler: Arc<HttpHandler>,
    sessions: Arc<
        SingleSessionManager<
            rmcp::transport::streamable_http_server::session::local::LocalSessionManager,
        >,
    >,
) -> Result<(), String> {
    let mut failures = Vec::new();

    if let Err(error) = handler.active_calls.wait_for_drain(SHUTDOWN_TIMEOUT).await {
        failures.push(error);
    }

    let server = Arc::clone(&handler.server);
    let core_result = tokio::task::spawn_blocking(move || {
        server.shutdown(SHUTDOWN_TIMEOUT);
    })
    .await;
    if let Err(error) = core_result {
        failures.push(format!("MCP core shutdown failed: {error}"));
    }

    match tokio::time::timeout(SHUTDOWN_TIMEOUT, sessions.shutdown()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => failures.push(error.to_string()),
        Err(_) => failures.push(format!(
            "MCP HTTP session shutdown exceeded {SHUTDOWN_TIMEOUT:?}"
        )),
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

async fn normalize_delete_response(request: Request, next: Next) -> Response {
    let is_delete = request.method() == axum::http::Method::DELETE;
    let mut response = next.run(request).await;
    if is_delete && response.status() == axum::http::StatusCode::ACCEPTED {
        *response.status_mut() = axum::http::StatusCode::NO_CONTENT;
    }
    response
}

fn http_config(
    host: &str,
    bound: SocketAddr,
    stop: CancellationToken,
) -> StreamableHttpServerConfig {
    let config = StreamableHttpServerConfig::default().with_cancellation_token(stop);
    if !is_loopback(bound.ip()) {
        eprintln!(
            "rea: MCP HTTP bound to non-loopback address {bound}; Host and Origin checks are disabled"
        );
        return config.disable_allowed_hosts().disable_allowed_origins();
    }
    let mut allowed = vec![
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        "::1".to_owned(),
        "[::1]".to_owned(),
        normalized_host_alias(host),
        normalized_host_alias(&bound.ip().to_string()),
    ];
    allowed.sort();
    allowed.dedup();
    let origins = allowed
        .iter()
        .map(|value| format_origin(value))
        .collect::<Vec<_>>();
    config
        .with_allowed_hosts(allowed)
        .with_allowed_origins(origins)
}

fn normalized_host_alias(host: &str) -> String {
    let unbracketed = host.trim_matches(['[', ']']);
    match unbracketed.parse::<IpAddr>() {
        Ok(IpAddr::V6(address)) => format!("[{address}]"),
        Ok(IpAddr::V4(address)) => address.to_string(),
        Err(_) => unbracketed.to_ascii_lowercase(),
    }
}

fn format_origin(host: &str) -> String {
    let host = host.trim_matches(['[', ']']);
    if host.contains(':') {
        format!("http://[{host}]:*")
    } else {
        format!("http://{host}:*")
    }
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => {
            ip == Ipv6Addr::LOCALHOST || ip.to_ipv4().is_some_and(|mapped| mapped.is_loopback())
        }
    }
}

struct SignalController {
    graceful: CancellationToken,
    force: CancellationToken,
    reason: Arc<AtomicU8>,
}

impl SignalController {
    fn install() -> std::io::Result<Self> {
        let controller = Self {
            graceful: CancellationToken::new(),
            force: CancellationToken::new(),
            reason: Arc::new(AtomicU8::new(0)),
        };
        let graceful = controller.graceful.clone();
        let force = controller.force.clone();
        let reason = Arc::clone(&controller.reason);

        #[cfg(unix)]
        let (mut interrupt, mut terminate) = {
            use tokio::signal::unix::{SignalKind, signal};
            (
                signal(SignalKind::interrupt())?,
                signal(SignalKind::terminate())?,
            )
        };

        tokio::spawn(async move {
            #[cfg(unix)]
            {
                tokio::select! {
                    _ = interrupt.recv() => reason.store(130, Ordering::Release),
                    _ = terminate.recv() => reason.store(143, Ordering::Release),
                }
                graceful.cancel();
                tokio::select! {
                    _ = interrupt.recv() => force.cancel(),
                    _ = terminate.recv() => force.cancel(),
                }
            }
            #[cfg(not(unix))]
            {
                if tokio::signal::ctrl_c().await.is_ok() {
                    reason.store(130, Ordering::Release);
                    graceful.cancel();
                }
            }
        });
        Ok(controller)
    }

    fn exit_code(&self) -> i32 {
        match self.reason.load(Ordering::Acquire) {
            130 | 143 => self.reason.load(Ordering::Acquire) as i32,
            _ => 0,
        }
    }
}

#[derive(Clone)]
struct HttpHandler {
    server: Arc<McpServer>,
    completion: Arc<dyn rea_mcp::CompletionProvider>,
    capabilities: ServerCapabilities,
    transport_stop: CancellationToken,
    active_calls: Arc<ActiveCalls>,
    include_output_schemas: bool,
    compact_input_schemas: bool,
}

#[derive(Default)]
struct ActiveCalls {
    count: AtomicUsize,
    drained: Notify,
}

impl ActiveCalls {
    fn enter(self: &Arc<Self>) -> ActiveCallGuard {
        self.count.fetch_add(1, Ordering::AcqRel);
        ActiveCallGuard {
            owner: Arc::clone(self),
        }
    }

    async fn wait_for_drain(&self, timeout: Duration) -> Result<(), String> {
        let wait = async {
            loop {
                if self.count.load(Ordering::Acquire) == 0 {
                    return;
                }
                self.drained.notified().await;
            }
        };
        tokio::time::timeout(timeout, wait)
            .await
            .map_err(|_| format!("MCP HTTP tool calls did not drain within {timeout:?}"))
    }
}

struct ActiveCallGuard {
    owner: Arc<ActiveCalls>,
}

impl Drop for ActiveCallGuard {
    fn drop(&mut self) {
        if self.owner.count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.owner.drained.notify_one();
        }
    }
}

struct ExecutionLifetime {
    _active_call: ActiveCallGuard,
    cancellation_watch: tokio::task::JoinHandle<()>,
}

impl Drop for ExecutionLifetime {
    fn drop(&mut self) {
        self.cancellation_watch.abort();
    }
}

impl ServerHandler for HttpHandler {
    fn get_info(&self) -> InitializeResult {
        InitializeResult::new(self.capabilities.clone())
            .with_protocol_version(ProtocolVersion::V_2025_11_25)
            .with_server_info(Implementation::new(
                catalog().server_name.clone(),
                catalog().server_version.clone(),
            ))
            .with_instructions(catalog().instructions.clone().unwrap_or_default())
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, rmcp::ErrorData>> + Send + '_
    {
        let result = catalog()
            .tools
            .iter()
            .map(|contract| {
                let mut listing = contract.listing(self.include_output_schemas);
                if self.compact_input_schemas {
                    if let Some(schema) = compact_input_schema(&contract.name) {
                        listing["inputSchema"] = schema.clone();
                    }
                }
                serde_json::from_value::<Tool>(listing).map_err(|error| {
                    rmcp::ErrorData::internal_error(
                        format!(
                            "catalog tool {} could not be encoded: {error}",
                            contract.name
                        ),
                        None,
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(ListToolsResult::with_all_items);
        std::future::ready(result)
    }

    fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListPromptsResult, rmcp::ErrorData>> + Send + '_
    {
        let result = serde_json::from_value(rea_mcp::prompts::list())
            .map_err(|error| rmcp::ErrorData::internal_error(error.to_string(), None));
        std::future::ready(result)
    }

    fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<GetPromptResponse, rmcp::ErrorData>> + Send + '_
    {
        let arguments = request.arguments.map(Value::Object);
        let result = rea_mcp::prompts::get(&request.name, arguments.as_ref())
            .map_err(|error| rmcp::ErrorData::invalid_params(error, None))
            .and_then(|value| {
                serde_json::from_value(value)
                    .map(rmcp::model::GetPromptResult::into)
                    .map_err(|error| rmcp::ErrorData::internal_error(error.to_string(), None))
            });
        std::future::ready(result)
    }

    fn complete(
        &self,
        request: CompleteRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CompleteResult, rmcp::ErrorData>> + Send + '_
    {
        let params = serde_json::to_value(request)
            .map_err(|error| rmcp::ErrorData::internal_error(error.to_string(), None));
        let result = params
            .and_then(|params| {
                rea_mcp::prompts::complete(&params, self.server.session(), self.completion.as_ref())
                    .map_err(|error| rmcp::ErrorData::invalid_params(error, None))
            })
            .and_then(|value| {
                serde_json::from_value(value)
                    .map_err(|error| rmcp::ErrorData::internal_error(error.to_string(), None))
            });
        std::future::ready(result)
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResponse, rmcp::ErrorData>> + Send + '_
    {
        let server = Arc::clone(&self.server);
        let active_calls = Arc::clone(&self.active_calls);
        let peer = context.peer.clone();
        let progress_token = context.meta.get_progress_token();
        let cancellation_token = context.ct.clone();
        let runtime = tokio::runtime::Handle::current();
        let transport_stop = self.transport_stop.clone();
        let name = request.name.to_string();
        let arguments = Value::Object(request.arguments.unwrap_or_default());
        async move {
            let contract = catalog().tool(&name).ok_or_else(|| {
                rmcp::ErrorData::invalid_params(format!("Tool {name} not found"), None)
            })?;
            let cancellation = Cancellation::default();
            let cancellation_for_watch = cancellation.clone();
            let cancellation_watch = tokio::spawn(async move {
                tokio::select! {
                    _ = cancellation_token.cancelled() => {},
                    _ = transport_stop.cancelled() => {},
                }
                cancellation_for_watch.cancel("MCP request cancelled");
            });
            let progress = progress_token.map_or_else(Progress::silent, |token| {
                Progress::new(Arc::new(move |value, message| {
                    let peer = peer.clone();
                    let token = token.clone();
                    runtime.spawn(async move {
                        if let Err(error) = peer
                            .notify_progress(
                                ProgressNotificationParam::new(token, value as f64)
                                    .with_message(message),
                            )
                            .await
                        {
                            eprintln!("rea: MCP progress notification failed: {error}");
                        }
                    });
                }))
            });
            let active_call = active_calls.enter();
            let result = tokio::task::spawn_blocking(move || {
                let _execution_lifetime = ExecutionLifetime {
                    _active_call: active_call,
                    cancellation_watch,
                };
                server.execute(contract, arguments, cancellation, progress)
            })
            .await;
            let result =
                result.map_err(|error| rmcp::ErrorData::internal_error(error.to_string(), None))?;
            let result = serde_json::from_value::<CallToolResult>(result)
                .map_err(|error| rmcp::ErrorData::internal_error(error.to_string(), None))?;
            Ok(CallToolResponse::Complete(result))
        }
    }
}

enum HttpCommand {
    Help,
    Serve { host: String, port: u16 },
}

fn parse_arguments(arguments: &[String]) -> Result<HttpCommand, String> {
    if arguments
        .iter()
        .any(|argument| argument == "--help" || argument == "-h")
    {
        return Ok(HttpCommand::Help);
    }
    let mut http = false;
    let mut host = None;
    let mut port = None;
    let mut index = 0;
    while index < arguments.len() {
        let (flag, inline) = arguments[index]
            .split_once('=')
            .map_or((arguments[index].as_str(), None), |(flag, value)| {
                (flag, Some(value))
            });
        match flag {
            "--http" if inline.is_none() => http = true,
            "--host" | "--port" => {
                let value = inline
                    .map(str::to_owned)
                    .or_else(|| {
                        index += 1;
                        arguments.get(index).cloned()
                    })
                    .ok_or_else(|| format!("Missing value for {flag}"))?;
                if value.starts_with('-') && inline.is_none() {
                    return Err(format!("Missing value for {flag}"));
                }
                if flag == "--host" {
                    host = Some(value);
                } else {
                    port = Some(value);
                }
            }
            _ => return Err(format!("Unknown mcp --http argument: {}", arguments[index])),
        }
        index += 1;
    }
    if !http {
        return Err("--host and --port require --http".into());
    }
    let host = host
        .or_else(|| std::env::var("MCP_HOST").ok())
        .unwrap_or_else(|| DEFAULT_HOST.into())
        .trim()
        .to_owned();
    if host.is_empty() {
        return Err("--host must be a non-empty host name or IP address".into());
    }
    let port_text = port.or_else(|| std::env::var("MCP_PORT").ok());
    let port = match port_text {
        None => DEFAULT_PORT,
        Some(value)
            if value == "0"
                || (!value.starts_with('0') && value.chars().all(|c| c.is_ascii_digit())) =>
        {
            value.parse::<u16>().map_err(|_| {
                "Invalid --port: MCP_PORT must be a decimal integer between 0 and 65535.".to_owned()
            })?
        }
        Some(_) => {
            return Err(
                "Invalid --port: MCP_PORT must be a decimal integer between 0 and 65535.".into(),
            );
        }
    };
    Ok(HttpCommand::Serve { host, port })
}

fn help_text() -> &'static str {
    "rea mcp --http — Serve the MCP server over streamable HTTP for one local client\n\nOptions:\n  --http          Serve at /mcp\n  --host HOST     Listener address; default MCP_HOST, else 127.0.0.1\n  --port PORT     Listener port; default MCP_PORT, else 0 for an ephemeral port\n  -h, --help      Show help"
}

#[cfg(test)]
mod tests {
    use super::{HttpCommand, parse_arguments};
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }
    #[test]
    fn parses_http_options_and_rejects_unrelated_flags() {
        assert!(
            matches!(parse_arguments(&args(&["--http", "--host= localhost ", "--port=4321"])), Ok(HttpCommand::Serve { host, port }) if host == "localhost" && port == 4321)
        );
        assert!(parse_arguments(&args(&["--host", "127.0.0.1"])).is_err());
    }
    #[test]
    fn help_wins_before_transport_validation() {
        assert!(matches!(
            parse_arguments(&args(&["--help", "--host"])),
            Ok(HttpCommand::Help)
        ));
    }
    #[test]
    fn mapped_loopback_and_ipv6_origins_are_safe() {
        assert!(super::is_loopback("::ffff:127.0.0.1".parse().unwrap()));
        assert_eq!(super::format_origin("::1"), "http://[::1]:*");
    }
}
