use anyhow::Context;
use clap::Parser;
use codex_arg0::arg0_dispatch_or_else;
use codex_backend_client::Client as BackendClient;
use codex_cli::login::read_api_key_from_stdin;
use codex_cli::login::run_login_status;
use codex_cli::login::run_login_with_api_key;
use codex_cli::login::run_login_with_chatgpt;
use codex_cli::login::run_login_with_device_code;
use codex_cli::login::run_logout;
use codex_common::CliConfigOverrides;
use codex_core::AuthManager;
use codex_core::CodexAuth;
use codex_core::ConversationManager;
use codex_core::ModelClient;
use codex_core::Prompt;
use codex_core::ResponseEvent;
use codex_core::RolloutRecorder;
use codex_core::ToolsConfig;
use codex_core::ToolsConfigParams;
use codex_core::blueprintlm_default_tool_specs_from_str;
use codex_core::config::Config;
use codex_core::config::ConfigOverrides;
use codex_core::features::Feature;
use codex_core::models_manager::manager::ModelsManager;
use codex_core::rollout::find_conversation_path_by_id_str;
use codex_core::rollout::list::Cursor as SessionsCursor;
use codex_core::rollout::list::get_conversations;
use codex_core::rollout::recorder::RolloutRecorderParams;
use codex_core::terminal;
use codex_otel::otel_manager::OtelManager;
use codex_protocol::ConversationId;
use codex_protocol::models::ResponseInputItem;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::InitialHistory;
use codex_protocol::protocol::RateLimitSnapshot;
use codex_protocol::protocol::RolloutItem;
use codex_protocol::protocol::RolloutLine;
use codex_protocol::protocol::SessionConfiguredEvent;
use codex_protocol::protocol::SessionSource;
use codex_protocol::protocol::TokenUsage;
use futures_util::StreamExt;
use serde::Deserialize;
use serde::Serialize;
use std::env;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::BufWriter;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use time::OffsetDateTime;
use time::macros::format_description;
use tracing::info;
use tracing::subscriber::DefaultGuard;
use tracing::warn;

/// Codex CLI
#[derive(Debug, Parser)]
#[clap(
    author,
    version,
    bin_name = "blueprintlm-cli",
    subcommand_required = true,
    override_usage = "blueprintlm-cli <COMMAND> [ARGS]"
)]
struct MultitoolCli {
    #[clap(flatten)]
    pub config_overrides: CliConfigOverrides,

    #[clap(subcommand)]
    subcommand: Subcommand,
}

#[derive(Debug, clap::Subcommand)]
enum Subcommand {
    /// Send a prompt and print the model response without launching the TUI.
    Ask(AskCommand),

    /// Validate tools JSON for `ask`.
    ValidateTools(ValidateToolsCommand),

    /// List recorded sessions as JSON.
    Sessions(SessionsCommand),

    /// Fetch rollout history for a recorded session as JSON.
    #[clap(name = "rollout-history")]
    RolloutHistory(RolloutHistoryCommand),

    /// Start a session and print session metadata as JSON.
    #[clap(name = "start-session")]
    StartSession(StartSessionCommand),

    /// Manage login.
    Login(LoginCommand),

    /// Remove stored authentication credentials.
    Logout(LogoutCommand),

    /// Fetch current rate limit snapshot and print JSON.
    GetRateLimits,

    /// List available models as JSON.
    Models,
}

#[derive(Debug, Parser)]
struct AskCommand {
    /// JSON object containing payloads and tool definitions (use '-' to read from stdin).
    #[arg(value_name = "ASK_INPUT_JSON")]
    input: String,

    /// Resume an existing session by id instead of starting a new one.
    #[arg(long = "session-id", value_name = "SESSION_ID")]
    session_id: String,

    /// Save per-turn prompt payloads for debugging into the Codex home debug directory.
    #[arg(long = "debug-save-prompts", default_value_t = false, hide = true)]
    debug_save_prompts: bool,

    /// Additional directories that should be writable alongside the primary workspace.
    #[arg(long = "add-dir", value_name = "DIR", value_hint = clap::ValueHint::DirPath)]
    add_dir: Vec<PathBuf>,

    /// Tell the agent to use the specified directory as its working root.
    #[clap(long = "cd", short = 'C', value_name = "DIR")]
    cwd: Option<PathBuf>,

    /// Stream output text deltas as NDJSON before the final response.
    #[arg(long = "stream", default_value_t = false)]
    stream: bool,

    /// Trigger a synthetic stream error instead of calling the API (debug only).
    #[arg(
        long = "debug-stream-error",
        value_name = "ERR_KIND",
        hide = true,
        help = "Trigger a synthetic stream error for testing (internal)"
    )]
    debug_stream_error: Option<String>,
}

#[derive(Debug, Parser)]
struct ValidateToolsCommand {
    /// JSON tool definitions (use '-' to read from stdin).
    #[arg(long = "tools", value_name = "TOOLS_JSON", required = true)]
    tools: String,
}

#[derive(Debug, Parser)]
struct SessionsCommand {
    /// Page size (max conversations to return).
    #[arg(long = "limit", default_value_t = 50)]
    page_size: usize,

    /// Pagination cursor returned from a previous call.
    #[arg(long)]
    cursor: Option<String>,

    /// Filter by model provider (comma-separated). Defaults to all.
    #[arg(long = "provider", value_delimiter = ',', value_name = "PROVIDER")]
    providers: Vec<String>,

    /// Filter by project id.
    #[arg(long = "project-id", value_name = "PROJECT_ID")]
    project_id: Option<String>,
}

#[derive(Debug, Parser)]
struct RolloutHistoryCommand {
    /// Session id to read history for.
    #[arg(long = "session-id", value_name = "SESSION_ID")]
    session_id: String,
}

#[derive(Debug, Parser)]
struct StartSessionCommand {
    /// Additional directories that should be writable alongside the primary workspace.
    #[arg(long = "add-dir", value_name = "DIR", value_hint = clap::ValueHint::DirPath)]
    add_dir: Vec<PathBuf>,

    /// Tell the agent to use the specified directory as its working root.
    #[clap(long = "cd", short = 'C', value_name = "DIR")]
    cwd: Option<PathBuf>,

    /// Project identifier to record in session metadata.
    #[arg(long = "project-id", value_name = "PROJECT_ID")]
    project_id: String,

    /// Inline contents of AGENTS.md to use for this session (use '-' to read from stdin).
    #[arg(long = "project-doc", value_name = "AGENTS_MD", required = true)]
    project_doc: String,

    /// Simulate a start-session failure for testing error handling.
    #[arg(long = "debug-start-session-error", value_name = "KIND", hide = true)]
    debug_start_session_error: Option<String>,
}

#[derive(Debug, Parser)]
struct LoginCommand {
    #[clap(skip)]
    config_overrides: CliConfigOverrides,

    #[arg(
        long = "with-api-key",
        help = "Read the API key from stdin (e.g. `printenv OPENAI_API_KEY | blueprintlm-cli login --with-api-key`)"
    )]
    with_api_key: bool,

    #[arg(
        long = "api-key",
        value_name = "API_KEY",
        help = "(deprecated) Previously accepted the API key directly; now exits with guidance to use --with-api-key",
        hide = true
    )]
    api_key: Option<String>,

    #[arg(long = "device-auth")]
    use_device_code: bool,

    /// EXPERIMENTAL: Use custom OAuth issuer base URL (advanced)
    /// Override the OAuth issuer base URL (advanced)
    #[arg(long = "experimental_issuer", value_name = "URL", hide = true)]
    issuer_base_url: Option<String>,

    /// EXPERIMENTAL: Use custom OAuth client ID (advanced)
    #[arg(long = "experimental_client-id", value_name = "CLIENT_ID", hide = true)]
    client_id: Option<String>,

    #[command(subcommand)]
    action: Option<LoginSubcommand>,
}

#[derive(Debug, clap::Subcommand)]
enum LoginSubcommand {
    /// Show login status.
    Status,
}

#[derive(Debug, Parser)]
struct LogoutCommand {
    #[clap(skip)]
    config_overrides: CliConfigOverrides,
}

fn main() -> anyhow::Result<()> {
    arg0_dispatch_or_else(|codex_linux_sandbox_exe| async move {
        cli_main(codex_linux_sandbox_exe).await?;
        Ok(())
    })
}

async fn cli_main(_codex_linux_sandbox_exe: Option<PathBuf>) -> anyhow::Result<()> {
    let MultitoolCli {
        config_overrides: root_config_overrides,
        subcommand,
    } = MultitoolCli::parse();

    match subcommand {
        Subcommand::Ask(AskCommand {
            input,
            session_id,
            debug_save_prompts,
            add_dir,
            cwd,
            stream,
            debug_stream_error,
        }) => {
            let resolved_ask_input = resolve_ask_input(input, &mut std::io::stdin().lock())?;
            run_ask(
                resolved_ask_input,
                AskRunParams {
                    session_id,
                    debug_save_prompts,
                    add_dir,
                    cwd,
                    stream_output: stream,
                    debug_stream_error,
                    root_config_overrides,
                },
            )
            .await?;
        }
        Subcommand::ValidateTools(ValidateToolsCommand { tools }) => {
            let tools_json = resolve_tools_input(tools, &mut std::io::stdin().lock())?;
            run_validate_tools(tools_json, root_config_overrides).await?;
        }
        Subcommand::Sessions(SessionsCommand {
            page_size,
            cursor,
            providers,
            project_id,
        }) => {
            let cursor = if let Some(cursor) = cursor {
                Some(
                    serde_json::from_str::<SessionsCursor>(&format!("\"{cursor}\""))
                        .context("invalid cursor")?,
                )
            } else {
                None
            };
            let cli_overrides = root_config_overrides
                .parse_overrides()
                .map_err(anyhow::Error::msg)?;
            let config = Config::load_with_cli_overrides_and_harness_overrides(
                cli_overrides,
                ConfigOverrides::default(),
            )
            .await?;
            let provider_refs: Option<&[String]> = if providers.is_empty() {
                None
            } else {
                Some(&providers)
            };
            let conversations = get_conversations(
                &config.codex_home,
                page_size,
                cursor.as_ref(),
                &[
                    SessionSource::Cli,
                    SessionSource::Exec,
                    SessionSource::VSCode,
                ],
                provider_refs,
                config.model_provider_id.as_str(),
                project_id.as_deref(),
            )
            .await?;
            let json = serde_json::to_string_pretty(&conversations)?;
            println!("{json}");
        }
        Subcommand::RolloutHistory(RolloutHistoryCommand { session_id }) => {
            run_rollout_history(session_id, root_config_overrides).await?;
        }
        Subcommand::StartSession(StartSessionCommand {
            add_dir,
            cwd,
            project_id,
            project_doc,
            debug_start_session_error,
        }) => {
            run_start_session(
                add_dir,
                cwd,
                project_id,
                project_doc,
                debug_start_session_error,
                root_config_overrides,
            )
            .await?;
        }
        Subcommand::Login(mut login_cli) => {
            prepend_config_flags(
                &mut login_cli.config_overrides,
                root_config_overrides.clone(),
            );
            match login_cli.action {
                Some(LoginSubcommand::Status) => {
                    run_login_status(login_cli.config_overrides).await;
                }
                None => {
                    if login_cli.use_device_code {
                        run_login_with_device_code(
                            login_cli.config_overrides,
                            login_cli.issuer_base_url,
                            login_cli.client_id,
                        )
                        .await;
                    } else if login_cli.api_key.is_some() {
                        eprintln!(
                            "The --api-key flag is no longer supported. Pipe the key instead, e.g. `printenv OPENAI_API_KEY | blueprintlm-cli login --with-api-key`."
                        );
                        std::process::exit(1);
                    } else if login_cli.with_api_key {
                        let api_key = read_api_key_from_stdin();
                        run_login_with_api_key(login_cli.config_overrides, api_key).await;
                    } else {
                        run_login_with_chatgpt(login_cli.config_overrides).await;
                    }
                }
            }
        }
        Subcommand::Logout(mut logout_cli) => {
            prepend_config_flags(
                &mut logout_cli.config_overrides,
                root_config_overrides.clone(),
            );
            run_logout(logout_cli.config_overrides).await;
        }
        Subcommand::GetRateLimits => {
            run_get_rate_limits(root_config_overrides).await?;
        }
        Subcommand::Models => {
            run_list_models(root_config_overrides).await?;
        }
    }

    Ok(())
}

/// Prepend root-level overrides so they have lower precedence than
/// CLI-specific ones specified after the subcommand (if any).
fn prepend_config_flags(
    subcommand_config_overrides: &mut CliConfigOverrides,
    cli_config_overrides: CliConfigOverrides,
) {
    subcommand_config_overrides
        .raw_overrides
        .splice(0..0, cli_config_overrides.raw_overrides);
}

#[derive(Serialize)]
struct AskResponse {
    success: bool,
    error: Option<String>,
    response: Vec<RolloutLine>,
}

#[derive(Serialize)]
struct AskStreamEvent {
    success: bool,
    error: Option<String>,
    #[serde(flatten)]
    event: AskStreamEventKind,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum AskStreamEventKind {
    Created,
    OutputTextDelta {
        delta: String,
    },
    ReasoningSummaryDelta {
        delta: String,
        summary_index: i64,
    },
    ReasoningContentDelta {
        delta: String,
        content_index: i64,
    },
    ReasoningSummaryPartAdded {
        summary_index: i64,
    },
    OutputItemAdded {
        item: ResponseItem,
    },
    OutputItemDone {
        item: ResponseItem,
    },
    Completed {
        response_id: String,
        token_usage: Option<TokenUsage>,
    },
    RateLimits {
        snapshot: RateLimitSnapshot,
    },
}

#[derive(Serialize)]
struct ValidateToolsResponse {
    success: bool,
    error: Option<String>,
    tool_count: usize,
}

#[derive(Serialize)]
struct StartSessionResponse {
    success: bool,
    session: Option<SessionConfiguredEvent>,
    error: Option<String>,
}

#[derive(Serialize)]
struct RolloutHistoryResponse {
    success: bool,
    error: Option<String>,
    session_id: Option<String>,
    rollout_path: Option<String>,
    history: Vec<RolloutLine>,
}

fn emit_error(error: String, pretty: bool) -> anyhow::Result<()> {
    let response = AskResponse {
        success: false,
        error: Some(error),
        response: Vec::new(),
    };
    print_ask_response(&response, pretty)
}

fn print_ask_response(response: &AskResponse, pretty: bool) -> anyhow::Result<()> {
    let json = if pretty {
        serde_json::to_string_pretty(response)?
    } else {
        serde_json::to_string(response)?
    };
    println!("{json}");
    Ok(())
}

fn emit_stream_event(writer: &mut impl Write, event: AskStreamEvent) -> anyhow::Result<()> {
    let json = serde_json::to_string(&event)?;
    writeln!(writer, "{json}")?;
    writer.flush()?;
    Ok(())
}

fn response_items_from_history(
    history: &InitialHistory,
) -> anyhow::Result<(ConversationId, Vec<ResponseItem>)> {
    match history {
        InitialHistory::Resumed(resumed) => {
            let mut items = Vec::new();
            for item in &resumed.history {
                match item {
                    RolloutItem::ResponseItem(ri) => items.push(ri.clone()),
                    RolloutItem::Compacted(compacted) => {
                        items.push(ResponseItem::from(compacted.clone()))
                    }
                    _ => {}
                }
            }
            Ok((resumed.conversation_id, items))
        }
        _ => Err(anyhow::anyhow!(
            "Session history not found for provided session id"
        )),
    }
}

fn emit_rollout_history_error(error: String) -> anyhow::Result<()> {
    let response = RolloutHistoryResponse {
        success: false,
        error: Some(error),
        session_id: None,
        rollout_path: None,
        history: Vec::new(),
    };
    let json = serde_json::to_string_pretty(&response)?;
    println!("{json}");
    Ok(())
}

fn read_full_rollout(path: &Path) -> io::Result<(Vec<RolloutLine>, ConversationId)> {
    let text = fs::read_to_string(path)?;
    if text.trim().is_empty() {
        return Err(io::Error::other("empty session file"));
    }

    let mut history: Vec<RolloutLine> = Vec::new();
    let mut conversation_id: Option<ConversationId> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<RolloutLine>(trimmed) {
            Ok(rollout_line) => {
                if conversation_id.is_none()
                    && let RolloutItem::SessionMeta(session_meta_line) = &rollout_line.item
                {
                    conversation_id = Some(session_meta_line.meta.id);
                }
                history.push(rollout_line);
            }
            Err(err) => {
                eprintln!("Failed to parse rollout line: {err}");
            }
        }
    }

    let Some(conversation_id) = conversation_id else {
        return Err(io::Error::other(
            "failed to parse conversation ID from rollout file",
        ));
    };

    Ok((history, conversation_id))
}

#[derive(Debug, Deserialize)]
struct AskInput {
    payloads: serde_json::Value,
    tools: serde_json::Value,
}

struct ResolvedAskInput {
    ask_input: AskInput,
    stdin_raw: Option<String>,
}

struct AskRunParams {
    session_id: String,
    debug_save_prompts: bool,
    add_dir: Vec<PathBuf>,
    cwd: Option<PathBuf>,
    stream_output: bool,
    debug_stream_error: Option<String>,
    root_config_overrides: CliConfigOverrides,
}

fn parse_ask_input(raw: &str) -> anyhow::Result<AskInput> {
    serde_json::from_str(raw)
        .context("invalid ask input JSON; expected object with \"payloads\" and \"tools\"")
}

fn resolve_ask_input(input: String, mut reader: impl Read) -> anyhow::Result<ResolvedAskInput> {
    if input != "-" {
        return Ok(ResolvedAskInput {
            ask_input: parse_ask_input(&input)?,
            stdin_raw: None,
        });
    }

    let mut buf = String::new();
    reader.read_to_string(&mut buf)?;
    if buf.trim().is_empty() {
        anyhow::bail!("stdin ask input must not be empty");
    }
    Ok(ResolvedAskInput {
        ask_input: parse_ask_input(&buf)?,
        stdin_raw: Some(buf),
    })
}

fn resolve_tools_input(input: String, mut reader: impl Read) -> anyhow::Result<String> {
    if input != "-" {
        return Ok(input);
    }

    let mut buf = String::new();
    reader.read_to_string(&mut buf)?;
    if buf.trim().is_empty() {
        anyhow::bail!("stdin tools input must not be empty");
    }
    Ok(buf)
}

async fn run_ask(resolved_ask_input: ResolvedAskInput, params: AskRunParams) -> anyhow::Result<()> {
    let ResolvedAskInput {
        ask_input,
        stdin_raw,
    } = resolved_ask_input;
    let AskRunParams {
        session_id,
        debug_save_prompts,
        add_dir,
        cwd,
        stream_output,
        debug_stream_error,
        root_config_overrides,
    } = params;
    let cli_overrides = root_config_overrides
        .parse_overrides()
        .map_err(anyhow::Error::msg)?;
    let config_overrides = ConfigOverrides {
        cwd: cwd.clone(),
        additional_writable_roots: add_dir.clone(),
        ..Default::default()
    };
    let config =
        Config::load_with_cli_overrides_and_harness_overrides(cli_overrides, config_overrides)
            .await?;

    if debug_save_prompts {
        let debug_dir = config.codex_home.join("debug").join("prompts");
        // set_var is marked unsafe in this build; we only write trusted paths here.
        unsafe {
            std::env::set_var("CODEX_SAVE_PROMPTS_DIR", &debug_dir);
        }
    }

    let auth_manager = AuthManager::shared(
        config.codex_home.clone(),
        true,
        config.cli_auth_credentials_store_mode,
    );
    let models_manager = ModelsManager::new(auth_manager.clone());
    let Some(model) = config.model.as_deref() else {
        emit_error("model not configured".to_string(), !stream_output)?;
        return Ok(());
    };
    let model_family = models_manager.construct_model_family(model, &config).await;
    let model_family_for_client = model_family.clone();
    let conversation_id = match ConversationId::from_string(&session_id) {
        Ok(id) => id,
        Err(err) => {
            emit_error(err.to_string(), !stream_output)?;
            return Ok(());
        }
    };
    let rollout_path = match find_conversation_path_by_id_str(&config.codex_home, &session_id).await
    {
        Ok(Some(path)) => path,
        Ok(None) => {
            emit_error(
                format!("Session with id {session_id} not found"),
                !stream_output,
            )?;
            return Ok(());
        }
        Err(err) => {
            emit_error(format!("Failed to locate session: {err}"), !stream_output)?;
            return Ok(());
        }
    };
    let initial_history = match RolloutRecorder::get_rollout_history(&rollout_path).await {
        Ok(history) => history,
        Err(err) => {
            emit_error(
                format!("Failed to load session history: {err}"),
                !stream_output,
            )?;
            return Ok(());
        }
    };
    let (resumed_id, mut history_items) = match response_items_from_history(&initial_history) {
        Ok((id, items)) => (id, items),
        Err(err) => {
            emit_error(err.to_string(), !stream_output)?;
            return Ok(());
        }
    };
    let history_item_count = history_items.len();
    if resumed_id != conversation_id {
        emit_error(
            "Session id mismatch between provided id and rollout history".to_string(),
            !stream_output,
        )?;
        return Ok(());
    }
    let mut ask_log = create_ask_log_file(&config.codex_home, &conversation_id);
    let _tracing_guard = ask_log.as_ref().and_then(init_tracing);
    log_line(&mut ask_log, "ask started");
    log_line(&mut ask_log, format!("session id: {conversation_id}"));
    let rollout_path_display = rollout_path.display();
    log_line(
        &mut ask_log,
        format!("rollout path: {rollout_path_display}"),
    );
    let debug_stream_error_summary = debug_stream_error.as_deref().unwrap_or("none");
    log_line(
        &mut ask_log,
        format!(
            "stream_output: {stream_output}, debug_save_prompts: {debug_save_prompts}, debug_stream_error: {debug_stream_error_summary}"
        ),
    );
    if let Some(cwd) = &cwd {
        let cwd_display = cwd.display();
        log_line(&mut ask_log, format!("cwd override: {cwd_display}"));
    }
    if !add_dir.is_empty() {
        let add_dir_list = add_dir
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        log_line(
            &mut ask_log,
            format!("additional writable roots: {add_dir_list}"),
        );
    }
    if let Some(stdin_raw) = stdin_raw {
        log_line(&mut ask_log, format!("stdin ask input: {stdin_raw}"));
    }
    log_line(
        &mut ask_log,
        format!("loaded {history_item_count} history items from rollout"),
    );
    info!(
        session_id = %conversation_id,
        rollout_path = %rollout_path.display(),
        "resuming session from rollout"
    );
    let rollout_recorder =
        match RolloutRecorder::new(&config, RolloutRecorderParams::resume(rollout_path.clone()))
            .await
        {
            Ok(rec) => Some(rec),
            Err(err) => {
                eprintln!("Failed to open rollout recorder: {err}");
                None
            }
        };
    let auth = auth_manager.auth();
    let otel_event_manager = OtelManager::new(
        conversation_id,
        model,
        model_family.slug.as_str(),
        auth.as_ref().and_then(CodexAuth::get_account_id),
        auth.as_ref().and_then(CodexAuth::get_account_email),
        auth.as_ref().map(|a| a.mode),
        config.otel.log_user_prompt,
        terminal::user_agent(),
        SessionSource::Cli,
    );
    let provider = config.model_provider.clone();
    let provider_name = provider.name.clone();
    let provider_base_url = provider
        .base_url
        .clone()
        .unwrap_or_else(|| "default".to_string());
    let provider_wire = provider.wire_api;
    let provider_stream_idle_timeout_ms = provider.stream_idle_timeout().as_millis();
    let model_family_slug = model_family.slug.as_str();
    log_line(
        &mut ask_log,
        format!("model: {model} (family: {model_family_slug})"),
    );
    log_line(
        &mut ask_log,
        format!("provider: {provider_name} (wire: {provider_wire:?})"),
    );
    log_line(
        &mut ask_log,
        format!("provider base_url: {provider_base_url}"),
    );
    log_line(
        &mut ask_log,
        format!("stream_idle_timeout_ms: {provider_stream_idle_timeout_ms}"),
    );
    let client = ModelClient::new(
        Arc::new(config.clone()),
        Some(auth_manager),
        model_family_for_client,
        otel_event_manager,
        provider,
        config.model_reasoning_effort,
        config.model_reasoning_summary,
        conversation_id,
        SessionSource::Cli,
    );

    let payloads_json =
        serde_json::to_string(&ask_input.payloads).context("failed to serialize ask payloads")?;
    let tools_json =
        serde_json::to_string(&ask_input.tools).context("failed to serialize ask tools")?;
    let response_inputs: Vec<ResponseInputItem> =
        match serde_json::from_str::<Vec<ResponseInputItem>>(&payloads_json) {
            Ok(items) => items,
            Err(err) => {
                emit_error(
                    format!("Invalid payloads JSON (array parse error: {err})"),
                    !stream_output,
                )?;
                return Ok(());
            }
        };
    let new_items_count = response_inputs.len();
    log_line(
        &mut ask_log,
        format!("parsed payloads into {new_items_count} ResponseInputItem entries"),
    );
    let mut new_items: Vec<ResponseItem> = Vec::new();
    let mut prompt = Prompt::default();
    prompt.input.append(&mut history_items);
    for item in response_inputs {
        let response_item = ResponseItem::from(item);
        prompt.input.push(response_item.clone());
        new_items.push(response_item);
    }
    let total_prompt_items = prompt.input.len();
    log_line(
        &mut ask_log,
        format!(
            "seeded prompt with {history_item_count} history items and {new_items_count} new items (total {total_prompt_items})"
        ),
    );
    if let Some(recorder) = rollout_recorder.as_ref() {
        let to_record: Vec<RolloutItem> = new_items
            .iter()
            .cloned()
            .map(RolloutItem::ResponseItem)
            .collect();
        if let Err(err) = recorder.append_items(&to_record).await {
            eprintln!("Failed to record request items: {err}");
        } else if let Err(err) = recorder.flush().await {
            eprintln!("Failed to flush rollout after request items: {err}");
        }
    }

    let tools_config = ToolsConfig::new(&ToolsConfigParams {
        model_family: &model_family,
        features: &config.features,
    });
    let tools = match blueprintlm_default_tool_specs_from_str(&tools_config, &tools_json) {
        Ok(tools) => tools,
        Err(err) => {
            emit_error(
                format!("Failed to load tools from ask input: {err}"),
                !stream_output,
            )?;
            return Ok(());
        }
    };
    let tool_count = tools.len();
    let parallel_tool_calls = model_family.supports_parallel_tool_calls
        && config.features.enabled(Feature::ParallelToolCalls);
    prompt.set_tools(tools);
    prompt.set_parallel_tool_calls(parallel_tool_calls);
    log_line(
        &mut ask_log,
        format!("loaded {tool_count} tools (parallel_tool_calls: {parallel_tool_calls})"),
    );

    if debug_save_prompts {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let seconds = i128::from(timestamp.as_secs());
        let millis = i128::from(timestamp.subsec_millis());
        let path = config
            .codex_home
            .join("debug")
            .join("prompts")
            .join(format!(
                "prompt-{conversation_id}-{seconds}-{millis:03}.json"
            ));
        if let Some(parent) = path.parent() {
            if let Err(err) = fs::create_dir_all(parent) {
                eprintln!("Failed to create prompt debug directory: {err}");
                log_line(
                    &mut ask_log,
                    format!("failed to create prompt debug directory: {err}"),
                );
            } else {
                let payload = serde_json::json!({
                    "input": prompt.get_formatted_input(),
                    "instructions": prompt.get_full_instructions(&model_family),
                    "tools": prompt.tools().to_vec(),
                    "parallel_tool_calls": prompt.parallel_tool_calls(),
                });
                match serde_json::to_string_pretty(&payload) {
                    Ok(serialized) => {
                        if let Err(err) = fs::write(&path, serialized) {
                            eprintln!("Failed to write prompt debug file: {err}");
                            log_line(
                                &mut ask_log,
                                format!("failed to write prompt debug file: {err}"),
                            );
                        } else {
                            let path_display = path.display();
                            log_line(
                                &mut ask_log,
                                format!("saved prompt debug payload to {path_display}"),
                            );
                        }
                    }
                    Err(err) => {
                        eprintln!("Failed to serialize prompt debug payload: {err}");
                        log_line(
                            &mut ask_log,
                            format!("failed to serialize prompt debug payload: {err}"),
                        );
                    }
                }
            }
        }
    }

    let previous_debug_stream_error = if debug_stream_error.is_some() {
        env::var("BLUEPRINTLM_DEBUG_STREAM_ERROR").ok()
    } else {
        None
    };
    if let Some(kind) = debug_stream_error.clone() {
        log_line(&mut ask_log, format!("debug stream error injected: {kind}"));
        unsafe {
            env::set_var("BLUEPRINTLM_DEBUG_STREAM_ERROR", kind);
        }
    }

    log_line(
        &mut ask_log,
        format!(
            "starting response stream (provider: {provider_name}, wire: {provider_wire:?}, base_url: {provider_base_url})"
        ),
    );
    let request_started = Instant::now();
    let mut stream = match client.stream(&prompt).await {
        Ok(stream) => {
            let elapsed_ms = request_started.elapsed().as_millis();
            log_line(
                &mut ask_log,
                format!("response stream opened after {elapsed_ms}ms"),
            );
            stream
        }
        Err(err) => {
            let elapsed_ms = request_started.elapsed().as_millis();
            log_line(
                &mut ask_log,
                format!("response stream failed after {elapsed_ms}ms: {err}"),
            );
            if debug_stream_error.is_some() {
                if let Some(prev) = previous_debug_stream_error {
                    unsafe {
                        env::set_var("BLUEPRINTLM_DEBUG_STREAM_ERROR", prev);
                    }
                } else {
                    unsafe {
                        env::remove_var("BLUEPRINTLM_DEBUG_STREAM_ERROR");
                    }
                }
            }
            let response = AskResponse {
                success: false,
                error: Some(err.to_string()),
                response: Vec::new(),
            };
            print_ask_response(&response, !stream_output)?;
            return Ok(());
        }
    };
    if debug_stream_error.is_some() {
        if let Some(prev) = previous_debug_stream_error {
            unsafe {
                env::set_var("BLUEPRINTLM_DEBUG_STREAM_ERROR", prev);
            }
        } else {
            unsafe {
                env::remove_var("BLUEPRINTLM_DEBUG_STREAM_ERROR");
            }
        }
    }
    let stdout = io::stdout();
    let mut stream_stdout = if stream_output {
        Some(stdout.lock())
    } else {
        None
    };
    let mut first_event_logged = false;
    let mut saw_completed = false;
    let mut output_text_delta_count = 0usize;
    let mut reasoning_summary_delta_count = 0usize;
    let mut reasoning_content_delta_count = 0usize;
    let mut reasoning_summary_part_added_count = 0usize;
    let mut output_item_added_count = 0usize;
    let mut output_item_done_count = 0usize;
    let mut rate_limit_event_count = 0usize;
    let mut completed_response_id: Option<String> = None;
    let mut completed_token_usage: Option<TokenUsage> = None;
    let mut stream_error = None;
    let mut collected_items: Vec<RolloutLine> = Vec::new();
    while let Some(event) = stream.next().await {
        match event {
            Ok(ev) => {
                if !first_event_logged {
                    let elapsed_ms = request_started.elapsed().as_millis();
                    log_line(
                        &mut ask_log,
                        format!("first stream event after {elapsed_ms}ms"),
                    );
                    first_event_logged = true;
                }
                match ev {
                    ResponseEvent::Created => {
                        log_line(&mut ask_log, "stream event: created");
                        if let Some(stdout) = stream_stdout.as_mut() {
                            emit_stream_event(
                                stdout,
                                AskStreamEvent {
                                    success: true,
                                    error: None,
                                    event: AskStreamEventKind::Created,
                                },
                            )?;
                        }
                    }
                    ResponseEvent::OutputTextDelta(delta) => {
                        output_text_delta_count += 1;
                        log_line(
                            &mut ask_log,
                            format!("stream event: output_text_delta delta={delta:?}"),
                        );
                        if let Some(stdout) = stream_stdout.as_mut() {
                            emit_stream_event(
                                stdout,
                                AskStreamEvent {
                                    success: true,
                                    error: None,
                                    event: AskStreamEventKind::OutputTextDelta { delta },
                                },
                            )?;
                        }
                    }
                    ResponseEvent::ReasoningSummaryDelta {
                        delta,
                        summary_index,
                    } => {
                        reasoning_summary_delta_count += 1;
                        log_line(
                            &mut ask_log,
                            format!(
                                "stream event: reasoning_summary_delta summary_index={summary_index} delta={delta:?}"
                            ),
                        );
                        if let Some(stdout) = stream_stdout.as_mut() {
                            emit_stream_event(
                                stdout,
                                AskStreamEvent {
                                    success: true,
                                    error: None,
                                    event: AskStreamEventKind::ReasoningSummaryDelta {
                                        delta,
                                        summary_index,
                                    },
                                },
                            )?;
                        }
                    }
                    ResponseEvent::ReasoningContentDelta {
                        delta,
                        content_index,
                    } => {
                        reasoning_content_delta_count += 1;
                        log_line(
                            &mut ask_log,
                            format!(
                                "stream event: reasoning_content_delta content_index={content_index} delta={delta:?}"
                            ),
                        );
                        if let Some(stdout) = stream_stdout.as_mut() {
                            emit_stream_event(
                                stdout,
                                AskStreamEvent {
                                    success: true,
                                    error: None,
                                    event: AskStreamEventKind::ReasoningContentDelta {
                                        delta,
                                        content_index,
                                    },
                                },
                            )?;
                        }
                    }
                    ResponseEvent::ReasoningSummaryPartAdded { summary_index } => {
                        reasoning_summary_part_added_count += 1;
                        log_line(
                            &mut ask_log,
                            format!(
                                "stream event: reasoning_summary_part_added summary_index={summary_index}"
                            ),
                        );
                        if let Some(stdout) = stream_stdout.as_mut() {
                            emit_stream_event(
                                stdout,
                                AskStreamEvent {
                                    success: true,
                                    error: None,
                                    event: AskStreamEventKind::ReasoningSummaryPartAdded {
                                        summary_index,
                                    },
                                },
                            )?;
                        }
                    }
                    ResponseEvent::OutputItemAdded(item) => {
                        output_item_added_count += 1;
                        log_stream_event_payload(&mut ask_log, "output_item_added", &item);
                        if let Some(stdout) = stream_stdout.as_mut() {
                            emit_stream_event(
                                stdout,
                                AskStreamEvent {
                                    success: true,
                                    error: None,
                                    event: AskStreamEventKind::OutputItemAdded { item },
                                },
                            )?;
                        }
                    }
                    ResponseEvent::OutputItemDone(item) => {
                        output_item_done_count += 1;
                        log_stream_event_payload(&mut ask_log, "output_item_done", &item);
                        if let Some(stdout) = stream_stdout.as_mut() {
                            emit_stream_event(
                                stdout,
                                AskStreamEvent {
                                    success: true,
                                    error: None,
                                    event: AskStreamEventKind::OutputItemDone {
                                        item: item.clone(),
                                    },
                                },
                            )?;
                        }
                        let timestamp = OffsetDateTime::now_utc()
                        .format(&format_description!(
                            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
                        ))
                        .unwrap_or_else(|_| "unknown".to_string());
                        collected_items.push(RolloutLine {
                            timestamp,
                            item: RolloutItem::ResponseItem(item),
                        });
                    }
                    ResponseEvent::Completed {
                        response_id,
                        token_usage,
                    } => {
                        let response_id_for_log = response_id.clone();
                        let token_usage_for_log = token_usage.clone();
                        let token_usage_summary = token_usage_for_log
                            .as_ref()
                            .map(|usage| format!("{usage:?}"))
                            .unwrap_or_else(|| "none".to_string());
                        log_line(
                            &mut ask_log,
                            format!(
                                "stream event: completed response_id={response_id_for_log} token_usage={token_usage_summary}"
                            ),
                        );
                        if let Some(stdout) = stream_stdout.as_mut() {
                            emit_stream_event(
                                stdout,
                                AskStreamEvent {
                                    success: true,
                                    error: None,
                                    event: AskStreamEventKind::Completed {
                                        response_id,
                                        token_usage,
                                    },
                                },
                            )?;
                        }
                        saw_completed = true;
                        completed_response_id = Some(response_id_for_log.clone());
                        completed_token_usage = token_usage_for_log.clone();
                        let elapsed_ms = request_started.elapsed().as_millis();
                        log_line(
                            &mut ask_log,
                            format!(
                                "response completed: id={response_id_for_log} elapsed_ms={elapsed_ms} token_usage={token_usage_summary}"
                            ),
                        );
                        break;
                    }
                    ResponseEvent::RateLimits(snapshot) => {
                        rate_limit_event_count += 1;
                        let snapshot_for_log = snapshot.clone();
                        if let Some(stdout) = stream_stdout.as_mut() {
                            emit_stream_event(
                                stdout,
                                AskStreamEvent {
                                    success: true,
                                    error: None,
                                    event: AskStreamEventKind::RateLimits { snapshot },
                                },
                            )?;
                        }
                        match serde_json::to_string(&snapshot_for_log) {
                            Ok(snapshot_json) => {
                                log_line(
                                    &mut ask_log,
                                    format!("rate limits update: {snapshot_json}"),
                                );
                            }
                            Err(err) => {
                                log_line(
                                    &mut ask_log,
                                    format!("failed to serialize rate limits snapshot: {err}"),
                                );
                            }
                        }
                    }
                }
            }
            Err(err) => {
                stream_error = Some(err.to_string());
                warn!(
                    session_id = %conversation_id,
                    error = %err,
                    "stream returned error"
                );
                let elapsed_ms = request_started.elapsed().as_millis();
                log_line(
                    &mut ask_log,
                    format!("stream error after {elapsed_ms}ms: {err}"),
                );
                break;
            }
        }
    }

    let stream_error_summary = stream_error.as_deref().unwrap_or("none");
    let elapsed_ms = request_started.elapsed().as_millis();
    let response_items_count = collected_items.len();
    log_line(
        &mut ask_log,
        format!(
            "stream summary: completed={saw_completed} error={stream_error_summary} response_items={response_items_count} elapsed_ms={elapsed_ms}"
        ),
    );
    log_line(
        &mut ask_log,
        format!(
            "stream event counts: output_text_deltas={output_text_delta_count}, output_items_added={output_item_added_count}, output_items_done={output_item_done_count}, reasoning_summary_deltas={reasoning_summary_delta_count}, reasoning_content_deltas={reasoning_content_delta_count}, reasoning_summary_parts={reasoning_summary_part_added_count}, rate_limit_updates={rate_limit_event_count}"
        ),
    );
    if let Some(response_id) = completed_response_id.as_deref() {
        let token_usage_summary = completed_token_usage
            .as_ref()
            .map(|usage| format!("{usage:?}"))
            .unwrap_or_else(|| "none".to_string());
        log_line(
            &mut ask_log,
            format!(
                "completed response summary: id={response_id} token_usage={token_usage_summary}"
            ),
        );
    }
    let response = AskResponse {
        success: stream_error.is_none(),
        error: stream_error,
        response: collected_items,
    };
    info!(
        session_id = %conversation_id,
        response_items = response.response.len(),
        success = response.success,
        "ask completed"
    );
    if let Some(recorder) = rollout_recorder.as_ref() {
        let to_record: Vec<RolloutItem> = response
            .response
            .iter()
            .cloned()
            .map(|line| line.item)
            .collect();
        if let Err(err) = recorder.append_items(&to_record).await {
            eprintln!("Failed to record response items: {err}");
        } else if let Err(err) = recorder.flush().await {
            eprintln!("Failed to flush rollout after response items: {err}");
        }
    }
    log_line(&mut ask_log, "writing AskResponse JSON to stdout");
    if let Some(stdout) = stream_stdout.as_mut() {
        let json = serde_json::to_string(&response)?;
        writeln!(stdout, "{json}")?;
        stdout.flush()?;
    } else {
        print_ask_response(&response, true)?;
    }

    Ok(())
}

async fn run_validate_tools(
    tools_json: String,
    root_config_overrides: CliConfigOverrides,
) -> anyhow::Result<()> {
    let cli_overrides = root_config_overrides
        .parse_overrides()
        .map_err(anyhow::Error::msg)?;
    let config = Config::load_with_cli_overrides_and_harness_overrides(
        cli_overrides,
        ConfigOverrides::default(),
    )
    .await?;

    let auth_manager = AuthManager::shared(
        config.codex_home.clone(),
        true,
        config.cli_auth_credentials_store_mode,
    );
    let models_manager = ModelsManager::new(auth_manager);
    let Some(model) = config.model.as_deref() else {
        let response = ValidateToolsResponse {
            success: false,
            error: Some("model not configured".to_string()),
            tool_count: 0,
        };
        let json = serde_json::to_string_pretty(&response)?;
        println!("{json}");
        return Ok(());
    };
    let model_family = models_manager.construct_model_family(model, &config).await;
    let tools_config = ToolsConfig::new(&ToolsConfigParams {
        model_family: &model_family,
        features: &config.features,
    });
    let tool_count = match blueprintlm_default_tool_specs_from_str(&tools_config, &tools_json) {
        Ok(tools) => tools.len(),
        Err(err) => {
            let response = ValidateToolsResponse {
                success: false,
                error: Some(format!("Failed to load tools: {err}")),
                tool_count: 0,
            };
            let json = serde_json::to_string_pretty(&response)?;
            println!("{json}");
            return Ok(());
        }
    };

    let response = ValidateToolsResponse {
        success: true,
        error: None,
        tool_count,
    };
    let json = serde_json::to_string_pretty(&response)?;
    println!("{json}");
    Ok(())
}

async fn run_rollout_history(
    session_id: String,
    root_config_overrides: CliConfigOverrides,
) -> anyhow::Result<()> {
    let cli_overrides = root_config_overrides
        .parse_overrides()
        .map_err(anyhow::Error::msg)?;
    let config = Config::load_with_cli_overrides_and_harness_overrides(
        cli_overrides,
        ConfigOverrides::default(),
    )
    .await?;

    let conversation_id = match ConversationId::from_string(&session_id) {
        Ok(id) => id,
        Err(err) => {
            emit_rollout_history_error(err.to_string())?;
            return Ok(());
        }
    };

    let rollout_path = match find_conversation_path_by_id_str(&config.codex_home, &session_id).await
    {
        Ok(Some(path)) => path,
        Ok(None) => {
            emit_rollout_history_error(format!("Session with id {session_id} not found"))?;
            return Ok(());
        }
        Err(err) => {
            emit_rollout_history_error(format!("Failed to locate session: {err}"))?;
            return Ok(());
        }
    };

    let (history, parsed_id) = match read_full_rollout(&rollout_path) {
        Ok(result) => result,
        Err(err) => {
            emit_rollout_history_error(format!("Failed to read rollout history: {err}"))?;
            return Ok(());
        }
    };

    if parsed_id != conversation_id {
        emit_rollout_history_error(
            "Session id mismatch between provided id and rollout history".to_string(),
        )?;
        return Ok(());
    }

    let response = RolloutHistoryResponse {
        success: true,
        error: None,
        session_id: Some(conversation_id.to_string()),
        rollout_path: Some(rollout_path.to_string_lossy().into_owned()),
        history,
    };
    let json = serde_json::to_string_pretty(&response)?;
    println!("{json}");
    Ok(())
}

async fn run_start_session(
    add_dir: Vec<PathBuf>,
    cwd: Option<PathBuf>,
    project_id: String,
    project_doc: String,
    debug_start_session_error: Option<String>,
    root_config_overrides: CliConfigOverrides,
) -> anyhow::Result<()> {
    if let Some(kind) = debug_start_session_error
        && kind == "io"
    {
        let response = StartSessionResponse {
            success: false,
            session: None,
            error: Some("simulated io error".to_string()),
        };
        let json = serde_json::to_string_pretty(&response)?;
        println!("{json}");
        return Ok(());
    }

    let mut project_doc_override = project_doc;
    if project_doc_override.trim().is_empty() {
        anyhow::bail!("--project-doc must not be empty");
    }
    if project_doc_override == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        if buf.trim().is_empty() {
            anyhow::bail!("--project-doc stdin content must not be empty");
        }
        project_doc_override = buf;
    }

    let cli_overrides = root_config_overrides
        .parse_overrides()
        .map_err(anyhow::Error::msg)?;
    let config_overrides = ConfigOverrides {
        cwd: cwd.clone(),
        additional_writable_roots: add_dir.clone(),
        project_id: Some(project_id),
        ..Default::default()
    };
    let mut config =
        Config::load_with_cli_overrides_and_harness_overrides(cli_overrides, config_overrides)
            .await?;
    config.user_instructions = None;
    config.project_doc_override = Some(project_doc_override);

    let auth_manager = AuthManager::shared(
        config.codex_home.clone(),
        true,
        config.cli_auth_credentials_store_mode,
    );
    let conversation_manager = ConversationManager::new(auth_manager, SessionSource::Cli);
    let response = match conversation_manager.new_conversation(config).await {
        Ok(new_conversation) => StartSessionResponse {
            success: true,
            session: Some(new_conversation.session_configured),
            error: None,
        },
        Err(err) => StartSessionResponse {
            success: false,
            session: None,
            error: Some(err.to_string()),
        },
    };

    let json = serde_json::to_string_pretty(&response)?;
    println!("{json}");

    Ok(())
}

async fn run_get_rate_limits(root_config_overrides: CliConfigOverrides) -> anyhow::Result<()> {
    let cli_overrides = root_config_overrides
        .parse_overrides()
        .map_err(anyhow::Error::msg)?;
    let config = Config::load_with_cli_overrides_and_harness_overrides(
        cli_overrides,
        ConfigOverrides::default(),
    )
    .await?;

    let auth_manager = AuthManager::shared(
        config.codex_home.clone(),
        true,
        config.cli_auth_credentials_store_mode,
    );
    let Some(auth) = auth_manager.auth() else {
        anyhow::bail!("Not logged in; run `blueprintlm-cli login` first.");
    };

    let client = BackendClient::from_auth(config.chatgpt_base_url.clone(), &auth).await?;
    let snapshot = client.get_rate_limits().await?;
    let json = serde_json::to_string_pretty(&snapshot)?;
    println!("{json}");
    Ok(())
}

async fn run_list_models(root_config_overrides: CliConfigOverrides) -> anyhow::Result<()> {
    let cli_overrides = root_config_overrides
        .parse_overrides()
        .map_err(anyhow::Error::msg)?;
    let config = Config::load_with_cli_overrides_and_harness_overrides(
        cli_overrides,
        ConfigOverrides::default(),
    )
    .await?;

    let auth_manager = AuthManager::shared(
        config.codex_home.clone(),
        true,
        config.cli_auth_credentials_store_mode,
    );
    let models_manager = ModelsManager::new(auth_manager);
    let presets = models_manager.list_models(&config).await;
    let json = serde_json::to_string_pretty(&presets)?;
    println!("{json}");
    Ok(())
}

struct AskLog {
    writer: BufWriter<File>,
    path: PathBuf,
}

fn create_ask_log_file(base_dir: &Path, conversation_id: &ConversationId) -> Option<AskLog> {
    let now = OffsetDateTime::now_utc();
    let log_dir = base_dir
        .join("log")
        .join(now.year().to_string())
        .join(format!("{:02}", u8::from(now.month())))
        .join(format!("{:02}", now.day()));
    if let Err(err) = fs::create_dir_all(&log_dir) {
        eprintln!(
            "Failed to create log directory {}: {}",
            log_dir.display(),
            err
        );
        return None;
    }

    let timestamp = now
        .format(&format_description!(
            "[hour]-[minute]-[second].[subsecond digits:3]Z"
        ))
        .unwrap_or_else(|_| "unknown".to_string());
    let filename = format!("ask-{conversation_id}-{timestamp}.log");
    let path = log_dir.join(filename);
    match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(file) => {
            let message = format!("log started for {conversation_id}");
            log_line_raw(&path, file, &message).map(|writer| AskLog { writer, path })
        }
        Err(err) => {
            eprintln!("Failed to open log file {}: {}", path.display(), err);
            warn!(path = %path.display(), "failed to create ask log file");
            None
        }
    }
}

fn log_line(log: &mut Option<AskLog>, message: impl AsRef<str>) {
    if let Some(log) = log {
        if let Err(err) = writeln!(log.writer, "[{}] {}", log_timestamp(), message.as_ref()) {
            eprintln!("Failed to write ask log line: {err}");
        }
        let _ = log.writer.flush();
    }
}

fn log_line_raw(path: &Path, file: File, message: &str) -> Option<BufWriter<File>> {
    let mut writer = BufWriter::new(file);
    if writeln!(writer, "[{}] {message}", log_timestamp()).is_err() {
        eprintln!("Failed to write initial ask log line to {}", path.display());
        return None;
    }
    Some(writer)
}

fn log_stream_event_payload<T: Serialize>(log: &mut Option<AskLog>, label: &str, payload: &T) {
    match serde_json::to_string(payload) {
        Ok(payload_json) => {
            log_line(log, format!("stream event: {label} payload={payload_json}"));
        }
        Err(err) => {
            log_line(
                log,
                format!("stream event: {label} payload_serialization_error={err}"),
            );
        }
    }
}

fn log_timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
        ))
        .unwrap_or_else(|_| "unknown".to_string())
}

#[allow(clippy::expect_used)]
fn init_tracing(log: &AskLog) -> Option<DefaultGuard> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log.path)
        .ok()?;

    // Clone the file handle for the subscriber; our manual log writes use a separate handle.
    let writer = move || {
        file.try_clone()
            .map(BufWriter::new)
            .expect("failed to clone log file handle")
    };
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(writer)
        .with_target(false)
        .finish();

    Some(tracing::subscriber::set_default(subscriber))
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_protocol::protocol::SessionMeta;
    use codex_protocol::protocol::SessionMetaLine;
    use pretty_assertions::assert_eq;
    use std::io::Cursor;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn ask_subcommand_parses_bundle_arg() {
        let bundle = r#"{"payloads":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}],"tools":{"tools":[{"type":"function","name":"get_project_directory","description":"Declares the UE5 project directory resolver. Codex only surfaces the tool; the UE plugin executes it.","parameters":{"type":"object","properties":{"project_dir":{"type":"string"}},"additionalProperties":false},"strict":false}]}}"#;
        let cli = MultitoolCli::try_parse_from([
            "blueprintlm-cli",
            "ask",
            "--session-id",
            "abc",
            "-C",
            "/tmp",
            "--add-dir",
            "/tmp/foo",
            bundle,
        ])
        .expect("parse");
        let Subcommand::Ask(AskCommand {
            input,
            session_id,
            add_dir,
            cwd,
            debug_save_prompts,
            stream,
            debug_stream_error,
        }) = cli.subcommand
        else {
            unreachable!()
        };
        assert_eq!(input, bundle);
        assert_eq!(session_id.as_str(), "abc");
        assert_eq!(add_dir, vec![std::path::PathBuf::from("/tmp/foo")]);
        assert_eq!(cwd.as_deref(), Some(std::path::Path::new("/tmp")));
        assert!(!debug_save_prompts);
        assert!(!stream);
        assert!(debug_stream_error.is_none());
    }

    #[test]
    fn validate_tools_subcommand_parses() {
        let cli =
            MultitoolCli::try_parse_from(["blueprintlm-cli", "validate-tools", "--tools", "-"])
                .expect("parse");
        let Subcommand::ValidateTools(ValidateToolsCommand { tools }) = cli.subcommand else {
            unreachable!()
        };
        assert_eq!(tools, "-");
    }

    #[test]
    fn models_subcommand_parses() {
        let cli = MultitoolCli::try_parse_from(["blueprintlm-cli", "models"]).expect("parse");
        assert!(matches!(cli.subcommand, Subcommand::Models));
    }

    #[test]
    fn start_session_subcommand_parses() {
        let cli = MultitoolCli::try_parse_from([
            "blueprintlm-cli",
            "start-session",
            "-C",
            "/tmp",
            "--add-dir",
            "/tmp/foo",
            "--project-id",
            "proj123",
            "--project-doc",
            "agents text",
            "--debug-start-session-error",
            "io",
        ])
        .expect("parse");
        let Subcommand::StartSession(StartSessionCommand {
            add_dir,
            cwd,
            project_id,
            project_doc,
            debug_start_session_error,
        }) = cli.subcommand
        else {
            unreachable!()
        };
        assert_eq!(add_dir, vec![std::path::PathBuf::from("/tmp/foo")]);
        assert_eq!(cwd.as_deref(), Some(std::path::Path::new("/tmp")));
        assert_eq!(project_id, "proj123");
        assert_eq!(project_doc, "agents text");
        assert_eq!(debug_start_session_error.as_deref(), Some("io"));
    }

    #[test]
    fn resolve_ask_input_reads_from_stdin() {
        let mut stdin = Cursor::new(
            r#"{"payloads":[{"type":"message","role":"user","content":[{"type":"input_text","text":"from stdin"}]}],"tools":[{"type":"function","name":"get_project_directory","description":"Declares the UE5 project directory resolver. Codex only surfaces the tool; the UE plugin executes it.","parameters":{"type":"object","properties":{"project_dir":{"type":"string"}},"additionalProperties":false},"strict":false}]}"#,
        );
        let ResolvedAskInput {
            ask_input,
            stdin_raw,
        } = resolve_ask_input("-".to_string(), &mut stdin).expect("ask input");
        assert_eq!(
            stdin_raw.as_deref(),
            Some(
                r#"{"payloads":[{"type":"message","role":"user","content":[{"type":"input_text","text":"from stdin"}]}],"tools":[{"type":"function","name":"get_project_directory","description":"Declares the UE5 project directory resolver. Codex only surfaces the tool; the UE plugin executes it.","parameters":{"type":"object","properties":{"project_dir":{"type":"string"}},"additionalProperties":false},"strict":false}]}"#
            )
        );
        assert_eq!(
            ask_input.payloads,
            serde_json::json!([{
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": "from stdin"}]
            }])
        );
        assert_eq!(
            ask_input.tools,
            serde_json::json!([{
                "type": "function",
                "name": "get_project_directory",
                "description": "Declares the UE5 project directory resolver. Codex only surfaces the tool; the UE plugin executes it.",
                "parameters": {
                    "type": "object",
                    "properties": {"project_dir": {"type": "string"}},
                    "additionalProperties": false
                },
                "strict": false
            }])
        );
    }

    #[test]
    fn resolve_tools_input_reads_from_stdin() {
        let tools_json = r#"[{"type":"function","name":"get_project_directory","description":"Declares the UE5 project directory resolver. Codex only surfaces the tool; the UE plugin executes it.","parameters":{"type":"object","properties":{"project_dir":{"type":"string"}},"additionalProperties":false},"strict":false}]"#;
        let mut stdin = Cursor::new(tools_json);
        let tools = resolve_tools_input("-".to_string(), &mut stdin).expect("tools input");
        assert_eq!(tools, tools_json);
    }

    #[test]
    fn resolve_ask_input_passthrough_inline() {
        let bundle = r#"{"payloads":[{"foo":"bar"}],"tools":{"tools":[{"type":"function","name":"get_project_directory","description":"Declares the UE5 project directory resolver. Codex only surfaces the tool; the UE plugin executes it.","parameters":{"type":"object","properties":{"project_dir":{"type":"string"}},"additionalProperties":false},"strict":false}]}}"#;
        let ResolvedAskInput {
            ask_input,
            stdin_raw,
        } = resolve_ask_input(bundle.to_string(), &mut Cursor::new(Vec::new())).expect("ask input");
        assert!(stdin_raw.is_none());
        assert_eq!(ask_input.payloads, serde_json::json!([{ "foo": "bar" }]));
        assert_eq!(
            ask_input.tools,
            serde_json::json!({
                "tools": [{
                    "type": "function",
                    "name": "get_project_directory",
                    "description": "Declares the UE5 project directory resolver. Codex only surfaces the tool; the UE plugin executes it.",
                    "parameters": {
                        "type": "object",
                        "properties": {"project_dir": {"type": "string"}},
                        "additionalProperties": false
                    },
                    "strict": false
                }]
            })
        );
    }

    #[test]
    fn rollout_history_subcommand_parses() {
        let cli = MultitoolCli::try_parse_from([
            "blueprintlm-cli",
            "rollout-history",
            "--session-id",
            "abc",
        ])
        .expect("parse");
        let Subcommand::RolloutHistory(RolloutHistoryCommand { session_id }) = cli.subcommand
        else {
            unreachable!()
        };
        assert_eq!(session_id.as_str(), "abc");
    }

    #[test]
    fn read_full_rollout_parses_conversation_id() {
        let conversation_id = ConversationId::new();
        let timestamp = "2024-01-02T03:04:05.000Z".to_string();
        let meta_line = RolloutLine {
            timestamp: timestamp.clone(),
            item: RolloutItem::SessionMeta(SessionMetaLine {
                meta: SessionMeta {
                    id: conversation_id,
                    timestamp: timestamp.clone(),
                    cwd: PathBuf::from("/tmp"),
                    originator: "test-origin".to_string(),
                    cli_version: "0.0.0-test".to_string(),
                    instructions: None,
                    source: SessionSource::Cli,
                    model_provider: Some("provider".to_string()),
                    project_id: Some("project".to_string()),
                },
                git: None,
            }),
        };
        let mut file = NamedTempFile::new().expect("temp file");
        let serialized = serde_json::to_string(&meta_line).expect("serialize rollout line");
        writeln!(file, "{serialized}").expect("write rollout line");
        writeln!(file, "{{invalid json").expect("write invalid line");

        let (history, parsed_id) = read_full_rollout(file.path()).expect("load rollout");
        assert_eq!(parsed_id, conversation_id);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].timestamp, timestamp);
    }

    #[test]
    fn read_full_rollout_errors_on_empty_file() {
        let file = NamedTempFile::new().expect("temp file");
        let result = read_full_rollout(file.path());
        assert!(result.is_err());
    }
}
