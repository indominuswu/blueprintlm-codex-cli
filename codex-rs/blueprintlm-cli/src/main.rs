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
use codex_core::blueprintlm_default_tool_specs;
use codex_core::config::Config;
use codex_core::config::ConfigOverrides;
use codex_core::features::Feature;
use codex_core::openai_models::models_manager::ModelsManager;
use codex_core::rollout::find_conversation_path_by_id_str;
use codex_core::rollout::list::Cursor as SessionsCursor;
use codex_core::rollout::list::get_conversations;
use codex_core::rollout::recorder::RolloutRecorderParams;
use codex_core::terminal;
use codex_otel::otel_event_manager::OtelEventManager;
use codex_protocol::ConversationId;
use codex_protocol::models::ResponseInputItem;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::InitialHistory;
use codex_protocol::protocol::RolloutItem;
use codex_protocol::protocol::RolloutLine;
use codex_protocol::protocol::SessionConfiguredEvent;
use codex_protocol::protocol::SessionSource;
use futures_util::StreamExt;
use serde::Serialize;
use std::env;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use time::OffsetDateTime;
use time::macros::format_description;

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

    /// List recorded sessions as JSON.
    Sessions(SessionsCommand),

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
    /// JSON payload representing one or more ResponseInputItem entries.
    #[arg(long = "payload", value_name = "PAYLOAD_JSON")]
    payload: Option<String>,

    /// JSON payload representing one or more ResponseInputItem entries (positional).
    #[arg(value_name = "PAYLOAD_JSON", required_unless_present = "payload")]
    payload_arg: Option<String>,

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
            payload,
            payload_arg,
            session_id,
            debug_save_prompts,
            add_dir,
            cwd,
            debug_stream_error,
        }) => {
            let payload = payload.or(payload_arg).ok_or_else(|| {
                anyhow::anyhow!("payload is required either via --payload or positional argument")
            })?;
            run_ask(
                payload,
                session_id,
                debug_save_prompts,
                add_dir,
                cwd,
                debug_stream_error,
                root_config_overrides,
            )
            .await?;
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
            let config =
                Config::load_with_cli_overrides(cli_overrides, ConfigOverrides::default()).await?;
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
struct StartSessionResponse {
    success: bool,
    session: Option<SessionConfiguredEvent>,
    error: Option<String>,
}

fn emit_error(error: String) -> anyhow::Result<()> {
    let response = AskResponse {
        success: false,
        error: Some(error),
        response: Vec::new(),
    };
    let json = serde_json::to_string_pretty(&response)?;
    println!("{json}");
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

async fn run_ask(
    payload: String,
    session_id: String,
    debug_save_prompts: bool,
    add_dir: Vec<PathBuf>,
    cwd: Option<PathBuf>,
    debug_stream_error: Option<String>,
    root_config_overrides: CliConfigOverrides,
) -> anyhow::Result<()> {
    let cli_overrides = root_config_overrides
        .parse_overrides()
        .map_err(anyhow::Error::msg)?;
    let config_overrides = ConfigOverrides {
        cwd: cwd.clone(),
        additional_writable_roots: add_dir.clone(),
        ..Default::default()
    };
    let config = Config::load_with_cli_overrides(cli_overrides, config_overrides).await?;

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
    let model_family = models_manager.construct_model_family(&config.model, &config);
    let model_family_for_client = model_family.clone();
    let conversation_id = match ConversationId::from_string(&session_id) {
        Ok(id) => id,
        Err(err) => {
            emit_error(err.to_string())?;
            return Ok(());
        }
    };
    let rollout_path = match find_conversation_path_by_id_str(&config.codex_home, &session_id).await
    {
        Ok(Some(path)) => path,
        Ok(None) => {
            emit_error(format!("Session with id {session_id} not found"))?;
            return Ok(());
        }
        Err(err) => {
            emit_error(format!("Failed to locate session: {err}"))?;
            return Ok(());
        }
    };
    let initial_history = match RolloutRecorder::get_rollout_history(&rollout_path).await {
        Ok(history) => history,
        Err(err) => {
            emit_error(format!("Failed to load session history: {err}"))?;
            return Ok(());
        }
    };
    let (resumed_id, mut history_items) = match response_items_from_history(&initial_history) {
        Ok((id, items)) => (id, items),
        Err(err) => {
            emit_error(err.to_string())?;
            return Ok(());
        }
    };
    if resumed_id != conversation_id {
        emit_error("Session id mismatch between provided id and rollout history".to_string())?;
        return Ok(());
    }
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
    let otel_event_manager = OtelEventManager::new(
        conversation_id,
        config.model.as_str(),
        model_family.slug.as_str(),
        auth.as_ref().and_then(CodexAuth::get_account_id),
        auth.as_ref().and_then(CodexAuth::get_account_email),
        auth.as_ref().map(|a| a.mode),
        config.otel.log_user_prompt,
        terminal::user_agent(),
    );
    let provider = config.model_provider.clone();
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

    let response_inputs: Vec<ResponseInputItem> = match serde_json::from_str::<Vec<ResponseInputItem>>(
        &payload,
    ) {
        Ok(items) => items,
        Err(err_vec) => match serde_json::from_str::<ResponseInputItem>(&payload) {
            Ok(item) => vec![item],
            Err(err_single) => {
                emit_error(format!(
                    "Invalid payload JSON (array parse error: {err_vec}; single parse error: {err_single})"
                ))?;
                return Ok(());
            }
        },
    };
    let mut new_items: Vec<ResponseItem> = Vec::new();
    let mut prompt = Prompt::default();
    prompt.input.append(&mut history_items);
    for item in response_inputs {
        let response_item = ResponseItem::from(item);
        prompt.input.push(response_item.clone());
        new_items.push(response_item);
    }
    if let Some(recorder) = rollout_recorder.as_ref() {
        let to_record: Vec<RolloutItem> = new_items
            .iter()
            .cloned()
            .map(RolloutItem::ResponseItem)
            .collect();
        if let Err(err) = recorder.append_items(&to_record).await {
            eprintln!("Failed to record request items: {err}");
        }
    }

    let tools_config = ToolsConfig::new(&ToolsConfigParams {
        model_family: &model_family,
        features: &config.features,
    });
    prompt.set_tools(blueprintlm_default_tool_specs(&tools_config));
    prompt.set_parallel_tool_calls(
        model_family.supports_parallel_tool_calls
            && config.features.enabled(Feature::ParallelToolCalls),
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
                        }
                    }
                    Err(err) => {
                        eprintln!("Failed to serialize prompt debug payload: {err}");
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
        unsafe {
            env::set_var("BLUEPRINTLM_DEBUG_STREAM_ERROR", kind);
        }
    }

    let mut stream = match client.stream(&prompt).await {
        Ok(stream) => stream,
        Err(err) => {
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
            let json = serde_json::to_string_pretty(&response)?;
            println!("{json}");
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
    let mut stream_error = None;
    let mut collected_items: Vec<RolloutLine> = Vec::new();
    while let Some(event) = stream.next().await {
        match event {
            Ok(ev) => match ev {
                ResponseEvent::OutputTextDelta(_) => {}
                ResponseEvent::OutputItemAdded(_) => {}
                ResponseEvent::OutputItemDone(item) => {
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
                ResponseEvent::Completed { .. } => break,
                _ => {}
            },
            Err(err) => {
                stream_error = Some(err.to_string());
                break;
            }
        }
    }

    let response = AskResponse {
        success: stream_error.is_none(),
        error: stream_error,
        response: collected_items,
    };
    if let Some(recorder) = rollout_recorder.as_ref() {
        let to_record: Vec<RolloutItem> = response
            .response
            .iter()
            .cloned()
            .map(|line| line.item)
            .collect();
        if let Err(err) = recorder.append_items(&to_record).await {
            eprintln!("Failed to record response items: {err}");
        }
    }
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
    let mut config = Config::load_with_cli_overrides(cli_overrides, config_overrides).await?;
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
    let config = Config::load_with_cli_overrides(cli_overrides, ConfigOverrides::default()).await?;

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
    let config = Config::load_with_cli_overrides(cli_overrides, ConfigOverrides::default()).await?;

    let auth_manager = AuthManager::shared(
        config.codex_home.clone(),
        true,
        config.cli_auth_credentials_store_mode,
    );
    let models_manager = ModelsManager::new(auth_manager);
    let presets = models_manager.available_models.read().await.clone();
    let json = serde_json::to_string_pretty(&presets)?;
    println!("{json}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn ask_subcommand_parses_prompt() {
        let cli = MultitoolCli::try_parse_from([
            "blueprintlm-cli",
            "ask",
            "--session-id",
            "abc",
            "-C",
            "/tmp",
            "--add-dir",
            "/tmp/foo",
            r#"{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}"#,
        ])
        .expect("parse");
        let Subcommand::Ask(AskCommand {
            payload,
            payload_arg,
            session_id,
            add_dir,
            cwd,
            debug_save_prompts,
            debug_stream_error,
        }) = cli.subcommand
        else {
            unreachable!()
        };
        assert!(payload.is_none());
        assert_eq!(
            payload_arg,
            Some(
                r#"{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}"#
                    .to_string()
            )
        );
        assert_eq!(session_id.as_str(), "abc");
        assert_eq!(add_dir, vec![std::path::PathBuf::from("/tmp/foo")]);
        assert_eq!(cwd.as_deref(), Some(std::path::Path::new("/tmp")));
        assert!(!debug_save_prompts);
        assert!(debug_stream_error.is_none());
    }

    #[test]
    fn ask_subcommand_parses_payload_flag() {
        let cli = MultitoolCli::try_parse_from([
            "blueprintlm-cli",
            "ask",
            "--payload",
            r#"{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}"#,
            "--session-id",
            "abc",
        ])
        .expect("parse");
        let Subcommand::Ask(AskCommand {
            payload,
            payload_arg,
            session_id,
            add_dir,
            cwd,
            debug_save_prompts,
            debug_stream_error,
        }) = cli.subcommand
        else {
            unreachable!()
        };
        assert_eq!(
            payload,
            Some(
                r#"{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}"#
                    .to_string()
            )
        );
        assert!(payload_arg.is_none());
        assert_eq!(session_id.as_str(), "abc");
        assert!(add_dir.is_empty());
        assert!(cwd.is_none());
        assert!(!debug_save_prompts);
        assert!(debug_stream_error.is_none());
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
}
