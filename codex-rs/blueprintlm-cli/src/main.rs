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
use codex_core::ModelClient;
use codex_core::Prompt;
use codex_core::ResponseEvent;
use codex_core::config::Config;
use codex_core::config::ConfigOverrides;
use codex_core::openai_models::models_manager::ModelsManager;
use codex_core::rollout::list::Cursor as SessionsCursor;
use codex_core::rollout::list::get_conversations;
use codex_core::terminal;
use codex_otel::otel_event_manager::OtelEventManager;
use codex_protocol::ConversationId;
use codex_protocol::models::ContentItem;
use codex_protocol::models::ResponseInputItem;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::SessionSource;
use codex_protocol::user_input::UserInput;
use futures_util::StreamExt;
use serde::Serialize;
use std::env;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

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
    /// Prompt to send. Use `-` to read from stdin.
    #[arg(value_name = "PROMPT")]
    prompt: String,

    /// Resume an existing session by id instead of starting a new one.
    #[arg(long = "session-id", value_name = "SESSION_ID")]
    session_id: Option<String>,

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
            prompt,
            session_id,
            debug_save_prompts,
            add_dir,
            cwd,
            debug_stream_error,
        }) => {
            run_ask(
                prompt,
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
            )
            .await?;
            let json = serde_json::to_string_pretty(&conversations)?;
            println!("{json}");
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
    output: Option<String>,
    error: Option<String>,
}

async fn run_ask(
    prompt: String,
    session_id: Option<String>,
    debug_save_prompts: bool,
    add_dir: Vec<PathBuf>,
    cwd: Option<PathBuf>,
    debug_stream_error: Option<String>,
    root_config_overrides: CliConfigOverrides,
) -> anyhow::Result<()> {
    let mut stdin_buf = String::new();
    let prompt_text = if prompt == "-" {
        std::io::stdin().read_to_string(&mut stdin_buf)?;
        stdin_buf
    } else {
        prompt
    };

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

    if session_id.is_some() {
        eprintln!("--session-id is not supported in simplified ask mode; starting a new session.");
    }

    let auth_manager = AuthManager::shared(
        config.codex_home.clone(),
        true,
        config.cli_auth_credentials_store_mode,
    );
    let models_manager = ModelsManager::new(auth_manager.clone());
    let model_family = models_manager.construct_model_family(&config.model, &config);
    let conversation_id = ConversationId::new();
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
        model_family,
        otel_event_manager,
        provider,
        config.model_reasoning_effort,
        config.model_reasoning_summary,
        conversation_id,
        SessionSource::Cli,
    );

    let response_input: ResponseInputItem = ResponseInputItem::from(vec![UserInput::Text {
        text: prompt_text.clone(),
    }]);
    let response_item: ResponseItem = response_input.into();
    let mut prompt = Prompt::default();
    prompt.input = vec![response_item];

    let previous_debug_stream_error = if debug_stream_error.is_some() {
        env::var("CODEX_DEBUG_STREAM_ERROR").ok()
    } else {
        None
    };
    if let Some(kind) = debug_stream_error.clone() {
        unsafe {
            env::set_var("CODEX_DEBUG_STREAM_ERROR", kind);
        }
    }

    let mut stream = match client.stream(&prompt).await {
        Ok(stream) => stream,
        Err(err) => {
            if debug_stream_error.is_some() {
                if let Some(prev) = previous_debug_stream_error {
                    unsafe {
                        env::set_var("CODEX_DEBUG_STREAM_ERROR", prev);
                    }
                } else {
                    unsafe {
                        env::remove_var("CODEX_DEBUG_STREAM_ERROR");
                    }
                }
            }
            let response = AskResponse {
                success: false,
                output: None,
                error: Some(err.to_string()),
            };
            let json = serde_json::to_string_pretty(&response)?;
            println!("{json}");
            return Ok(());
        }
    };
    if debug_stream_error.is_some() {
        if let Some(prev) = previous_debug_stream_error {
            unsafe {
                env::set_var("CODEX_DEBUG_STREAM_ERROR", prev);
            }
        } else {
            unsafe {
                env::remove_var("CODEX_DEBUG_STREAM_ERROR");
            }
        }
    }
    let mut final_message = String::new();
    let mut stream_error = None;
    while let Some(event) = stream.next().await {
        match event {
            Ok(ev) => match ev {
                ResponseEvent::OutputTextDelta(delta) => final_message.push_str(&delta),
                ResponseEvent::OutputItemDone(item) | ResponseEvent::OutputItemAdded(item) => {
                    if let ResponseItem::Message { role, content, .. } = item
                        && role == "assistant"
                    {
                        for ci in content {
                            if let ContentItem::OutputText { text } = ci {
                                final_message.push_str(&text);
                            }
                        }
                    }
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
        output: if final_message.is_empty() {
            None
        } else {
            Some(final_message)
        },
        error: stream_error,
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
            "hello",
        ])
        .expect("parse");
        let Subcommand::Ask(AskCommand {
            prompt,
            session_id,
            add_dir,
            cwd,
            debug_save_prompts,
            debug_stream_error,
        }) = cli.subcommand
        else {
            unreachable!()
        };
        assert_eq!(prompt, "hello");
        assert_eq!(session_id.as_deref(), Some("abc"));
        assert_eq!(add_dir, vec![std::path::PathBuf::from("/tmp/foo")]);
        assert_eq!(cwd.as_deref(), Some(std::path::Path::new("/tmp")));
        assert!(!debug_save_prompts);
        assert!(debug_stream_error.is_none());
    }

    #[test]
    fn models_subcommand_parses() {
        let cli = MultitoolCli::try_parse_from(["blueprintlm-cli", "models"]).expect("parse");
        assert!(matches!(cli.subcommand, Subcommand::Models));
    }
}
