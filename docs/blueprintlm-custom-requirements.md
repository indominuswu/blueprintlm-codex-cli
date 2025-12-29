# BlueprintLM Custom Requirements

This file captures BlueprintLM-only behavior that needs to survive merges from upstream `openai/codex`. Use it as a checklist whenever rebasing or cherry-picking from upstream.

## CLI surface (`codex-rs/blueprintlm-cli`)
- Binary name is `blueprintlm-codex` (crate at `codex-rs/blueprintlm-cli`); upstream `codex-rs/cli` should remain untouched.
- All subcommands print JSON to stdout with a `success` flag and optional `error`; stderr is for warnings only.
- `ask` is resume-only: it requires `--session-id` and consumes a single JSON object `{ "payloads": [...], "tools": ... }` via arg or `-` (stdin). `payloads` must parse into `ResponseInputItem` entries; `tools` must be function tools only (array or `{ "tools": [...] }`) or the command errors.
- `ask` resolves sessions by id across both `sessions/` and `subagent_sessions/`.
- Tools passed to `ask` are the entire prompt tool set (`blueprintlm_default_tool_specs_from_str`); there is no config-side lookup. Caller-provided tools must keep working.
- `ask` appends rollout items to the existing session, logs to `$BLUEPRINTLM_HOME/log/YYYY/MM/DD/ask-*.log`, and respects `--add-dir`/`--cd` for workspace rooting.
- Output schema is `{"success": bool, "error": Option<String>, "response": Vec<RolloutLine>}`; do not break this contract.
- `ask --stream` emits NDJSON events before the final response. Each line includes `success`, `error`, and a `type` such as `created`, `output_text_delta`, `reasoning_summary_delta`, `reasoning_content_delta`, `reasoning_summary_part_added`, `output_item_added`, `output_item_done`, `rate_limits`, `completed`; item events include the full `ResponseItem`, and the final line is the normal AskResponse in compact JSON.
- `validate-tools --tools <TOOLS_JSON>` validates tools input (use `-` for stdin) and returns `{"success": bool, "error": Option<String>, "tool_count": usize}`.
- Debug hooks: `--debug-stream-error <kind>` (with `BLUEPRINTLM_DEBUG_STREAM_ERROR`) and `--debug-save-prompts` which writes prettified prompts to `$BLUEPRINTLM_HOME/debug/prompts` via `CODEX_SAVE_PROMPTS_DIR`.

## Session lifecycle
- `start-session` requires both `--project-id` and `--project-doc` (AGENTS.md content); `-` reads stdin and empty docs are rejected.
- On `start-session`, `config.user_instructions` is cleared and `project_doc_override` is set to the provided text so the session always uses caller-supplied instructions.
- `--debug-start-session-error io` returns `{"success": false, "error": "simulated io error"}` without hitting the backend; keep this shape for integration tests.
- `start-subagent-session` mirrors `start-session`, adds `--subagent-label` (defaults to `external`), and uses `SessionSource::SubAgent`.
- `sessions`, `rollout-history`, `subagent-sessions`, `subagent-rollout-history`, `models`, and `get-rate-limits` stay JSON-only commands.

## Models
- Built-in presets live in `codex-rs/core/src/openai_models/model_presets.rs`; `gpt-5.1-codex-max` is the default. Preserve the BlueprintLM codex family (`gpt-5.1-codex[-mini]`, `gpt-5-codex[-mini]`, `gpt-5.1`, `gpt-5`) and their upgrade mappings and reasoning effort options.
- `blueprintlm-codex models` should continue printing the presets JSON (not a table).

## Tooling expectations
- Default Codex home is `$BLUEPRINTLM_HOME` (defaults to `~/.blueprintlm-codex`/`%USERPROFILE%\\.blueprintlm-codex`); logs, prompts, and rollouts live underneath (`sessions/` for main sessions, `subagent_sessions/` for subagents).
- UE5 tool set must remain available where tools are auto-built: `get_project_directory`, `get_project_context`, `list_directory`, `list_assets`, `open_asset_in_editor`, `get_blueprint_graph`, `compile_blueprint`, `query_log`, `execute_console_command`, plus model-specific base tools (`shell`/`shell_command`/`local_shell`, `apply_patch`, `view_image`, MCP helpers).
- For CLI `ask`, only caller-supplied function tools are allowed; non-function or empty tool lists must stay an error.

## Telemetry/headers
- Default `originator`/User-Agent prefix stays `codex_cli_rs`; `CODEX_INTERNAL_ORIGINATOR_OVERRIDE` exists for tests but the default value should not change.
