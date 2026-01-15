# BlueprintLM Custom Requirements

This document captures BlueprintLM-only behavior that must survive merges
from upstream `openai/codex`. This is the single source of truth.

## Scope
- Focus on BlueprintLM-specific behavior, APIs, and UX contracts.
- Treat upstream `codex-rs/cli` as off-limits; BlueprintLM CLI lives in
  `codex-rs/blueprintlm-cli`.

## CLI surface (`blueprintlm-codex`)
- Binary name is `blueprintlm-codex` (crate: `codex-rs/blueprintlm-cli`).
- All subcommands emit JSON to stdout with `success` + optional `error`;
  stderr is warnings only.
- `ask` is resume-only and requires `--session-id`.
  - Input is a single JSON object via arg or `-` (stdin):
    `{ "payloads": [...], "tools": ... }`.
  - `payloads` parse into `ResponseInputItem` entries.
  - `tools` must be function tools only (array or `{ "tools": [...] }`).
  - Caller-provided tools are the full prompt tool set via
    `blueprintlm_default_tool_specs_from_str`; no config-side lookup.
  - Session lookup must resolve ids across both `sessions/` and
    `subagent_sessions/`.
  - `ask` appends rollout items to the existing session, logs to
    `$BLUEPRINTLM_HOME/log/YYYY/MM/DD/ask-*.log`, and respects `--add-dir`
    and `--cd` for workspace rooting.
  - Output schema: `{"success": bool, "error": Option<String>, "response": Vec<RolloutLine>}`.
- `ask --stream` emits NDJSON events before the final response.
  - Each line includes `success`, `error`, and a `type` such as `created`,
    `output_text_delta`, `reasoning_summary_delta`, `reasoning_content_delta`,
    `reasoning_summary_part_added`, `output_item_added`, `output_item_done`,
    `rate_limits`, `completed`.
  - Item events include the full `ResponseItem`.
  - Final line is the normal AskResponse in compact JSON.
- `validate-tools --tools <TOOLS_JSON>` returns
  `{"success": bool, "error": Option<String>, "tool_count": usize}`.
- JSON-only commands must stay JSON-only: `sessions`, `rollout-history`,
  `subagent-sessions`, `subagent-rollout-history`, `models`, `get-rate-limits`.
- `rollout-add-subagent-session` records a subagent session event for a parent
  rollout. It writes `SubagentSessionStarted` with `--session-id`,
  `--session-kind` (main or subagent), `--subagent-session-id`,
  `--subagent-name`, and optional `--call-id`, and returns JSON with `success`,
  `error`, `session_id`, `rollout_path`, `subagent_session_id`,
  `subagent_name`, and `call_id`.

## Session lifecycle
- `start-session` requires `--project-id` and `--project-doc` (AGENTS.md).
  `-` reads stdin; empty docs are rejected.
- On `start-session`, `config.user_instructions` is cleared and
  `project_doc_override` is set to caller-supplied instructions.
- `--debug-start-session-error io` returns
  `{"success": false, "error": "simulated io error"}` without hitting the backend.
- `start-subagent-session` mirrors `start-session`, adds `--subagent-label`
  (default `external`), and uses `SessionSource::SubAgent`.
- Session resolution must search both `sessions/` and `subagent_sessions/`.

## Models
- Built-in presets live in `codex-rs/core/src/openai_models/model_presets.rs`.
- Default model is `gpt-5.1-codex-max`.
- Preserve BlueprintLM codex family:
  `gpt-5.1-codex[-mini]`, `gpt-5-codex[-mini]`, `gpt-5.1`, `gpt-5`,
  including upgrade mappings and reasoning effort options.
- `blueprintlm-codex models` prints presets JSON (not a table).

## Tooling expectations
- Default Codex home is `$BLUEPRINTLM_HOME` (defaults to
  `~/.blueprintlm-codex` or `%USERPROFILE%\\.blueprintlm-codex`).
  Logs, prompts, and rollouts live underneath (`sessions/` for main sessions,
  `subagent_sessions/` for subagents).
- UE5 tool set must remain available where tools are auto-built:
  `get_project_directory`, `get_project_context`, `list_directory`,
  `list_assets`, `open_asset_in_editor`, `get_blueprint_graph`,
  `compile_blueprint`, `query_log`, `execute_console_command`,
  plus model-specific base tools (`shell`/`shell_command`/`local_shell`,
  `apply_patch`, `view_image`, MCP helpers).
- For CLI `ask`, only caller-supplied function tools are allowed;
  non-function or empty tool lists must remain an error.

## Diagnostics and telemetry
- Debug hooks:
  - `--debug-stream-error <kind>` (with `BLUEPRINTLM_DEBUG_STREAM_ERROR`).
  - `--debug-save-prompts` writes prettified prompts to
    `$BLUEPRINTLM_HOME/debug/prompts` via `CODEX_SAVE_PROMPTS_DIR`.
- Default `originator`/User-Agent prefix stays `codex_cli_rs`;
  `CODEX_INTERNAL_ORIGINATOR_OVERRIDE` exists for tests, but the default
  value should not change.

# Codexをマージしたときの確認事項
- rolloutに書き込むコマンドでは、書き込まれたJSONの形式が変更されていないか確認
- project docにCodex由来の文字列が含まれないかを確認