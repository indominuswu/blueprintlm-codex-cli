# blueprintlm-codex debug flags

Quick reference for debug-only CLI switches that help exercise error paths and capture prompt payloads. These flags are hidden from `--help` output and are intended for testing only.

## ask

- `--debug-stream-error <kind>`  
  Injects a synthetic streaming error instead of calling the API. Supported kinds: `context_window`, `quota_exceeded`, `usage_not_included`, `stream_retry`, `unexpected_status`, `retry_limit`, `fatal` (unknown values behave like `fatal`). Output is still JSON with `success`/`error`.

- `--debug-save-prompts`  
  Saves per-turn prompt payloads to `$BLUEPRINTLM_HOME/debug/prompts` as prettified JSON. Useful for inspecting what was sent to the model.

Usage example:

```
blueprintlm-codex ask "hello" --session-id <SESSION_UUID> --debug-stream-error quota_exceeded
```

## start-session

- `--debug-start-session-error io`  
  Skips session creation and immediately emits a JSON error response: `{"success": false, "error": "simulated io error"}`. Use this to verify callers correctly handle start-session failures.

Usage example:

```
blueprintlm-codex start-session --debug-start-session-error io
```
