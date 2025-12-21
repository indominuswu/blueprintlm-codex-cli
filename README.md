cargo install --path codex-rs\blueprintlm-cli --locked --force

## blueprintlm-cli ask usage

`blueprintlm-cli ask` now reads both the prompt payloads and tool specs from a single JSON object passed as an argument or via stdin (`-`). Example:

```json
{"payloads":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}],"tools":[{"type":"function","name":"get_project_directory","description":"Declares the UE5 project directory resolver. Codex only surfaces the tool; the UE plugin executes it.","parameters":{"type":"object","properties":{"project_dir":{"type":"string"}},"additionalProperties":false},"strict":false}]}
```

Usage:

```shell
echo '<the-json-above>' | blueprintlm-cli ask --session-id SESSION_ID -
```

## Streaming output

Use `--stream` to emit output text deltas as NDJSON before the final AskResponse:

```shell
echo '<the-json-above>' | blueprintlm-cli ask --stream --session-id SESSION_ID -
```

Each line includes `success`, `error`, and a `type` such as `created`, `output_text_delta`, `reasoning_summary_delta`, `reasoning_content_delta`, `reasoning_summary_part_added`, `output_item_added`, `output_item_done`, `rate_limits`, `completed`. Item events include the full `ResponseItem`; the final line is the usual AskResponse JSON.
