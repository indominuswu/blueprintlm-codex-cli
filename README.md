cargo install --path codex-rs\blueprintlm-cli --locked --force

## blueprintlm-cli ask usage

`blueprintlm-cli ask` now reads both the prompt payload and tool specs from a single JSON object passed as an argument or via stdin (`-`). Example:

```json
{"payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]},"tools":[{"type":"function","name":"get_project_directory","description":"Declares the UE5 project directory resolver. Codex only surfaces the tool; the UE plugin executes it.","parameters":{"type":"object","properties":{"project_dir":{"type":"string"}},"additionalProperties":false},"strict":false}]}
```

Usage:

```shell
echo '<the-json-above>' | blueprintlm-cli ask --session-id SESSION_ID -
```
