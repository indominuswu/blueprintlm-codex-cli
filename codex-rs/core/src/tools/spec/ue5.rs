use std::collections::BTreeMap;
use std::sync::Arc;

use crate::client_common::tools::ResponsesApiTool;
use crate::tools::handlers::CompileBlueprintHandler;
use crate::tools::handlers::ExecuteConsoleCommandHandler;
use crate::tools::handlers::GetBlueprintGraphHandler;
use crate::tools::handlers::GetProjectContextHandler;
use crate::tools::handlers::GetProjectDirectoryHandler;
use crate::tools::handlers::ListAssetsHandler;
use crate::tools::handlers::ListDirectoryHandler;
use crate::tools::handlers::OpenAssetInEditorHandler;
use crate::tools::handlers::QueryLogHandler;
use crate::tools::registry::ToolRegistryBuilder;

use super::JsonSchema;
use super::ToolSpec;

pub(super) fn create_get_project_directory_tool() -> ToolSpec {
    let mut properties = BTreeMap::new();
    properties.insert(
        "project_dir".to_string(),
        JsonSchema::String {
            description: Some(
                "Optional UE5 project directory hint. Actual resolution happens in the UE plugin."
                    .to_string(),
            ),
        },
    );

    ToolSpec::Function(ResponsesApiTool {
        name: "get_project_directory".to_string(),
        description: "Declares the UE5 project directory resolver. Codex only surfaces the tool; the UE plugin executes it."
            .to_string(),
        strict: false,
        parameters: JsonSchema::Object {
            properties,
            required: None,
            additional_properties: Some(false.into()),
        },
    })
}

pub(super) fn create_get_project_context_tool() -> ToolSpec {
    ToolSpec::Function(ResponsesApiTool {
        name: "get_project_context".to_string(),
        description:
            "Returns core information about the current Unreal Engine project (engine version, root paths, modules).".to_string(),
        strict: false,
        parameters: JsonSchema::Object {
            properties: BTreeMap::new(),
            required: None,
            additional_properties: Some(false.into()),
        },
    })
}

pub(super) fn create_list_directory_tool() -> ToolSpec {
    let mut properties = BTreeMap::new();
    properties.insert(
        "path".to_string(),
        JsonSchema::String {
            description: Some("Absolute or project-relative path.".to_string()),
        },
    );
    properties.insert(
        "filter_patterns".to_string(),
        JsonSchema::Array {
            items: Box::new(JsonSchema::String { description: None }),
            description: Some(
                "Optional file wildcard filters (e.g. ['*.ini', '*.cpp']).".to_string(),
            ),
        },
    );

    ToolSpec::Function(ResponsesApiTool {
        name: "list_directory".to_string(),
        description: "Lists files and folders at a given path. Does not modify project state."
            .to_string(),
        strict: false,
        parameters: JsonSchema::Object {
            properties,
            required: Some(vec!["path".to_string()]),
            additional_properties: Some(false.into()),
        },
    })
}

pub(super) fn create_list_assets_tool() -> ToolSpec {
    let mut properties = BTreeMap::new();
    properties.insert(
        "path".to_string(),
        JsonSchema::String {
            description: Some("UE asset path (e.g. /Game/Characters).".to_string()),
        },
    );
    properties.insert(
        "class_filter".to_string(),
        JsonSchema::String {
            description: Some(
                "Asset class filter (Blueprint, SkeletalMesh, Material...).".to_string(),
            ),
        },
    );
    properties.insert(
        "name_pattern".to_string(),
        JsonSchema::String {
            description: Some("Wildcard filter for asset name.".to_string()),
        },
    );

    ToolSpec::Function(ResponsesApiTool {
        name: "list_assets".to_string(),
        description: "Returns Unreal Engine asset metadata for a directory and optional filters."
            .to_string(),
        strict: false,
        parameters: JsonSchema::Object {
            properties,
            required: Some(vec!["path".to_string()]),
            additional_properties: Some(false.into()),
        },
    })
}

pub(super) fn create_open_asset_in_editor_tool() -> ToolSpec {
    let mut properties = BTreeMap::new();
    properties.insert(
        "asset_path".to_string(),
        JsonSchema::String { description: None },
    );

    ToolSpec::Function(ResponsesApiTool {
        name: "open_asset_in_editor".to_string(),
        description: "Opens the specified asset in Unreal Editor (Blueprint, ControlRig, material, map, etc.).".to_string(),
        strict: false,
        parameters: JsonSchema::Object {
            properties,
            required: Some(vec!["asset_path".to_string()]),
            additional_properties: Some(false.into()),
        },
    })
}

pub(super) fn create_get_blueprint_graph_tool() -> ToolSpec {
    let mut properties = BTreeMap::new();
    properties.insert(
        "asset_path".to_string(),
        JsonSchema::String { description: None },
    );

    ToolSpec::Function(ResponsesApiTool {
        name: "get_blueprint_graph".to_string(),
        description: "Retrieves Blueprint graph structure (nodes, pins, connections). Read-only."
            .to_string(),
        strict: false,
        parameters: JsonSchema::Object {
            properties,
            required: Some(vec!["asset_path".to_string()]),
            additional_properties: Some(false.into()),
        },
    })
}

pub(super) fn create_compile_blueprint_tool() -> ToolSpec {
    let mut properties = BTreeMap::new();
    properties.insert(
        "asset_path".to_string(),
        JsonSchema::String { description: None },
    );

    ToolSpec::Function(ResponsesApiTool {
        name: "compile_blueprint".to_string(),
        description: "Compiles a Blueprint asset and returns error/warning details.".to_string(),
        strict: false,
        parameters: JsonSchema::Object {
            properties,
            required: Some(vec!["asset_path".to_string()]),
            additional_properties: Some(false.into()),
        },
    })
}

pub(super) fn create_query_log_tool() -> ToolSpec {
    let mut properties = BTreeMap::new();
    properties.insert(
        "source".to_string(),
        JsonSchema::String {
            description: Some("Log category: editor, pie, build, cook.".to_string()),
        },
    );
    properties.insert(
        "since".to_string(),
        JsonSchema::String {
            description: Some("Optional cursor or timestamp.".to_string()),
        },
    );
    properties.insert(
        "filter".to_string(),
        JsonSchema::String {
            description: Some("Optional substring or regex.".to_string()),
        },
    );

    ToolSpec::Function(ResponsesApiTool {
        name: "query_log".to_string(),
        description: "Returns new lines from Unreal's log files (Editor log, PIE log, Build log)."
            .to_string(),
        strict: false,
        parameters: JsonSchema::Object {
            properties,
            required: Some(vec!["source".to_string()]),
            additional_properties: Some(false.into()),
        },
    })
}

pub(super) fn create_execute_console_command_tool() -> ToolSpec {
    let mut properties = BTreeMap::new();
    properties.insert(
        "command".to_string(),
        JsonSchema::String { description: None },
    );

    ToolSpec::Function(ResponsesApiTool {
        name: "execute_console_command".to_string(),
        description: "Runs an Unreal console command (stat fps, r.ShadowQuality, etc.)."
            .to_string(),
        strict: false,
        parameters: JsonSchema::Object {
            properties,
            required: Some(vec!["command".to_string()]),
            additional_properties: Some(false.into()),
        },
    })
}

pub(super) fn register_ue5_tools(builder: &mut ToolRegistryBuilder) {
    let get_project_directory_handler = Arc::new(GetProjectDirectoryHandler);
    let get_project_context_handler = Arc::new(GetProjectContextHandler);
    let list_directory_handler = Arc::new(ListDirectoryHandler);
    let list_assets_handler = Arc::new(ListAssetsHandler);
    let open_asset_in_editor_handler = Arc::new(OpenAssetInEditorHandler);
    let get_blueprint_graph_handler = Arc::new(GetBlueprintGraphHandler);
    let compile_blueprint_handler = Arc::new(CompileBlueprintHandler);
    let query_log_handler = Arc::new(QueryLogHandler);
    let execute_console_command_handler = Arc::new(ExecuteConsoleCommandHandler);

    builder.push_spec_with_parallel_support(create_get_project_directory_tool(), true);
    builder.register_handler("get_project_directory", get_project_directory_handler);

    builder.push_spec_with_parallel_support(create_get_project_context_tool(), true);
    builder.register_handler("get_project_context", get_project_context_handler);

    builder.push_spec_with_parallel_support(create_list_directory_tool(), true);
    builder.register_handler("list_directory", list_directory_handler);

    builder.push_spec_with_parallel_support(create_list_assets_tool(), true);
    builder.register_handler("list_assets", list_assets_handler);

    builder.push_spec_with_parallel_support(create_open_asset_in_editor_tool(), true);
    builder.register_handler("open_asset_in_editor", open_asset_in_editor_handler);

    builder.push_spec_with_parallel_support(create_get_blueprint_graph_tool(), true);
    builder.register_handler("get_blueprint_graph", get_blueprint_graph_handler);

    builder.push_spec_with_parallel_support(create_compile_blueprint_tool(), true);
    builder.register_handler("compile_blueprint", compile_blueprint_handler);

    builder.push_spec_with_parallel_support(create_query_log_tool(), true);
    builder.register_handler("query_log", query_log_handler);

    builder.push_spec_with_parallel_support(create_execute_console_command_tool(), true);
    builder.register_handler("execute_console_command", execute_console_command_handler);
}
