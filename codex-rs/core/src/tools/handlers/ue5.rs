use crate::function_tool::FunctionCallError;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolOutput;
use crate::tools::context::ToolPayload;
use crate::tools::registry::ToolHandler;
use crate::tools::registry::ToolKind;
use async_trait::async_trait;

fn handle_function_only(
    invocation: ToolInvocation,
    tool_name: &str,
) -> Result<ToolOutput, FunctionCallError> {
    if matches!(invocation.payload, ToolPayload::Function { .. }) {
        return Ok(ToolOutput::Function {
            content: String::new(),
            content_items: None,
            success: Some(true),
        });
    }
    Err(FunctionCallError::Fatal(format!(
        "{tool_name} requires function payload"
    )))
}

/// Declares a UE5-side project directory resolver. The UE plugin performs the actual lookup.
pub struct GetProjectDirectoryHandler;

/// Returns core information about the current Unreal Engine project.
pub struct GetProjectContextHandler;

/// Lists files and folders at a given path.
pub struct ListDirectoryHandler;

/// Returns Unreal Engine asset metadata for a directory and optional filters.
pub struct ListAssetsHandler;

/// Opens a specified asset in the Unreal Editor.
pub struct OpenAssetInEditorHandler;

/// Retrieves Blueprint graph structure (nodes, pins, connections).
pub struct GetBlueprintGraphHandler;

/// Compiles a Blueprint asset and returns error/warning details.
pub struct CompileBlueprintHandler;

/// Returns new lines from Unreal's log files.
pub struct QueryLogHandler;

/// Runs an Unreal console command.
pub struct ExecuteConsoleCommandHandler;

#[async_trait]
impl ToolHandler for GetProjectDirectoryHandler {
    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<ToolOutput, FunctionCallError> {
        handle_function_only(invocation, "get_project_directory")
    }
}

#[async_trait]
impl ToolHandler for GetProjectContextHandler {
    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<ToolOutput, FunctionCallError> {
        handle_function_only(invocation, "get_project_context")
    }
}

#[async_trait]
impl ToolHandler for ListDirectoryHandler {
    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<ToolOutput, FunctionCallError> {
        handle_function_only(invocation, "list_directory")
    }
}

#[async_trait]
impl ToolHandler for ListAssetsHandler {
    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<ToolOutput, FunctionCallError> {
        handle_function_only(invocation, "list_assets")
    }
}

#[async_trait]
impl ToolHandler for OpenAssetInEditorHandler {
    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<ToolOutput, FunctionCallError> {
        handle_function_only(invocation, "open_asset_in_editor")
    }
}

#[async_trait]
impl ToolHandler for GetBlueprintGraphHandler {
    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<ToolOutput, FunctionCallError> {
        handle_function_only(invocation, "get_blueprint_graph")
    }
}

#[async_trait]
impl ToolHandler for CompileBlueprintHandler {
    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<ToolOutput, FunctionCallError> {
        handle_function_only(invocation, "compile_blueprint")
    }
}

#[async_trait]
impl ToolHandler for QueryLogHandler {
    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<ToolOutput, FunctionCallError> {
        handle_function_only(invocation, "query_log")
    }
}

#[async_trait]
impl ToolHandler for ExecuteConsoleCommandHandler {
    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<ToolOutput, FunctionCallError> {
        handle_function_only(invocation, "execute_console_command")
    }
}
