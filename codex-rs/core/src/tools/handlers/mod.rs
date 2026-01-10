pub mod apply_patch;
pub(crate) mod collab;
mod grep_files;
mod list_dir;
mod mcp;
mod mcp_resource;
mod plan;
mod read_file;
mod shell;
mod test_sync;
mod ue5;
mod unified_exec;
mod view_image;

pub use plan::PLAN_TOOL;
use serde::Deserialize;

use crate::function_tool::FunctionCallError;
pub use apply_patch::ApplyPatchHandler;
pub use collab::CollabHandler;
pub use grep_files::GrepFilesHandler;
pub use list_dir::ListDirHandler;
pub use mcp::McpHandler;
pub use mcp_resource::McpResourceHandler;
pub use plan::PlanHandler;
pub use read_file::ReadFileHandler;
pub use shell::ShellCommandHandler;
pub use shell::ShellHandler;
pub use test_sync::TestSyncHandler;
pub use ue5::CompileBlueprintHandler;
pub use ue5::ExecuteConsoleCommandHandler;
pub use ue5::GetBlueprintGraphHandler;
pub use ue5::GetProjectContextHandler;
pub use ue5::GetProjectDirectoryHandler;
pub use ue5::ListAssetsHandler;
pub use ue5::ListDirectoryHandler;
pub use ue5::OpenAssetInEditorHandler;
pub use ue5::QueryLogHandler;
pub use unified_exec::UnifiedExecHandler;
pub use view_image::ViewImageHandler;

fn parse_arguments<T>(arguments: &str) -> Result<T, FunctionCallError>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_str(arguments).map_err(|err| {
        FunctionCallError::RespondToModel(format!("failed to parse function arguments: {err}"))
    })
}
