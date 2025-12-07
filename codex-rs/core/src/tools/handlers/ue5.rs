use crate::function_tool::FunctionCallError;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolOutput;
use crate::tools::context::ToolPayload;
use crate::tools::registry::ToolHandler;
use crate::tools::registry::ToolKind;
use async_trait::async_trait;

/// Declares a UE5-side project directory resolver. The UE plugin performs the actual lookup.
pub struct Ue5ProjectDirHandler;

#[async_trait]
impl ToolHandler for Ue5ProjectDirHandler {
    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<ToolOutput, FunctionCallError> {
        if matches!(invocation.payload, ToolPayload::Function { .. }) {
            return Ok(ToolOutput::Function {
                content: String::new(),
                content_items: None,
                success: Some(true),
            });
        }
        Err(FunctionCallError::Fatal(
            "ue5_project_dir requires function payload".to_string(),
        ))
    }
}
