#![no_std]

use mcp_proxy_sdk::{export_policy_plugin, Decision, EvaluationContext, PolicyPlugin};

struct DemoPlugin;

impl PolicyPlugin for DemoPlugin {
    fn evaluate(ctx: &EvaluationContext) -> Decision {
        if ctx.tool_name() == "execute_bash" {
            Decision::block("execute_bash blocked by demo plugin")
        } else {
            Decision::allow()
        }
    }
}

export_policy_plugin!(DemoPlugin);
