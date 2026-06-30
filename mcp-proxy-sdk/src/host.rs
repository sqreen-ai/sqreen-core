//! Host imports provided by `mcp-proxy` to guest policy modules.

#[link(wasm_import_module = "env")]
extern "C" {
    /// Records a human-readable violation string in the host log.
    pub fn log_violation(ptr: *const u8, len: usize);

    /// Reports a block reason to the host before returning `DECISION_BLOCK`.
    pub fn report_block(ptr: *const u8, len: usize);

    /// Reports rewritten `tools/call` params before returning `DECISION_REWRITE`.
    pub fn report_rewrite(ptr: *const u8, len: usize);
}
