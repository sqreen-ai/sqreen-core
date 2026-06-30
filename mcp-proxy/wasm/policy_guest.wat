;; Example MCP policy extension module for mcp-proxy.
;;
;; Compile with: wat2wasm policy_guest.wat -o policy_guest.wasm
;; Run proxy with: MCP_WASM_POLICY=./policy_guest.wasm mcp-proxy -- run ...
;;
;; Guest ABI:
;;   exports: memory, input_ptr() -> i32, evaluate_policy(input_len: i32) -> i32
;;   imports: env.log_violation(ptr, len), env.report_block(ptr, len), env.report_rewrite(ptr, len)
;;   return codes: 0 = Allow, 1 = Block, 2 = Rewrite

(module
  (import "env" "log_violation" (func $log_violation (param i32 i32)))
  (import "env" "report_block" (func $report_block (param i32 i32)))
  (import "env" "report_rewrite" (func $report_rewrite (param i32 i32)))

  (memory (export "memory") 2)

  (data (i32.const 1024) "blocked by wasm policy extension")

  (func (export "input_ptr") (result i32)
    i32.const 0)

  (func (export "evaluate_policy") (param $len i32) (result i32)
    ;; Example policy: always block and log (replace with real logic).
    i32.const 1024
    i32.const 32
    call $report_block
    i32.const 1024
    i32.const 32
    call $log_violation
    i32.const 1)
)
