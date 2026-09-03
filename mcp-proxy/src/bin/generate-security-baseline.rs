//! Emit checked-in security baseline artifacts from the typed SoT.
//!
//! Usage:
//!   cargo run --bin generate-security-baseline
//!   cargo run --bin generate-security-baseline -- --apply
//!   cargo run --bin generate-security-baseline -- --check

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let apply = args.iter().any(|a| a == "--apply");
    let check = args.iter().any(|a| a == "--check");

    if check {
        mcp_proxy::security_baseline::artifacts::assert_generated_in_sync()?;
        println!("security baseline artifacts in sync");
        return Ok(());
    }

    let written = mcp_proxy::security_baseline::write_generated_tree(apply)?;
    for path in &written {
        println!("wrote {}", path.display());
    }
    if apply {
        println!("applied live copies (policy YAML, dashboard, hooks, installer)");
    } else {
        println!("hint: pass --apply to sync live repo copies");
    }
    Ok(())
}
