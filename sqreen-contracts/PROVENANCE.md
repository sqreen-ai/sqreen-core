# Sqreen Contracts — provenance

This package defines the public wire contracts shared by `sqreen-core` and
`sqreen-enterprise`.

## Licensing relationship

The parent monorepo ships a root **MIT** license and the Core crates are
**MIT OR Apache-2.0**.

`sqreen-contracts` is intended to remain a **public interoperability surface**.

Until counsel confirms a dedicated SPDX choice for this package alone:

- Treat it as covered by the repository's existing public MIT licensing intent.
- Do **not** invent a new license or relicense previously published material.
- See `COUNSEL_TODO` below before any public GitHub publication of a
  standalone contracts repo.

## COUNSEL_TODO

Confirm whether `sqreen-contracts` should:

1. Carry an explicit MIT `LICENSE` identical to the repository root, or
2. Use MIT OR Apache-2.0 to match `mcp-proxy`, or
3. Require a separate counsel-approved SPDX identifier.

Do not silently relicense.

## Contents

Machine-readable schema: `contracts.schema.json`.
