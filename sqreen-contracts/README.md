# Sqreen Contracts

Minimal public wire contracts between `sqreen-core` and `sqreen-enterprise`.

Design rules:

1. Contracts define wire shape and trust boundaries, not private algorithms.
2. `sqreen-core` owns local enforcement, validation, action binding, and failure behavior.
3. `sqreen-enterprise` may publish, route, store, and coordinate contract objects, but must
   not redefine their security meaning.
4. Do not put scoring weights, detector inventories, SOC analytics fields, or raw argument
   payloads into this public schema.
5. Additive fields preferred; breaking changes need a new schema version.

Public contract families:

- `PolicyDocument` / `PolicyEnvelope`
- `ThreatIntelBundle`
- `ApprovalRequest` / `ApprovalDecision`
- `ExecutionIdentity` / `DeviceIdentity`
- `TelemetryEvent`
- `ActionBinding`

Machine-readable definitions: `contracts.schema.json`.

Licensing / provenance: see `PROVENANCE.md` (includes COUNSEL_TODO).
