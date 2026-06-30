# Security Policy — Sqreen.ai

The Sqreen.ai team takes the security of our runtime application self-protection (RASP) data planes, sandboxes, and developer tools seriously. Thank you for helping us maintain a safe, private ecosystem for autonomous engineering agents.

## Supported Versions

We actively monitor and patch security vulnerabilities across the following release distributions:

| Version | Supported | Notes |
| ------- | --------- | ----- |
| v0.1.x  | ✅ Yes    | Active stable core branch (e.g., v0.1.7+) |
| < v0.1.0| ❌ No     | Alpha proof-of-concept tag baselines |

## Reporting a Vulnerability

**Please do not report security vulnerabilities or potential data leaks via public GitHub Issues or community threads.**

Instead, submit your findings privately to ensure we can coordinate a responsible disclosure timeline and roll out an automated patch stream to active developer laptops.

### Where to Report
* **Secure Corridor Email**: security@sqreen.ai
* **Response SLA**: The lead systems engineering contact will acknowledge your transmission within **24 hours** and provide a structural triage assessment within **48 hours**.

### What to Include
To help us patch and verify your report quickly, please structure your transmission with:
1. A concise overview of the systemic threat vector (e.g., a Wasm linear memory sandbox breakout or an entropy detection bypass).
2. A clean, minimal Proof of Concept (PoC) script or sample tool payload.
3. Steps to reproduce the execution states locally using the raw `mcp-proxy` standard I/O pipe.

We highly appreciate and respect the work of independent security researchers. Valid, responsibly disclosed findings will be publically acknowledged and credited inside our official release changelogs.
