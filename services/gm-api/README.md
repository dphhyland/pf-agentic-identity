# gm-api — Grant Management & Evaluation API for PingFederate

The proposed **Grant Evaluation API** (an extension to the OpenID Grant Management
API) running **inside PingFederate**, as a servlet plus an MCP add-on for AI agents.

A client asks whether an existing grant still permits an action — right now, without
a new authorization flow. The answer is an intersection: *what the client was granted*
∩ *what the subject actually holds* ∩ *the agent's authority* (when an agent is acting).
A grant can be valid, unexpired and correctly scoped and still worthless, because the
subject closed the account it names. That is what a token introspection cannot see.

## What's here

| Path | What |
|---|---|
| [`servlet/`](servlet) | The API as a PingFederate WAR: query / revoke / evaluate / metadata, plus the `/mcp` JSON-RPC add-on. Reads grants in-process via the PF SDK. **Start at [`servlet/README.md`](servlet/README.md).** |
| [`deploy/`](deploy) | PingFederate configuration (Terraform) and the demo grant store setup |
| [`docs/`](docs) | The draft spec extension, the PingFederate implementability report, MCP notes |
| [`examples/java`](examples/java) | A JDK-only Java client |

## Related

- **AS-agnostic Go reference:** [`grant-evaluation-api`](https://github.com/dphhyland/grant-evaluation-api).
  The same API, portable across authorization servers via a pluggable grant source
  (PingFederate, or any RFC 7662 introspection endpoint). curl and Go client examples
  live there.
- **RAR consent processor:** [`pf-rar-paz-plugin`](https://github.com/dphhyland/pf-rar-paz-plugin)
  governs `authorization_details` at consent time via PingAuthorize.

## The PDP

The servlet is the enforcement point; the decision is an **AuthZEN 1.0 PDP** it calls.
For a demo PDP, run `cmd/pdp` from `grant-evaluation-api`, or point `pdpUrl` at
**PingAuthorize** behind its AuthZEN facade. The servlet needs no PDP code of its own.
