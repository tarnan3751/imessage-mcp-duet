# iMessage MCP

An MCP server (Node.js, CommonJS, stdio or Streamable HTTP) that reads the macOS Messages database and sends messages through AppleScript. Dependencies: `@modelcontextprotocol/sdk`, `better-sqlite3` and `express` (HTTP mode only).

This file is for AI agents that work **on** this code. If you only use the server, read the [README](README.md).

## Build, test, run
- Node 18 up to but not including 26. Use Node 24 (`better-sqlite3` does not build on Node 26). On Homebrew: `PATH=/opt/homebrew/opt/node@24/bin:$PATH`.
- Install: `npm install` (or `npm ci`).
- Test: `npm test` (`node --test`). Run the whole suite before you say something works. Tests use mocks and temporary databases.
- Run: `node index.js` (stdio server; waits for an MCP client). `node index.js --http` runs the remote server and needs `IMESSAGE_MCP_PUBLIC_URL` and a passphrase from `--set-passphrase`.
- Never run the server against the real Messages database to test sending. Do not call `send_message`, `send_message_batch`, `react_to_message` or any mutation tool for real. Use the injected `runScript` and temporary databases the tests use.
- Do not touch `~/Library/Messages`, and do not launch the Messages app.

## Code map
- `index.js`: everything else. Tool registration (the `tools` list in the `ListTools` handler), tool handlers, `attributedBody` decoder, contact cache (AddressBook SQLite), AppleScript builders, release-flag gating (`IMESSAGE_MCP_RELEASES`), backup and delete logic.
- `lib/http.js`: HTTP mode. Express app with the OAuth endpoints, consent form, `/health` and `/mcp` (one MCP server per session, all sharing one `IMessageServer`).
- `lib/auth.js`: single-owner OAuth provider for the SDK's auth router, passphrase hashing, and the state files in `~/.imessage-mcp`.
- `scripts/install-launchagent.sh`, `scripts/uninstall-launchagent.sh`: the LaunchAgent for HTTP mode.
- `lib/batch.js`: batch preview, approval tokens.
- `lib/outreach.js`: follow-up classification for `find_outreach_followups`.
- `test/`: `mcp-tools.test.js`, `mutation-tools.test.js`, `batch.test.js`, `outreach.test.js`, `http.test.js` (OAuth flow and `/mcp` against a temporary state directory).

## Conventions
- Match the surrounding code: naming, comment density, idiom. Comments say why, not what.
- Plain CommonJS. No new dependencies without discussion.
- Sending, reacting and deleting stay behind `confirm: true` (plus an approval token for batches and `delete_threads`). Do not weaken a gate.
- Mutation and UI-automation tools stay behind release flags. A tool that needs a flag must not be listed without it.
- The server makes no outgoing network requests. Do not add any. HTTP mode only listens, on loopback by default.
- In HTTP mode every route except `/health`, discovery, registration, `/authorize`, `/consent` and `/token` needs a valid token. Never log tokens, codes, query strings or message content.
- Never put real messages, phone numbers or contact names in code, tests or docs.
- When you add or change a tool or release flag, update the README tools table and release flags table, and `CHANGELOG.md`.
