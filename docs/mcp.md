# MCP ticket approval adapter

Request, check, and activate access tickets through the existing requester-owned Warpgate HTTP APIs. Approvers review and decide requests in Warpgate using normal approval permissions. This adapter works independently of notification integrations.

The stdio adapter is a separate TypeScript/npm package requiring Node.js 22 or newer. It uses the existing HTTP APIs and adds no Cargo dependencies or Docker build steps.

The package is not published to npm yet. Build a runnable package from this checkout:

```bash
cd warpgate-mcp
npm ci
npm pack
```

`npm pack` compiles TypeScript and creates `zynoconsulting-warpgate-mcp-0.1.0.tgz`. Configure your MCP client to run that package through `npx`, with the Warpgate origin and an existing requester user API token:

```json
{
  "mcpServers": {
    "warpgate": {
      "command": "npx",
      "args": ["--yes", "--package", "/absolute/path/to/zynoconsulting-warpgate-mcp-0.1.0.tgz", "warpgate-mcp"],
      "env": {
        "WARPGATE_URL": "https://warpgate.example",
        "WARPGATE_TOKEN": "your-requester-user-api-token"
      }
    }
  }
}
```

After npm publication, simplify `args` to `["--yes", "@zynoconsulting/warpgate-mcp@0.1.0"]`. The installed package includes compiled JavaScript; consumers need no Rust or TypeScript compiler. For local development, run `npm run build` and then `npm start` inside `warpgate-mcp` with the same environment variables. `npm test` exercises the stdio tools against a local mock HTTP API.

Use an origin without a path, query, or fragment. HTTPS is required, with HTTP allowed for loopback development. Redirects are disabled to avoid forwarding the token to another origin. The normal API token expiry, requester identity, visibility, and authorization rules apply. A global admin token does not represent a requester user.

| Tool | Arguments | Result |
| --- | --- | --- |
| `warpgate_list_approval_targets` | None | Requestable targets and existing duration limits under `targets` |
| `warpgate_request_approval` | `target_name`, optional `duration_seconds`, optional `description` | Existing creation result with `request.id`, status, target information, and any auto-approved ticket secret |
| `warpgate_get_approval` | `approval_id` | The requester's existing request with `Pending`, `Approved`, or `Denied` status |
| `warpgate_activate_ticket` | `approval_id` | Existing activation result with the one-time secret and target connection metadata |

Request access, poll `warpgate_get_approval` for a decision, and activate an approved request whose `ticket_id` is absent. An auto-approved creation may already return a secret and ticket ID; keep that secret rather than activating again. No MCP tool approves requests or selects approvers.

Creation and activation secrets are returned only once. Warpgate stores their hashes, so an already activated ticket's plaintext secret cannot be retrieved. Preserve the secret securely; normal ticket expiry, use limits, and revocation apply after activation. Pending requests and unactivated approvals retain their existing untimed behavior.
