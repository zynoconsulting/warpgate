# Warpgate MCP

A stdio MCP adapter for requesting, checking, and activating access tickets through Warpgate's existing HTTP API. Approvers review and decide requests in Warpgate using normal approval permissions. Notification integrations are optional and separate.

Requires Node.js 22 or newer. The npm package includes compiled JavaScript and runs independently of Warpgate's Rust build and Docker image.

## Run with npx

This package is not published to npm yet. From this directory, build a local package:

```bash
npm ci
npm pack
```

Configure your MCP client:

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

After npm publication, simplify `args` to `["--yes", "@zynoconsulting/warpgate-mcp@0.1.0"]`.

`WARPGATE_URL` must be an HTTPS origin without credentials, a path, query, or fragment. HTTP is allowed for loopback development. `WARPGATE_TOKEN` must be an existing requester user API token. Redirects are disabled, and existing requester authorization remains enforced by Warpgate.

## Tools

| Tool | Arguments |
| --- | --- |
| `warpgate_list_approval_targets` | None |
| `warpgate_request_approval` | `target_name`, optional `duration_seconds`, optional `description` |
| `warpgate_get_approval` | `approval_id` |
| `warpgate_activate_ticket` | `approval_id` |

Poll for the existing `Pending`, `Approved`, or `Denied` status, then activate an approved request without a `ticket_id`. Creation may auto-approve and return a ticket secret immediately. Ticket secrets are returned only once; preserve them securely. Tools do not approve requests or retry creation or activation. Pending requests and unactivated approvals have no new expiry deadline.

See the [MCP ticket workflow setup](https://github.com/zynoconsulting/warpgate/blob/zyno/ticket-mcp/docs/mcp.md) for full result details and ticket lifecycle behavior.

## Develop

```bash
npm ci
npm test
npm start
```

`npm test` compiles the adapter and tests its stdio protocol and HTTP behavior against a local mock API. `npm start` runs the compiled adapter with the environment variables above. `npm pack` builds the distributable package automatically.
