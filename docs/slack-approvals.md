# Slack ticket request notifications and MCP setup

Warpgate posts pending access ticket requests to Slack with a link to that request in Warpgate. Approvers open the link, sign in normally, and approve or deny using the existing **Manage ticket requests** admin permission. Target access roles, approval policy, requester activation, and any independent session approval gate continue to work as before.

## Configure Slack notifications

Create a Slack app, install its bot with `chat:write`, and invite the bot to the notification channel. This uses Slack's [chat.postMessage API](https://docs.slack.dev/reference/methods/chat.postMessage/). No Slack event subscription, callback URL, reaction scope, identity binding, or Sign in with Slack setup is needed.

Configure the channel and bot token in the existing Warpgate YAML configuration on every node. Set the existing public host and HTTP external port so notification links point to your public HTTPS origin:

```yaml
external_host: warpgate.example
http:
  external_port: 443
slack_approvals:
  channel_id: C_APPROVALS
  bot_token: "your-slack-bot-token"
```

The presence of `slack_approvals` enables notifications; omit it to disable them. The token uses the existing config-file secret pattern. Keep the config readable only by the Warpgate service account. Environment-variable placeholders are not interpolated. Warpgate needs outbound HTTPS access to Slack.

Enable ticket self-service and choose approval requirements through the existing global and target settings. The integration adds no per-target approver lists, request deadlines, activation deadlines, or approval roles.

## Review a request

A notification includes the requester, target, requested duration, reason, and **Review request in Warpgate** link. The link selects the actual request under **Status → Requests**, including its current status if it has already been resolved. Sign-in preserves the link. Only users with the existing ticket request management permission can view and decide it; possession of the Slack link grants no access. Opening a link never approves or denies a request.

Approval leaves the existing request approved and awaiting requester activation. Activation creates the normal access ticket and starts its existing duration. Auto-approved requests retain immediate activation and do not generate Slack notifications. Targets that independently require session approval still enforce that gate when the ticket is used. Ticket secrets never appear in Slack.

Warpgate attempts one asynchronous post when a pending request is created. Delivery is best effort: Slack failures are logged, and a process interruption can lose a notification. The request remains available in Warpgate. There is no delivery storage, retry sweep, or additional timer. The linked page shows the current result after a decision.

## Run the MCP adapter

Build the standalone stdio adapter:

```bash
cargo build -p warpgate-mcp --release
```

The Docker image also includes `warpgate-mcp`. Configure your MCP client to launch the binary with the Warpgate origin and an existing requester user API token:

```json
{
  "mcpServers": {
    "warpgate": {
      "command": "/path/to/warpgate-mcp",
      "env": {
        "WARPGATE_URL": "https://warpgate.example",
        "WARPGATE_TOKEN": "your-requester-user-api-token"
      }
    }
  }
}
```

Use an origin without a path, query, or fragment. HTTPS is required, with HTTP allowed for loopback development. Redirects are disabled to avoid forwarding the token to another origin. The normal API token expiry, requester identity, visibility, and authorization rules apply. A global admin token does not represent a requester user.

| Tool | Arguments | Result |
| --- | --- | --- |
| `warpgate_list_approval_targets` | None | Requestable targets and existing duration limits under `targets` |
| `warpgate_request_approval` | `target_name`, optional `duration_seconds`, optional `description` | Existing creation result with `request.id`, status, target information, and any auto-approved ticket secret |
| `warpgate_get_approval` | `approval_id` | The requester's existing request with `Pending`, `Approved`, or `Denied` status |
| `warpgate_activate_ticket` | `approval_id` | Existing activation result with the one-time secret and target connection metadata |

Request access, poll `warpgate_get_approval` for a decision, and activate an approved request whose `ticket_id` is absent. An auto-approved creation may already return a secret and ticket ID; keep that secret rather than activating again. No MCP tool approves requests or selects approvers.

Creation and activation secrets are returned only once. Warpgate stores their hashes, so an already activated ticket's plaintext secret cannot be retrieved. Preserve the secret securely; normal ticket expiry, use limits, and revocation apply after activation. Pending requests and unactivated approvals retain their existing untimed behavior.
