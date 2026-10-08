# Ticket request notifications

Warpgate posts pending access ticket requests to Slack with a link to that request in Warpgate. Approvers open the link, sign in normally, and approve or deny using the existing **Manage ticket requests** admin permission. Target access roles, approval policy, requester activation, and any independent session approval gate continue to work as before.

## Configure Slack notifications

Create a Slack app, install its bot with `chat:write`, and invite the bot to the notification channel. This uses Slack's [chat.postMessage API](https://docs.slack.dev/reference/methods/chat.postMessage/). No Slack event subscription, callback URL, reaction scope, identity binding, or Sign in with Slack setup is needed.

Configure the channel and bot token in the existing Warpgate YAML configuration on every node. Set the existing public host and HTTP external port so notification links point to your public HTTPS origin:

```yaml
external_host: warpgate.example
http:
  external_port: 443
notifications:
  slack:
    channel_id: C_APPROVALS
    bot_token: "your-slack-bot-token"
```

The `notifications.slack` entry enables Slack delivery; omit it to disable it. The token uses the existing config-file secret pattern. Keep the config readable only by the Warpgate service account. Environment-variable placeholders are not interpolated. Warpgate needs outbound HTTPS access to Slack.

Enable ticket self-service and choose approval requirements through the existing global and target settings. The integration adds no per-target approver lists, request deadlines, activation deadlines, or approval roles.

## Review a request

A notification includes the requester, target, requested duration, reason, and **Review request in Warpgate** link. The link selects the actual request under **Status → Requests**, including its current status if it has already been resolved. Sign-in preserves the link. Only users with the existing ticket request management permission can view and decide it; possession of the Slack link grants no access. Opening a link never approves or denies a request.

Approval leaves the existing request approved and awaiting requester activation. Activation creates the normal access ticket and starts its existing duration. Auto-approved requests retain immediate activation and do not generate Slack notifications. Targets that independently require session approval still enforce that gate when the ticket is used. Ticket secrets never appear in Slack.

Warpgate attempts one asynchronous post when a pending request is created. Delivery is best effort: Slack failures are logged, and a process interruption can lose a notification. The request remains available in Warpgate. There is no delivery storage, retry sweep, or additional timer. The linked page shows the current result after a decision.

## Adding another notification provider

The HTTP request endpoint calls `notifications::notify_ticket_request` with the existing request data. The notifications module builds a provider-neutral payload containing raw requester, target, duration, reason, and request ID, and derives the review URL from the public origin. Providers own message formatting, escaping, size limits, and delivery. The Slack implementation lives in `warpgate-core/src/notifications/slack.rs`.

A future Teams or Discord implementation can add a provider module and an optional entry alongside `notifications.slack`, extend the configuration's empty-provider check, and add its send call to the dispatcher. Delivery errors are handled per provider. The ticket creation endpoint and approval authorization remain shared. Only Slack is implemented here.
