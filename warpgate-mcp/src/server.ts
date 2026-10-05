import { type CallToolResult, McpServer } from '@modelcontextprotocol/server'
import { z } from 'zod'

function result(
	value: Record<string, unknown>,
	isError = false,
): CallToolResult {
	return {
		content: [{ type: 'text', text: JSON.stringify(value) }],
		structuredContent: value,
		isError,
	}
}

export function createServer(origin: string, token: string): McpServer {
	let baseUrl: URL
	try {
		baseUrl = new URL(origin)
	} catch {
		throw new Error('WARPGATE_URL must be an absolute URL')
	}
	const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(
		baseUrl.hostname,
	)
	if (
		baseUrl.protocol !== 'https:' &&
		!(baseUrl.protocol === 'http:' && loopback)
	) {
		throw new Error(
			'WARPGATE_URL must use HTTPS (HTTP is allowed for loopback development)',
		)
	}
	if (
		baseUrl.username ||
		baseUrl.password ||
		baseUrl.search ||
		baseUrl.hash ||
		baseUrl.pathname !== '/'
	) {
		throw new Error(
			'WARPGATE_URL must contain only the Warpgate origin, without credentials, path, query or fragment',
		)
	}
	if (!token.trim()) {
		throw new Error('WARPGATE_TOKEN must be a user API token')
	}
	let headers: Headers
	try {
		headers = new Headers({ 'x-warpgate-token': token })
	} catch {
		throw new Error('Invalid WARPGATE_TOKEN header value')
	}
	baseUrl.pathname = '/@warpgate/api/'

	async function call(
		method: string,
		path: string,
		body?: object,
	): Promise<CallToolResult> {
		let response: Response
		try {
			response = await fetch(new URL(path, baseUrl), {
				method,
				headers: body
					? {
							...Object.fromEntries(headers),
							'content-type': 'application/json',
						}
					: headers,
				body: body ? JSON.stringify(body) : undefined,
				redirect: 'error',
				signal: AbortSignal.timeout(30_000),
			})
		} catch {
			return result({ error: 'Warpgate request failed or timed out' }, true)
		}
		let value: unknown
		try {
			value = await response.json()
		} catch {
			return result(
				{
					http_status: response.status,
					error: 'Warpgate returned no JSON result',
				},
				true,
			)
		}
		if (!response.ok) {
			return result({ http_status: response.status, error: value }, true)
		}
		if (Array.isArray(value)) {
			return result({ targets: value })
		}
		if (!value || typeof value !== 'object') {
			return result(
				{
					http_status: response.status,
					error: 'Warpgate returned no JSON object',
				},
				true,
			)
		}
		return result(value as Record<string, unknown>)
	}

	const server = new McpServer(
		{ name: 'warpgate-mcp', version: '0.1.0' },
		{
			instructions:
				'Request target access through the existing Warpgate ticket workflow. Slack notifications link approvers to Warpgate, where they approve or deny. Poll your request for the decision, then activate an approved unactivated request. Ticket secrets appear only once. Approval does not bypass independent session approval requirements. Never expose ticket secrets in Slack.',
		},
	)
	server.registerTool(
		'warpgate_list_approval_targets',
		{
			description:
				'List requestable Warpgate targets and their current ticket duration limits. Normal user visibility applies.',
			inputSchema: z.object({}).strict(),
			annotations: { readOnlyHint: true },
		},
		() => call('GET', 'ticket-request-targets'),
	)
	server.registerTool(
		'warpgate_request_approval',
		{
			description:
				'Request an access ticket as the configured Warpgate user. Pending requests send a Slack notification linking to the Warpgate approval page when configured. An approver decides in Warpgate. Existing auto-approval may return auto_approved_ticket_secret once: keep it securely; it cannot be retrieved again.',
			inputSchema: z
				.object({
					target_name: z
						.string()
						.describe('Target name from warpgate_list_approval_targets.'),
					duration_seconds: z
						.number()
						.int()
						.nullish()
						.describe(
							'Optional access duration in seconds; the existing Warpgate policy applies.',
						),
					description: z
						.string()
						.nullish()
						.describe(
							'Reason for requesting access; required if the existing policy says so.',
						),
				})
				.strict(),
		},
		args => call('POST', 'ticket-requests', args),
	)
	const approvalId = z
		.object({
			approval_id: z
				.uuid()
				.describe('UUID returned as request.id by warpgate_request_approval.'),
		})
		.strict()
	server.registerTool(
		'warpgate_get_approval',
		{
			description:
				'Read your ticket request’s Pending, Approved or Denied status. Poll to learn the decision. Approved requests with no ticket_id can be activated. Request approval creates no new expiry deadline.',
			inputSchema: approvalId,
			annotations: { readOnlyHint: true },
		},
		({ approval_id }) =>
			call('GET', `ticket-requests/${approval_id.toLowerCase()}`),
	)
	server.registerTool(
		'warpgate_activate_ticket',
		{
			description:
				'Activate your approved ticket request. Returns the ticket secret once and target connection metadata. Preserve the secret securely: activation is not replayable. Existing ticket duration/use limits and any separate target session approval still apply.',
			inputSchema: approvalId,
		},
		({ approval_id }) =>
			call('POST', `ticket-requests/${approval_id.toLowerCase()}/activate`),
	)
	return server
}
