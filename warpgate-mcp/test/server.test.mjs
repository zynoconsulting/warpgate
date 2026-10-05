import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createServer as createHttpServer } from 'node:http'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { Client } from '@modelcontextprotocol/client'
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio'
import { createServer } from '../dist/server.js'

const id = 'a9c4404a-cc86-4e46-a18e-587baf29c420'
const executable = fileURLToPath(new URL('../dist/main.js', import.meta.url))

async function http(t, handler) {
	const server = createHttpServer(handler)
	await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
	t.after(async () => {
		server.closeAllConnections()
		await new Promise(resolve => server.close(resolve))
	})
	return `http://127.0.0.1:${server.address().port}`
}

async function connect(t, origin) {
	const tarball = process.env.WARPGATE_MCP_TEST_PACKAGE
	const transport = new StdioClientTransport({
		command: tarball ? 'npx' : process.execPath,
		args: tarball
			? ['--yes', '--package', tarball, 'warpgate-mcp']
			: [executable],
		cwd: process.env.WARPGATE_MCP_TEST_CWD,
		env: { WARPGATE_URL: origin, WARPGATE_TOKEN: 'requester-token' },
		stderr: 'pipe',
	})
	let stderr = ''
	transport.stderr.on('data', chunk => {
		stderr += chunk.toString()
	})
	const client = new Client({ name: 'warpgate-test', version: '1.0.0' })
	t.after(async () => {
		await client.close()
		assert.ok(
			!stderr.includes('requester-token'),
			'diagnostics must not expose the token',
		)
	})
	await client.connect(transport)
	return client
}

test('stdio tools preserve owner authentication, decisions and one-time ticket secrets', async t => {
	const requests = []
	let status = 'Pending'
	let activations = 0
	const origin = await http(t, async (req, res) => {
		const chunks = []
		for await (const chunk of req) chunks.push(chunk)
		const text = Buffer.concat(chunks).toString()
		requests.push({
			method: req.method,
			path: req.url,
			token: req.headers['x-warpgate-token'],
			body: text ? JSON.parse(text) : undefined,
		})
		let value
		if (req.url === '/@warpgate/api/ticket-request-targets') {
			value = [{ name: 'target' }]
		} else if (
			req.method === 'POST' &&
			req.url === '/@warpgate/api/ticket-requests'
		) {
			value = {
				request: { id, status: 'Approved', ticket_id: 'auto-ticket' },
				auto_approved_ticket_secret: 'auto-secret',
			}
		} else if (req.url === `/@warpgate/api/ticket-requests/${id}`) {
			value = { request: { id, status, ticket_id: null } }
		} else if (req.url === `/@warpgate/api/ticket-requests/${id}/activate`) {
			activations += 1
			res.statusCode = activations === 1 ? 200 : 409
			value =
				activations === 1
					? {
							secret: 'activated-secret',
							target: { name: 'target', kind: 'Ssh' },
						}
					: 'Already activated'
		} else {
			res.statusCode = 404
			value = 'Not found'
		}
		res.setHeader('content-type', 'application/json')
		res.end(JSON.stringify(value))
	})
	const client = await connect(t, origin)
	const listed = await client.listTools()
	assert.deepEqual(listed.tools.map(tool => tool.name).sort(), [
		'warpgate_activate_ticket',
		'warpgate_get_approval',
		'warpgate_list_approval_targets',
		'warpgate_request_approval',
	])
	const targets = await client.callTool({
		name: 'warpgate_list_approval_targets',
	})
	assert.deepEqual(targets.structuredContent, { targets: [{ name: 'target' }] })
	const created = await client.callTool({
		name: 'warpgate_request_approval',
		arguments: {
			target_name: 'target',
			duration_seconds: 3600,
			description: 'Investigate',
		},
	})
	assert.equal(
		created.structuredContent.auto_approved_ticket_secret,
		'auto-secret',
	)
	assert.deepEqual(requests.at(-1).body, {
		target_name: 'target',
		duration_seconds: 3600,
		description: 'Investigate',
	})
	for (status of ['Pending', 'Approved', 'Denied']) {
		const decision = await client.callTool({
			name: 'warpgate_get_approval',
			arguments: { approval_id: id },
		})
		assert.equal(decision.structuredContent.request.status, status)
	}
	status = 'Approved'
	const activated = await client.callTool({
		name: 'warpgate_activate_ticket',
		arguments: { approval_id: id },
	})
	assert.equal(activated.structuredContent.secret, 'activated-secret')
	assert.equal(JSON.parse(activated.content[0].text).secret, 'activated-secret')
	const repeated = await client.callTool({
		name: 'warpgate_activate_ticket',
		arguments: { approval_id: id },
	})
	assert.equal(repeated.isError, true)
	assert.equal(repeated.structuredContent.http_status, 409)
	assert.equal(
		activations,
		2,
		'each tool call makes exactly one activation attempt',
	)
	const foreign = await client.callTool({
		name: 'warpgate_get_approval',
		arguments: { approval_id: 'c5c20a7a-c83c-4b36-920c-5357b7a034c7' },
	})
	assert.equal(foreign.isError, true)
	assert.equal(foreign.structuredContent.http_status, 404)
	assert.ok(requests.every(request => request.token === 'requester-token'))
})

test('invalid arguments never reach the Warpgate API', async t => {
	let requests = 0
	const origin = await http(t, (_req, res) => {
		requests += 1
		res.end('{}')
	})
	const client = await connect(t, origin)
	for (const request of [
		{
			name: 'warpgate_get_approval',
			arguments: { approval_id: '../../admin/users' },
		},
		{
			name: 'warpgate_request_approval',
			arguments: { target_name: 'target', user_id: 'another-user' },
		},
		{
			name: 'warpgate_request_approval',
			arguments: { target_name: 'target', duration_seconds: 1.5 },
		},
		{
			name: 'warpgate_list_approval_targets',
			arguments: { user_id: 'another-user' },
		},
	]) {
		try {
			const rejected = await client.callTool(request)
			assert.equal(rejected.isError, true)
		} catch (error) {
			assert.match(
				error.message,
				/invalid|validation|argument|uuid|unrecognized/i,
			)
		}
	}
	assert.equal(requests, 0)
})

test('redirects cannot forward the token and malformed HTTP results are errors', async t => {
	let leaked = 0
	const destination = await http(t, (_req, res) => {
		leaked += 1
		res.end('{}')
	})
	let calls = 0
	const origin = await http(t, (_req, res) => {
		calls += 1
		if (calls === 1) {
			res.writeHead(302, { location: `${destination}/capture` })
			res.end()
		} else {
			res.writeHead(503, { 'content-type': 'text/plain' })
			res.end('Unavailable')
		}
	})
	const client = await connect(t, origin)
	const redirected = await client.callTool({
		name: 'warpgate_list_approval_targets',
	})
	assert.equal(redirected.isError, true)
	assert.equal(leaked, 0)
	assert.ok(!JSON.stringify(redirected).includes('requester-token'))
	const malformed = await client.callTool({
		name: 'warpgate_list_approval_targets',
	})
	assert.equal(malformed.isError, true)
	assert.equal(malformed.structuredContent.http_status, 503)
	assert.equal(calls, 2)
})

test('unsafe configuration fails before startup without exposing credentials', () => {
	for (const origin of [
		'http://remote.example',
		'https://user:private-token@example.com',
		'https://example.com/path',
		'https://example.com?token=private-token',
		'https://example.com#fragment',
		'invalid',
	]) {
		assert.throws(() => createServer(origin, 'token'), /WARPGATE_URL/)
	}
	assert.throws(() => createServer('https://example.com', ''), /WARPGATE_TOKEN/)
	assert.throws(
		() => createServer('https://example.com', 'token\r\nInjected: yes'),
		/WARPGATE_TOKEN/,
	)
	const child = spawnSync(process.execPath, [executable], {
		env: {
			WARPGATE_URL: 'https://user:private-token@example.com',
			WARPGATE_TOKEN: 'private-token',
		},
		encoding: 'utf8',
	})
	assert.equal(child.status, 1)
	assert.equal(child.stdout, '')
	assert.ok(!child.stderr.includes('private-token'))
})
