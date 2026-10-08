#!/usr/bin/env node
import { serveStdio } from '@modelcontextprotocol/server/stdio'
import { createServer } from './server.js'

try {
	const origin = process.env.WARPGATE_URL
	const token = process.env.WARPGATE_TOKEN
	if (!origin) throw new Error('Set WARPGATE_URL to the Warpgate HTTPS origin')
	if (!token)
		throw new Error('Set WARPGATE_TOKEN to an existing user API token')
	const server = createServer(origin, token)
	serveStdio(() => server)
} catch (error) {
	console.error(
		error instanceof Error ? error.message : 'Could not start Warpgate MCP',
	)
	process.exitCode = 1
}
