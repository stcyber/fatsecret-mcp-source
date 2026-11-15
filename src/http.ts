import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { FatSecretMcpServer } from './index.js';

const port = Number(process.env.PORT || 10000);
const bearer = process.env.MCP_BEARER_TOKEN;
if (!bearer || bearer.length < 32) {
  throw new Error('MCP_BEARER_TOKEN must be set to a random secret of at least 32 characters');
}

function authorized(req: IncomingMessage): boolean {
  const supplied = req.headers.authorization;
  if (!supplied?.startsWith('Bearer ')) return false;
  const actual = Buffer.from(supplied.slice(7));
  const expected = Buffer.from(bearer!);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

const sessions = new Map<string, StreamableHTTPServerTransport>();

const http = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  if (req.url === '/health' && req.method === 'GET') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
    return;
  }
  if (req.url !== '/mcp') {
    res.writeHead(404).end();
    return;
  }
  if (!authorized(req)) {
    res.writeHead(401, { 'www-authenticate': 'Bearer', 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'Unauthorized' }));
    return;
  }
  try {
    const sessionId = req.headers['mcp-session-id'];
    let transport = typeof sessionId === 'string' ? sessions.get(sessionId) : undefined;
    if (req.method === 'POST' && !transport && !sessionId) {
      // Only initialize messages may create sessions.
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(Buffer.from(chunk));
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!isInitializeRequest(body)) {
        res.writeHead(400).end('Expected MCP initialize request');
        return;
      }
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id) => { sessions.set(id, transport!); },
      });
      transport.onclose = () => {
        if (transport?.sessionId) sessions.delete(transport.sessionId);
      };
      const server = new FatSecretMcpServer();
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
      return;
    }
    if (!transport) {
      res.writeHead(400).end('Unknown MCP session');
      return;
    }
    await transport.handleRequest(req, res);
  } catch (error) {
    console.error('MCP request failed:', error);
    if (!res.headersSent) res.writeHead(500).end('Internal server error');
  }
});
http.listen(port, '0.0.0.0', () => console.error(`FatSecret MCP HTTP listening on ${port}`));
