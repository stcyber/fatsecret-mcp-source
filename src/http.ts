import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomUUID, randomBytes, timingSafeEqual, createHmac, createHash } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { FatSecretMcpServer } from './index.js';

// One-owner OAuth 2.1 bridge for ChatGPT. FatSecret's OAuth 1.0 is separate.
const port = Number(process.env.PORT || 10000);
const ownerSecret = process.env.MCP_BEARER_TOKEN;
if (!ownerSecret || ownerSecret.length < 32) throw new Error('MCP_BEARER_TOKEN must be at least 32 characters');
const origin = (process.env.MCP_PUBLIC_URL || 'https://fatsecret-mcp-ns6r.onrender.com').replace(/\/$/, '');
const resource = origin + '/mcp';
const sessions = new Map<string, StreamableHTTPServerTransport>();
const pending = new Map<string, { clientId: string; redirect: string; challenge: string; expires: number }>();

function equal(a: string, b: string): boolean {
  const x = Buffer.from(a); const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
function send(res: ServerResponse, status: number, data: unknown, extra: Record<string, string> = {}) {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...extra });
  res.end(JSON.stringify(data));
}
async function form(req: IncomingMessage): Promise<URLSearchParams> {
  let body = '';
  for await (const part of req) {
    body += part.toString();
    if (body.length > 16384) throw new Error('Request too large');
  }
  return new URLSearchParams(body);
}
function validRedirect(uri: string): boolean {
  try {
    const u = new URL(uri);
    return !u.username && !u.password && !u.hash && (u.protocol === 'https:' || (u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname)));
  } catch { return false; }
}
function token(): string {
  const payload = Buffer.from(JSON.stringify({ aud: resource, exp: Date.now() + 30 * 86400000, nonce: randomUUID() })).toString('base64url');
  const mac = createHmac('sha256', ownerSecret!).update(payload).digest('base64url');
  return payload + '.' + mac;
}
function authorized(req: IncomingMessage): boolean {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return false;
  const supplied = header.slice(7);
  if (equal(supplied, ownerSecret!)) return true; // Retain existing private client access.
  const [payload, signature, extra] = supplied.split('.');
  if (!payload || !signature || extra) return false;
  const mac = createHmac('sha256', ownerSecret!).update(payload).digest('base64url');
  if (!equal(mac, signature)) return false;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return data.aud === resource && Number.isFinite(data.exp) && data.exp > Date.now();
  } catch { return false; }
}
function oauthError(res: ServerResponse, status: number, error: string) { send(res, status, { error }); }
function html(res: ServerResponse, status: number, body: string) {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'", 'x-content-type-options': 'nosniff' });
  res.end(body);
}
function authForm(q: URLSearchParams, invalid = false): string {
  const fields = ['response_type', 'client_id', 'redirect_uri', 'state', 'code_challenge', 'code_challenge_method', 'resource', 'scope'];
  const hidden = fields.map(k => '<input type="hidden" name="' + k + '" value="' + escapeHtml(q.get(k) || '') + '">').join('');
  return '<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize FatSecret MCP</title></head><body style="font:16px system-ui;max-width:440px;margin:60px auto;padding:20px"><h2>Connect FatSecret to ChatGPT</h2><p>Enter the MCP_BEARER_TOKEN value from your private Render Environment settings. Never share it in chat.</p>' + (invalid ? '<p style="color:#b00">Incorrect secret.</p>' : '') + '<form method="POST" action="/authorize">' + hidden + '<label>Owner secret <input name="password" type="password" required autocomplete="off" style="width:100%;padding:12px;box-sizing:border-box"></label><p><button type="submit" style="padding:12px">Authorize ChatGPT</button></p></form></body></html>';
}
function escapeHtml(s: string): string { return s.replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c]!); }
function authParams(q: URLSearchParams): boolean {
  return q.get('response_type') === 'code' && !!q.get('client_id') && !!q.get('state') &&
    q.get('code_challenge_method') === 'S256' && /^[A-Za-z0-9_-]{43,128}$/.test(q.get('code_challenge') || '') &&
    validRedirect(q.get('redirect_uri') || '') && (!q.get('resource') || q.get('resource') === resource);
}

const http = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  try {
    const path = new URL(req.url || '/', origin).pathname;
    if (path === '/authorize') console.error('OAuth authorize request:', req.method, 'content-type:', req.headers['content-type'] || 'none');
    if (path === '/health' && req.method === 'GET') return send(res, 200, { status: 'ok' });

    if ((path === '/.well-known/oauth-authorization-server' || path === '/.well-known/oauth-authorization-server/mcp') && req.method === 'GET') {
      return send(res, 200, { issuer: origin, authorization_endpoint: origin + '/authorize', token_endpoint: origin + '/token', registration_endpoint: origin + '/register', response_types_supported: ['code'], grant_types_supported: ['authorization_code'], token_endpoint_auth_methods_supported: ['none'], code_challenge_methods_supported: ['S256'] });
    }
    if ((path === '/.well-known/oauth-protected-resource' || path === '/.well-known/oauth-protected-resource/mcp') && req.method === 'GET') {
      return send(res, 200, { resource, authorization_servers: [origin], bearer_methods_supported: ['header'] });
    }
    if (path === '/register' && req.method === 'POST') {
      let raw = ''; for await (const chunk of req) { raw += chunk.toString(); if (raw.length > 16384) return oauthError(res, 413, 'invalid_client_metadata'); }
      let data: any; try { data = JSON.parse(raw); } catch { return oauthError(res, 400, 'invalid_client_metadata'); }
      if (!Array.isArray(data.redirect_uris) || !data.redirect_uris.length || !data.redirect_uris.every((x: unknown) => typeof x === 'string' && validRedirect(x))) return oauthError(res, 400, 'invalid_redirect_uri');
      // Stateless client registration: exact redirect URI is encoded in client_id.
      const clientId = Buffer.from(JSON.stringify(data.redirect_uris)).toString('base64url');
      return send(res, 201, { client_id: clientId, client_id_issued_at: Math.floor(Date.now() / 1000), redirect_uris: data.redirect_uris, token_endpoint_auth_method: 'none', grant_types: ['authorization_code'], response_types: ['code'] });
    }
    if (path === '/authorize' && (req.method === 'GET' || req.method === 'POST')) {
      const q = req.method === 'GET' ? new URL(req.url!, origin).searchParams : await form(req);
      if (!authParams(q)) { console.error('OAuth authorize: invalid parameters', { method: req.method, hasClient: !!q.get('client_id'), hasState: !!q.get('state'), hasChallenge: !!q.get('code_challenge'), hasRedirect: !!q.get('redirect_uri') }); return oauthError(res, 400, 'invalid_request'); }
      let redirects: string[];
      try { redirects = JSON.parse(Buffer.from(q.get('client_id')!, 'base64url').toString()); } catch { return oauthError(res, 400, 'invalid_client'); }
      if (!Array.isArray(redirects) || !redirects.includes(q.get('redirect_uri')!)) return oauthError(res, 400, 'invalid_redirect_uri');
      if (req.method === 'GET' || !equal(q.get('password') || '', ownerSecret!)) { if (req.method === 'POST') console.error('OAuth authorize: owner secret did not match'); return html(res, 200, authForm(q, req.method === 'POST')); }
      console.error('OAuth authorize: owner verified, redirecting to ChatGPT');
      const code = randomBytes(32).toString('base64url');
      pending.set(code, { clientId: q.get('client_id')!, redirect: q.get('redirect_uri')!, challenge: q.get('code_challenge')!, expires: Date.now() + 300000 });
      const dest = new URL(q.get('redirect_uri')!);
      dest.searchParams.set('code', code);
      dest.searchParams.set('state', q.get('state')!);
      res.writeHead(302, { location: dest.toString(), 'cache-control': 'no-store' }); res.end(); return;
    }
    if (path === '/token' && req.method === 'POST') {
      const q = await form(req);
      if (q.get('grant_type') !== 'authorization_code') return oauthError(res, 400, 'unsupported_grant_type');
      const code = q.get('code') || '';
      const p = pending.get(code);
      pending.delete(code);
      if (!p || p.expires < Date.now() || p.clientId !== q.get('client_id') || p.redirect !== q.get('redirect_uri')) return oauthError(res, 400, 'invalid_grant');
      const verifier = q.get('code_verifier') || '';
      if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return oauthError(res, 400, 'invalid_grant');
      const digest = createHash('sha256').update(verifier).digest('base64url');
      if (!equal(digest, p.challenge)) return oauthError(res, 400, 'invalid_grant');
      return send(res, 200, { access_token: token(), token_type: 'Bearer', expires_in: 2592000 });
    }
    if (path !== '/mcp') { res.writeHead(404).end(); return; }
    if (!authorized(req)) return send(res, 401, { error: 'Unauthorized' }, { 'www-authenticate': 'Bearer resource_metadata="' + origin + '/.well-known/oauth-protected-resource/mcp"' });
    const sessionId = req.headers['mcp-session-id'];
    let transport = typeof sessionId === 'string' ? sessions.get(sessionId) : undefined;
    if (req.method === 'POST' && !transport && !sessionId) {
      const chunks: Buffer[] = [];
      for await (const chunk of req) { chunks.push(Buffer.from(chunk)); if (chunks.reduce((n, b) => n + b.length, 0) > 1048576) return send(res, 413, { error: 'Too large' }); }
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!isInitializeRequest(body)) { res.writeHead(400).end('Expected MCP initialize request'); return; }
      transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID(), onsessioninitialized: (id) => { sessions.set(id, transport!); } });
      transport.onclose = () => { if (transport?.sessionId) sessions.delete(transport.sessionId); };
      const server = new FatSecretMcpServer();
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
      return;
    }
    if (!transport) { res.writeHead(400).end('Unknown MCP session'); return; }
    await transport.handleRequest(req, res);
  } catch (error) {
    console.error('HTTP request failed:', error);
    if (!res.headersSent) send(res, 500, { error: 'Internal server error' });
  }
});
http.listen(port, '0.0.0.0', () => console.error('FatSecret MCP HTTP listening on ' + port));
