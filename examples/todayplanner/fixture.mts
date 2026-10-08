/** Disposable harness around the actual todayPlanner app, OAuth and SQLite store. */
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const root = process.env.TODAYPLANNER_ROOT;
if (!root) throw new Error('TODAYPLANNER_ROOT is required');
const { oauthFixture } = await import(pathToFileURL(resolve(root, 'server/oauth-fixture.ts')).href);
const fixture = await oauthFixture();
const owner = await fixture.account('interlock-demo-owner@example.com');
const other = await fixture.account('interlock-demo-other@example.com');
const readOnly = await fixture.account('interlock-demo-readonly@example.com');
const client = await fixture.client('AgentInterlock disposable local validation');
const token = (await fixture.authorize(client.client_id, owner.token)).access_token;
const otherToken = (await fixture.authorize(client.client_id, other.token)).access_token;
const readOnlyToken = (await fixture.authorize(client.client_id, readOnly.token, 'planner:read')).access_token;
const initial = await fixture.request('/api/tasks', {
  expectedRevision: 0,
  task: { title: 'Disposable approved appointment', durationMinutes: 30, scheduledDate: '2030-10-06', startMinute: 600 },
}, owner.token);
if (initial.status !== 201) throw new Error('Fixture schedule creation failed');
const state = await initial.json();

// This loopback proxy really drops the caller's HTTP connection before dispatch
// or after the app has returned its committed result. Production has no fault flags.
const proxy = createServer(async (req, res) => {
  try {
    const body: Buffer[] = [];
    for await (const chunk of req) body.push(Buffer.from(chunk));
    const fault = req.headers['x-interlock-demo-fault'];
    if (fault === 'before_commit' && req.method === 'PATCH') { res.destroy(); return; }
    const response = await fetch(fixture.base + req.url, {
      method: req.method, redirect: 'error',
      headers: {
        Authorization: req.headers.authorization ?? '',
        'Content-Type': 'application/json', 'Accept-Language': 'en',
      },
      ...(body.length ? { body: Buffer.concat(body) } : {}),
    });
    const content = Buffer.from(await response.arrayBuffer());
    if (fault === 'after_commit' && req.method === 'PATCH' && response.ok) { res.destroy(); return; }
    res.writeHead(response.status, { 'Content-Type': 'application/json' }); res.end(content);
  } catch { if (!res.destroyed) { res.writeHead(502); res.end(); } }
});
await new Promise<void>(done => proxy.listen(0, '127.0.0.1', done));
const port = (proxy.address() as { port: number }).port;
// Consumed privately by the parent harness; credentials never enter its report.
process.stdout.write(JSON.stringify({ base: `http://127.0.0.1:${port}`, token, otherToken, readOnlyToken,
  taskId: state.tasks[0].id, revision: state.revision }) + '\n');
let closing = false;
async function close() {
  if (closing) return; closing = true;
  proxy.closeAllConnections();
  await new Promise<void>(done => proxy.close(() => done()));
  await fixture.cleanup();
  process.exit(0);
}
process.stdin.resume(); process.stdin.on('end', () => { void close(); });
process.once('SIGTERM', () => { void close(); }); process.once('SIGINT', () => { void close(); });
