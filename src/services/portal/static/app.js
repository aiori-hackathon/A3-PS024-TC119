const names = { ip: 'IP baseline', 'type2-bearer': 'Ordinary Type 2', arc: 'ARC', 'type2-holder': 'Holder-bound Type 2' };
const clients = ['A', 'B', 'C', 'D', 'E'];
const $ = id => document.getElementById(id);
let status;
let csrfToken;
let busy = false;
let connected = false;
let loadingStatus = false;
let lastRevision;

function setText(id, value) { $(id).textContent = value ?? '—'; }
function count(value) { return Number.isSafeInteger(value) && value >= 0 ? String(value) : '—'; }
function time(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? '—' : date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
function announce(message) {
  setText('result', message);
  setText('announcement', message);
}
function clearResource() {
  setText('resource-state', 'Access required');
  setText('resource-text', 'The full brief appears after an authorized access.');
  setText('delivered-to', 'Through the verification gateway');
}
function updateControls() {
  const live = connected && status?.mode === 'live';
  const ready = live && !busy;
  const active = ready && status?.state === 'active' && (!status.window?.endsAt || Date.now() < Date.parse(status.window.endsAt));
  const ip = status?.profile === 'ip';
  const acquired = status?.clients?.find(item => item.clientId === $('client').value)?.allowanceAcquired === true;
  $('ip-limit').disabled = !ready || !['idle', 'expired'].includes(status?.state);
  $('client-limit').disabled = $('ip-limit').disabled;
  $('profiles').disabled = !ready || status?.state !== 'idle';
  $('start').disabled = !ready || !['idle', 'expired'].includes(status?.state);
  $('start').textContent = status?.state === 'expired' ? 'Start new window' : 'Start demo';
  $('reset').disabled = !ready || !['active', 'expired', 'error', 'uncertain'].includes(status?.state);
  $('client').disabled = !active;
  $('acquire').disabled = !active || ip || acquired;
  $('acquire').textContent = ip ? 'No tokens needed (IP)' : acquired ? 'Allowance acquired' : 'Acquire allowance';
  $('access').disabled = !active || (!ip && !acquired);
  $('request-count').disabled = $('access').disabled;
  $('send-requests').disabled = $('access').disabled;
  setText('acquire-help', ip ? 'IP needs no acquisition. Every client spends the same shared IP budget.'
    : acquired ? 'Existing credentials are ready. Acquisition cannot refill this window.' : 'Acquire allowance once for this client before sending requests.');
  $('compare').disabled = !ready || !['idle', 'active', 'expired'].includes(status?.state);
  $('theft').disabled = !ready || !['idle', 'active', 'expired'].includes(status?.state);
}
function renderWindow() {
  const end = Date.parse(status?.window?.endsAt ?? '');
  if (!Number.isFinite(end)) return;
  const left = Math.max(0, Math.ceil((end - Date.now()) / 1000));
  setText('window', left > 0
    ? `${status.window.label} · ${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')} left`
    : 'Allowance expired — stop the demo or explicitly start a new window.');
}
function renderClient() {
  const client = status?.clients?.find(item => item.clientId === $('client').value);
  setText('estimate', count(client?.estimatedUsesLeft));
  setText('client-state', client?.state ?? 'Awaiting run');
  updateControls();
}
function appendRow(body, values, header = false) {
  const row = document.createElement('tr');
  values.forEach((value, index) => {
    const cell = document.createElement(header && index === 0 ? 'th' : 'td');
    if (header && index === 0) cell.scope = 'row';
    cell.textContent = value;
    row.append(cell);
  });
  body.append(row);
}
function render(next) {
  if (!next || typeof next !== 'object') throw Error('status-invalid');
  if (lastRevision !== undefined && next.revision < lastRevision) return;
  if (lastRevision !== undefined && next.revision !== lastRevision) clearResource();
  lastRevision = next.revision;
  status = next;
  csrfToken = next.csrfToken ?? csrfToken;
  connected = true;
  setText('mode', next.mode === 'live' ? 'Supervised laboratory' : 'Layout preview');
  setText('connection', next.mode === 'live' ? 'Connected to the local controller' : 'Live client controls require a connected backend');
  setText('server-state', ({ expired: 'Allowance expired', expiring: 'Closing expired allowance' })[next.state] ?? next.state ?? 'Unknown');
  setText('active-profile', names[next.profile] ?? '—');
  setText('window', next.window?.endsAt ? `${next.window.label} · ends ${time(next.window.endsAt)}` : '—');
  setText('updated', time(next.observedAt));
  const body = $('clients-body');
  body.replaceChildren();
  for (const clientId of clients) {
    const client = next.clients?.find(item => item.clientId === clientId);
    appendRow(body, [`Client ${clientId}`, count(client?.estimatedUsesLeft), client?.state ?? 'Awaiting run'], true);
  }
  renderClient();
  const evidence = next.evidence;
  const observed = Boolean(evidence?.observedAt);
  setText('received', observed ? count(evidence.requestsReceived) : '—');
  setText('served', observed ? count(evidence.resourcesServed) : '—');
  setText('mismatches', observed ? count(evidence.generationMismatches) : '—');
  setText('evidence-time', time(evidence?.observedAt));
  setText('evidence-state', observed ? ({ verified: 'Verified aggregate snapshot', incomplete: 'Incomplete observation', mismatch: 'Generation mismatch observed' }[evidence.state] ?? 'Observed aggregate snapshot') : 'Awaiting an observed snapshot');
  const workers = evidence?.workerVerificationAttempts;
  const source = evidence?.sameSourceObserved === true ? 'Shared proxy source observed'
    : evidence?.sameSourceObserved === false ? 'Multiple sources observed' : 'Source observation pending';
  setText('gateway-evidence', Array.isArray(workers)
    ? `Gateway claims ${count(evidence.gatewayClaims)} · ${source} · Workers observed ${workers.filter(attempts => attempts > 0).length}/${workers.length}`
    : 'Awaiting an authenticated gateway observation.');
  const comparison = Array.isArray(next.comparison) ? next.comparison : [];
  $('comparison-body').replaceChildren();
  for (const profile of ['ip', 'type2-bearer', 'arc']) {
    const item = comparison.find(row => row.profile === profile);
    appendRow($('comparison-body'), [names[profile], item?.state ?? 'Unobserved', count(item?.accepted), count(item?.denied), count(item?.honestDelivered), count(item?.originArrivals), count(item?.issuanceBytes), count(item?.issuanceInteractions), typeof item?.latencyMs === 'number' && item.latencyMs >= 0 ? item.latencyMs.toFixed(1) : '—'], true);
  }
  setText('comparison-state', comparison.length ? 'Latest observed comparison' : 'No comparison observed');
  const theft = next.theftScene;
  setText('active-limit', next.rateLimit ? `Enforced limit: ${next.rateLimit.limit} accepted requests per ${next.rateLimit.scope} in this window. Changing a field applies only to a new window.` : 'No active rate limit.');
  $('request-history').replaceChildren();
  for (const row of next.requestHistory ?? []) appendRow($('request-history'), [
    `Client ${row.clientId}`, count(row.attempts), count(row.accepted), count(row.refused), count(row.originArrivals), row.evidenceState,
  ]);
  setText('bearer-outcome', 'Separate bearer theft experiment pending');
  setText('holder-outcome', theft?.holderOutcome ?? 'Awaiting experiment');
  setText('theft-origin', theft ? `${theft.state ?? 'Observed'} · Attack arrivals ${count(theft.attackOriginArrivals)} · Owner arrivals ${count(theft.ownerOriginArrivals)}` : 'Awaiting experiment');
  updateControls();
  renderWindow();
}
async function loadStatus() {
  if (loadingStatus) return;
  loadingStatus = true;
  try {
    const response = await fetch('/api/status', { cache: 'no-store' });
    if (!response.ok) throw Error('status-unavailable');
    render(await response.json());
  } catch {
    connected = false;
    setText('connection', 'Controller status unavailable. Actions are paused.');
    setText('server-state', 'Unconfirmed');
    updateControls();
  } finally { loadingStatus = false; }
}
function delay(milliseconds) { return new Promise(resolve => setTimeout(resolve, milliseconds)); }
async function execute(command, pendingLabel) {
  if (busy || !connected) return;
  if (['access', 'send_requests'].includes(command.action)) clearResource();
  busy = true;
  updateControls();
  announce(pendingLabel);
  try {
    const response = await fetch('/api/command', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
      body: JSON.stringify(command),
    });
    if (!response.ok) {
      const labels = { 400: 'The command was rejected. Refresh status before continuing.', 403: 'The browser session needs a fresh status check.', 409: 'Another operation is still running. Wait for its result.', 503: 'The laboratory is unavailable.' };
      announce(labels[response.status] ?? 'The command was rejected by the portal.');
      return;
    }
    const operation = await response.json();
    if (!/^[a-f0-9]{48}$/.test(operation.operationId)) throw Error('operation-invalid');
    for (;;) {
      await delay(700);
      const resultResponse = await fetch(`/api/operations/${operation.operationId}`, { cache: 'no-store' });
      if (!resultResponse.ok) throw Error('operation-unavailable');
      const operationStatus = await resultResponse.json();
      if (operationStatus.state === 'pending') continue;
      const result = operationStatus.result ?? {};
      if (result.status) render({ ...result.status, mode: 'live' });
      const labels = { delivered: 'The protected resource was delivered.', refused: 'The gateway refused this request.', uncertain: 'The operation outcome is uncertain.', started: 'The run is active.', reset: 'The demo was stopped.', 'comparison-complete': 'The comparison completed.', 'theft-complete': 'The theft scene completed.', unavailable: 'The laboratory is unavailable.', 'operation-uncertain': 'The operation could not be confirmed.' };
      announce(result.message ?? labels[result.outcome] ?? 'The operation completed. Review the server state and evidence.');
      if (['access', 'send_requests'].includes(command.action) && status.revision === command.revision && result.authorizedAccess?.clientId === command.clientId && typeof result.authorizedAccess.text === 'string') {
        setText('resource-text', result.authorizedAccess.text);
        setText('resource-state', 'Delivered previously');
        setText('delivered-to', `Delivered to Client ${command.clientId}`);
      }
      break;
    }
  } catch {
    announce('The operation outcome is unconfirmed. Check the server state before another action. The request has not been retried.');
  } finally {
    busy = false;
    await loadStatus();
    updateControls();
  }
}
$('client').addEventListener('change', renderClient);
$('start').addEventListener('click', () => {
  const profile = document.querySelector('input[name="profile"]:checked').value;
  return execute({ action: 'start_run', profile, limit: Number($(profile === 'ip' ? 'ip-limit' : 'client-limit').value) }, 'Starting a supervised run…');
});
$('reset').addEventListener('click', () => execute({ action: 'reset_run', revision: status.revision }, 'Closing and resetting the run…'));
$('acquire').addEventListener('click', () => execute({ action: 'acquire', clientId: $('client').value, revision: status.revision }, `Acquiring allowance for Client ${$('client').value}…`));
$('access').addEventListener('click', () => execute({ action: 'access', clientId: $('client').value, revision: status.revision }, `Requesting the resource for Client ${$('client').value}…`));
$('send-requests').addEventListener('click', () => execute({ action: 'send_requests', clientId: $('client').value,
  count: Number($('request-count').value), revision: status.revision }, `Sending requests from Client ${$('client').value}…`));
$('compare').addEventListener('click', () => execute({ action: 'run_comparison', revision: status.revision }, 'Running the controlled comparison…'));
$('theft').addEventListener('click', () => execute({ action: 'run_theft_scene', revision: status.revision }, 'Running the separate theft scene…'));
await loadStatus();
setInterval(loadStatus, 3000);
setInterval(() => { renderWindow(); updateControls(); }, 1000);
