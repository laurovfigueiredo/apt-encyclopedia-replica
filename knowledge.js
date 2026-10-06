/* ------------------------------------------------------------------
   knowledge.js — the purple-team half of the Control Validation Compass.

   Four features, all client-side over two pre-parsed datasets:

   1. TTP Research Knowledge Center  (technique_pages.json, 578 techniques)
        Policy / Process Controls   -> MITRE D3FEND mappings
        Technical Controls          -> CAR, Sigma, Splunk, Elastic, Sentinel
        Offensive Security Tests    -> Atomic Red Team, CAR, Stratus Red Team

   2. Lookup by Controls            (controls.json, 578 x 27 provider matrix)
        Tick the providers you run; the matrix aligns attacker techniques
        to the counts available in each selected provider.

   3. Threat Alignment Risk Workflow
        Intersect the adversary scope of the threat model with the control
        stack to expose technique-level gaps.

   4. Knowledge Center — general reference material.
------------------------------------------------------------------- */

/* provider key -> [label, group, subgroup]   groups mirror controls.html */
const PROVIDERS = [
  ['mitigations', 'MITRE ATT&CK Mitigations', 'Policy/Process Controls', 'Frameworks'],
  ['nist', 'NIST 800-53 Mappings', 'Policy/Process Controls', 'Frameworks'],
  ['cis', 'CIS Controls', 'Policy/Process Controls', 'Frameworks'],
  ['d3fend', 'MITRE D3FEND', 'Policy/Process Controls', 'Frameworks'],
  ['engage', 'MITRE Engage', 'Policy/Process Controls', 'Frameworks'],

  ['splunk', 'Splunk', 'Defensive Capabilities', 'Native controls'],
  ['splunk_threatHunting', 'Threat Hunting Splunk App', 'Defensive Capabilities', 'Native controls'],
  ['elastic', 'Elastic Stack', 'Defensive Capabilities', 'Native controls'],
  ['eql_analytics', 'EQL Analytics Library', 'Defensive Capabilities', 'Native controls'],
  ['sentinel_defender', 'Microsoft Sentinel & Defender (Unified)', 'Defensive Capabilities', 'Native controls'],
  ['azure_sentinel', 'Sentinel detection mappings', 'Defensive Capabilities', 'Native controls'],
  ['logpoint', 'LogPoint', 'Defensive Capabilities', 'Native controls'],

  ['car', 'Cyber Analytics Repository', 'Defensive Capabilities', 'Third-party rule repositories'],
  ['atc', 'Atomic Threat Coverage', 'Defensive Capabilities', 'Third-party rule repositories'],
  ['sigma', 'Sigma rules public repository', 'Defensive Capabilities', 'Third-party rule repositories'],
  ['th_playbook', 'ThreatHunter Playbook', 'Defensive Capabilities', 'Third-party rule repositories'],
  ['proofpoint_emergingThreats', 'Network Security Monitoring rule mappings', 'Defensive Capabilities', 'Network telemetry'],
  ['tanium_threatResponse', 'Tanium Threat Response', 'Defensive Capabilities', 'Endpoint telemetry'],
  ['azure_fullStack', 'Azure full stack mappings', 'Defensive Capabilities', 'Cloud'],
  ['aws', 'AWS security control mappings', 'Defensive Capabilities', 'Cloud'],
  ['gcp', 'GCP Community Security Analytics', 'Defensive Capabilities', 'Cloud'],

  ['art', 'Atomic Red Team', 'Offensive Capabilities', ''],
  ['car_red', 'Cyber Analytics Repository', 'Offensive Capabilities', ''],
  ['rta', 'Red Team Automation', 'Offensive Capabilities', ''],
  ['prelude', 'Prelude Community TTPs', 'Offensive Capabilities', ''],
  ['stockpile', 'CALDERA Stockpile', 'Offensive Capabilities', ''],
  ['scythe', 'Scythe', 'Offensive Capabilities', ''],
];

const POLICY_KEYS = new Set(['mitigations', 'nist', 'cis', 'd3fend', 'engage']);
const TEST_KEYS = new Set(['art', 'car_red', 'rta', 'prelude', 'stockpile', 'scythe']);

/* section order in the original knowledge pages */
const SECTION_ORDER = [
  'Policy / Process Controls',
  'Technical Controls (Detection Rules)',
  'Offensive Security Tests',
];
const SECTION_NOTE = {
  'Policy / Process Controls': 'Defensive and hardening measures mapped to this technique. These reduce the likelihood or impact of the technique succeeding.',
  'Technical Controls (Detection Rules)': 'Detection content you can deploy today to alert on this technique.',
  'Offensive Security Tests': 'Executable tests that emulate the technique, to validate that your controls actually detect it.',
};

const KNOW = {
  index: [],            // technique_index.json -- eager, powers the list
  details: new Map(),   // technique_pages.json  -- lazy, one entry per modal
  detailPromise: null,
  byId: new Map(),      // index lookup, id -> index row
  matrix: [],            // controls.json rows
  matrixById: new Map(),
  pIndex: new Map(),     // provider key -> column index
  sel: new Set(),        // ticked providers
  tactics: new Set(),    // ticked tactics
  lowestOnly: false,     // "lowest-level techniques only"
  sort: { dir: 'desc', key: 'total' },
  pageLimit: 120,
};

const NUM = (n) => (n || 0).toLocaleString('en-US');

function providerMeta(key) {
  const row = PROVIDERS.find((p) => p[0] === key);
  return { key, label: row?.[1] || key, group: row?.[2] || '', sub: row?.[3] || '' };
}

/* ---------------- load ---------------- */
function initKnowledge(index, ctrl) {
  KNOW.index = index;
  index.forEach((p) => KNOW.byId.set(p.id, p));

  KNOW.matrix = ctrl.techniques;
  KNOW.matrix.forEach((t) => KNOW.matrixById.set(t.id, t));
  ctrl.providers.forEach((k, i) => KNOW.pIndex.set(k, i));

  // default stack: D3FEND + Sigma + Splunk + Atomic Red Team (the purple-team core)
  ['d3fend', 'sigma', 'splunk', 'art'].forEach((k) => KNOW.sel.add(k));

  renderProviderBoxes();
  renderKnowledgeList();
  renderKnowledgeStats();
  renderMatrix();
  renderResources();
  loadGuide();
  (async ()=>{try{const r=await fetch("data/last_update.txt"); if(r.ok){const t=await r.text().trim(); const el=$("#last-updated"); if(el) el.textContent=t;}}catch(e){}})();
}

/* ---------------- 1. TTP Research Knowledge Center ---------------- */
const S_POLICY = 'Policy / Process Controls';
const S_DETECT = 'Technical Controls (Detection Rules)';
const S_TEST = 'Offensive Security Tests';

function knowledgeSearch() {
  const q = ($('#kn-q')?.value || '').trim().toLowerCase();
  const tac = $('#kn-tactic')?.value || '';
  const only = $('#kn-has')?.value || '';

  return KNOW.index.filter((p) => {
    if (tac && !(p.tactics || []).includes(tac)) return false;
    if (q) {
      const hay = `${p.id} ${p.name} ${(p.tactics || []).join(' ')} ${p.desc || ''}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    const n = p.n || {};
    if (only === 'detection' && !(n[S_DETECT] > 0)) return false;
    if (only === 'test' && !(n[S_TEST] > 0)) return false;
    if (only === 'policy' && !(n[S_POLICY] > 0)) return false;
    if (only === 'none' && Object.keys(n).length) return false;
    return true;
  }).sort((a, b) => a.id.localeCompare(b.id, undefined, { numeric: true }));
}

/* the 2.7 MB detail payload is only needed once a technique is opened */
function loadDetails() {
  if (KNOW.detailPromise) return KNOW.detailPromise;
  KNOW.detailPromise = fetch('data/technique_pages.json')
    .then((r) => {
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.json();
    })
    .then((pages) => {
      pages.forEach((p) => KNOW.details.set(p.id, p));
      return KNOW.details;
    });
  return KNOW.detailPromise;
}

function renderKnowledgeList() {
  const res = knowledgeSearch();
  const box = $('#kn-list');
  const count = $('#kn-count');
  if (!box || !count) return;
  count.textContent = `(${res.length})`;
  if (!res.length) { box.innerHTML = '<p class="muted">No techniques match the filters.</p>'; return; }

  box.innerHTML = res.slice(0, KNOW.pageLimit).map((p) => {
    const [pol, det, tst] = p.c || [0, 0, 0];
    const used = !!CVC.some((x) => (x.ttps || []).includes(p.id));
    return `<article class="card clickable kn-card" data-tech="${esc(p.id)}">
      <h3><span class="mono">${esc(p.id)}</span> ${esc(p.name)}</h3>
      <div class="meta">${(p.tactics || []).map((t) => esc(t)).join(' · ') || '—'}</div>
      <div class="badges">
        ${pol ? `<span class="badge">${pol} policy</span>` : ''}
        ${det ? `<span class="badge">${det} detection</span>` : ''}
        ${tst ? `<span class="badge">${tst} test${tst === 1 ? '' : 's'}</span>` : ''}
        ${!pol && !det && !tst ? '<span class="badge">no mapped content</span>' : ''}
        ${used ? '<span class="badge badge-medium">in our adversary set</span>' : ''}
      </div>
      ${p.desc ? `<div class="tech clamp" style="margin-top:8px">${esc(p.desc)}</div>` : ''}
    </article>`;
  }).join('') + (res.length > KNOW.pageLimit
    ? `<p class="muted" style="text-align:center;padding:12px">showing ${KNOW.pageLimit} of ${res.length} — refine the search to narrow it down</p>`
    : '');
}

function renderKnowledgeStats() {
  const el = $('#kn-stats');
  if (!el) return;
  let pol = 0, det = 0, tst = 0;
  KNOW.index.forEach((p) => {
    const c = p.c || [0, 0, 0];
    pol += c[0]; det += c[1]; tst += c[2];
  });
  const items = pol + det + tst;
  el.innerHTML = `
    <div class="card stat"><div class="meta">Techniques documented</div><div class="stat-num">${KNOW.index.length}</div></div>
    <div class="card stat"><div class="meta">Mapped resources</div><div class="stat-num">${NUM(items)}</div></div>
    <div class="card stat"><div class="meta">Detection rules</div><div class="stat-num">${NUM(det)}</div></div>
    <div class="card stat"><div class="meta">Offensive tests</div><div class="stat-num">${NUM(tst)}</div></div>`;
}

function providerBlock(b) {
  const items = b.items || [];
  const body = items.length ? items.map((it) => `<li>${it.url
    ? `<a href="${esc(it.url)}" target="_blank" rel="noopener">${esc(it.name)}</a>`
    : esc(it.name)}${it.tests ? ` <span class="muted">· ${it.tests} unit test${it.tests === 1 ? '' : 's'}</span>` : ''}</li>`
  ).join('') : '<li class="muted">No individual entries listed.</li>';

  return `<div class="card kn-provider">
    <div class="row-main">
      <div class="row-title">${b.url
    ? `<a href="${esc(b.url)}" target="_blank" rel="noopener">${esc(b.name)}</a>`
    : esc(b.name)}</div>
      <div class="tech">
        ${b.forThis ?? 0} mapped to this ${esc(b.kind || 'resource')}${b.kind ? (b.kind === 'resources' ? '' : b.kind) : ''}
        ${b.totalMapped ? ` · ${NUM(b.totalMapped)} total across all of ATT&amp;CK` : ''}
        ${b.lastAccessed ? ` · last accessed ${esc(b.lastAccessed)}` : ''}
      </div>
    </div>
    ${b.fileUrl ? `<div class="row-actions"><a class="btn btn-ghost" href="${esc(b.fileUrl)}" target="_blank" rel="noopener">File ↗</a></div>` : ''}
    <ul class="kn-items">${body}</ul>
  </div>`;
}

async function openTechnique(id) {
  if (!KNOW.byId.has(id)) return;
  let p = KNOW.details.get(id);
  if (!p) {
    $('#modal-body').innerHTML = `<h2><span class="mono">${esc(id)}</span></h2>
      <p class="tech">loading mapped controls, detections and tests…</p>`;
    $('#modal').classList.add('open');
    document.body.style.overflow = 'hidden';
    try {
      await loadDetails();
    } catch (e) {
      $('#modal-body').innerHTML = `<h2><span class="mono">${esc(id)}</span></h2>
        <p class="tag-warn">Could not load the technique details: ${esc(e.message)}</p>`;
      return;
    }
    p = KNOW.details.get(id);
  }
  if (!p) return;
  const m = KNOW.matrixById.get(id);

  const sections = SECTION_ORDER.filter((s) => (p.sections[s] || []).length)
    .map((s) => `<h3 class="mt">${esc(s)}</h3>
      <p class="tech">${esc(SECTION_NOTE[s])}</p>
      <div class="kn-grid">${p.sections[s].map(providerBlock).join('')}</div>`)
    .join('');

  const ours = CVC.filter((x) => (x.ttps || []).includes(id));
  const actors = TECHS.find((t) => t.id === id);

  $('#modal-body').innerHTML = `
    <h2><span class="mono">${esc(p.id)}</span> ${esc(p.name)}</h2>
    <div class="badges">
      ${(p.tactics || []).map((t) => `<span class="badge">${esc(t)}</span>`).join('')}
      ${m && m.level === 'y' ? '<span class="badge">lowest level</span>' : ''}
      <a class="badge" href="${esc(p.url)}" target="_blank" rel="noopener">attack.mitre.org ↗</a>
    </div>
    ${p.description ? `<p class="prose">${esc(p.description)}</p>` : ''}

    ${m ? `<div class="toolbar">
      ${[['Policy/process', m.scores[0]], ['Detection rules', m.scores[1]],
      ['Offensive tests', m.scores[2]], ['Combined', m.scores[3]]]
      .map(([k, v]) => `<span class="badge">${k}: ${v}</span>`).join('')}
    </div>` : ''}

    ${actors ? `<p class="tech">ATT&amp;CK: ${esc(actors.tactic || (actors.tactics || []).join(', '))}
      ${actors.isSubtechnique === false ? '· parent technique' : ''}</p>` : ''}

    ${ours.length ? `<h3 class="mt">Used by ${ours.length} adversar${ours.length === 1 ? 'y' : 'ies'} in this encyclopedia</h3>
      <div class="badges">${ours.slice(0, 40).map((x) => `<span class="badge">${esc(x.name)}</span>`).join('')}</div>` : ''}

    ${sections || '<p class="muted" style="margin-top:20px">No mapped resources for this technique.</p>'}

    ${p.refs?.length ? `<h3 class="mt">Related techniques referenced in this description</h3>
      <div class="badges">${p.refs.map((r) => {
    const t = KNOW.byId.get(r);
    return `<button class="badge" data-goto="${esc(r)}">${esc(r)}${t ? ` · ${esc(t.name)}` : ''}</button>`;
  }).join('')}</div>` : ''}
  `;
  $('#modal').classList.add('open');
  document.body.style.overflow = 'hidden';

  $$('#modal-body [data-goto]').forEach((b) =>
    b.addEventListener('click', () => openTechnique(b.dataset.goto)));
}

/* ---------------- 2. Lookup by Controls ---------------- */
function renderProviderBoxes() {
  const box = $('#ctl-providers');
  if (!box) return;
  const groups = [];
  PROVIDERS.forEach(([key, label, group, sub]) => {
    let g = groups.find((x) => x.name === group);
    if (!g) { g = { name: group, subs: [] }; groups.push(g); }
    let s = g.subs.find((x) => x.name === sub);
    if (!s) { s = { name: sub, items: [] }; g.subs.push(s); }
    s.items.push({ key, label });
  });

  box.innerHTML = groups.map((g) => `<div class="ctl-group">
    <h4>${esc(g.name)}</h4>
    ${g.subs.map((s) => `<div class="ctl-sub">
      ${s.name ? `<div class="ctl-subname">${esc(s.name)}</div>` : ''}
      <div class="chips">
        ${s.items.map((i) => `<label class="chip" data-pkey="${esc(i.key)}">
          <input type="checkbox" data-provider="${esc(i.key)}" ${KNOW.sel.has(i.key) ? 'checked' : ''}>
          <span>${esc(i.label)}</span>
          <span class="chip-count" data-count="${esc(i.key)}"></span>
        </label>`).join('')}
      </div>
    </div>`).join('')}
  </div>`).join('');

  refreshProviderCounts();
}

function providerTotals() {
  const totals = new Array(KNOW.matrix.length ? Math.max(...KNOW.matrix.map((t) => t.v.length)) : 0).fill(0);
  KNOW.matrix.forEach((t) => t.v.forEach((v, i) => { if (v) totals[i] += v; }));
  const out = new Map();
  PROVIDERS.forEach(([key]) => {
    const i = KNOW.pIndex.get(key);
    out.set(key, (i === undefined ? 0 : totals[i]) || 0);
  });
  return out;
}

function refreshProviderCounts() {
  const totals = providerTotals();
  $$('#ctl-providers .chip-count').forEach((el) => {
    const n = totals.get(el.dataset.count) || 0;
    el.textContent = n ? NUM(n) : '0';
  });
}

/* rows passing the current provider / tactic / level filters */
function matrixRows() {
  const cols = [...KNOW.sel].map((k) => KNOW.pIndex.get(k)).filter((i) => i !== undefined);
  let rows = KNOW.matrix;

  // with nothing ticked there is no alignment to show at all
  if (!cols.length) return [];
  if (KNOW.lowestOnly) rows = rows.filter((t) => t.level === 'y');
  if (KNOW.tactics.size) {
    rows = rows.filter((t) => (t.tactics || '').split(/,\s*/).some((x) => KNOW.tactics.has(x)));
  }
  rows = rows.filter((t) => cols.some((i) => t.v[i]));
  return rows;
}

/* coverage of a technique under the current provider selection */
function coverage(t) {
  const sel = [...KNOW.sel];
  let policy = 0, detect = 0, test = 0, total = 0;
  sel.forEach((k) => {
    const i = KNOW.pIndex.get(k);
    const v = t.v[i] || 0;
    total += v;
    if (POLICY_KEYS.has(k)) policy += v;
    else if (TEST_KEYS.has(k)) test += v;
    else detect += v;
  });
  return { policy, detect, test, total };
}

const SORT_KEYS = {
  policy: (c) => c.policy,
  detect: (c) => c.detect,
  test: (c) => c.test,
  total: (c) => c.total,
  id: (c) => c.id,
};

function renderMatrix() {
  const box = $('#ctl-out');
  const head = $('#ctl-head');
  if (!box || !head) return;

  const sel = [...KNOW.sel].map((k) => {
    const m = providerMeta(k);
    return `<span class="badge">${esc(m.label)}</span>`;
  });

  head.innerHTML = sel.length
    ? `<div class="meta">Control stack: ${sel.join(' ')}</div>`
    : '<div class="meta tag-warn">no providers selected — tick the capabilities you run</div>';

  let rows = matrixRows().map((t) => ({ t, c: coverage(t) }));
  const { dir, key } = KNOW.sort;
  const sign = dir === 'asc' ? 1 : -1;
  rows.sort((a, b) => {
    const av = SORT_KEYS[key](a.c), bv = SORT_KEYS[key](b.c);
    if (typeof av === 'string') return sign * av.localeCompare(bv);
    return sign * (av - bv) || a.t.id.localeCompare(b.t.id);
  });

  const shown = rows.slice(0, KNOW.pageLimit);
  $('#ctl-summary').textContent = `${rows.length} technique${rows.length === 1 ? '' : 's'} aligned · ${shown.length} shown`;

  if (!rows.length) {
    box.innerHTML = '<p class="muted">No techniques match — the selection has no coverage.</p>';
    return;
  }

  box.innerHTML = `<table class="ctl-table">
    <thead><tr>
      <th>Technique</th>
      <th class="num">Policy/Process</th>
      <th class="num">Rules</th>
      <th class="num">Tests</th>
      <th class="num">Total</th>
      <th class="num">Gap</th>
    </tr></thead>
    <tbody>${shown.map(({ t, c }) => `<tr data-tech="${esc(t.id)}">
      <td><span class="mono">${esc(t.id)}</span> ${esc(t.name)}
        <div class="tech">${esc(t.tactics || '')}</div></td>
      <td class="num">${c.policy || '<span class="muted">—</span>'}</td>
      <td class="num">${c.detect || '<span class="muted">—</span>'}</td>
      <td class="num">${c.test || '<span class="muted">—</span>'}</td>
      <td class="num"><b>${c.total}</b></td>
      <td class="num">${c.total ? '' : '<span class="tag-warn">gap</span>'}</td>
    </tr>`).join('')}</tbody>
  </table>
  ${rows.length > shown.length ? `<p class="muted" style="text-align:center;padding:10px">showing ${shown.length} of ${rows.length}</p>` : ''}`;
}

/* ---------------- 3. Threat Alignment Risk Workflow ---------------- */
function renderRisk() {
  const box = $('#risk-out');
  const sum = $('#risk-summary');
  if (!box || !sum) return;

  // scope comes straight from the threat model above
  const { adversaries, name } = currentScope();
  const techs = [...tally(adversaries).keys()];

  const sel = [...KNOW.sel];
  const withCov = [], gaps = [];
  techs.forEach((id) => {
    const m = KNOW.matrixById.get(id);
    if (!m) return;
    const c = coverage(m);
    (c.total ? withCov : gaps).push({ id, m, c });
  });
  const unknown = techs.filter((id) => !KNOW.matrixById.has(id));

  const total = techs.length;
  const pct = total ? Math.round((withCov.length / total) * 100) : 0;

  sum.innerHTML = `<div class="stats-bar">
    <div class="card stat"><div class="meta">Threat model scope</div><div class="stat-num" style="font-size:18px">${esc(name)}</div>
      <div class="tech">${adversaries.length} adversar${adversaries.length === 1 ? 'y' : 'ies'}</div></div>
    <div class="card stat"><div class="meta">Techniques in scope</div><div class="stat-num">${total}</div></div>
    <div class="card stat"><div class="meta">Covered by your stack</div><div class="stat-num">${withCov.length}</div></div>
    <div class="card stat"><div class="meta">Detection gaps</div><div class="stat-num" style="color:var(--cv-red)">${gaps.length}</div></div>
    <div class="card stat"><div class="meta">Coverage</div><div class="stat-num">${pct}%</div></div>
  </div>`;

  const row = ({ id, m, c }) => `<tr data-tech="${esc(id)}">
    <td><span class="mono">${esc(id)}</span> ${esc(m.name)}</td>
    <td class="num">${c.policy || '—'}</td>
    <td class="num">${c.detect || '—'}</td>
    <td class="num">${c.test || '—'}</td>
    <td>${c.total ? '<span class="tag-ok">covered</span>' : '<span class="tag-warn">gap</span>'}</td>
  </tr>`;

  box.innerHTML = `
    ${gaps.length ? `<h3>Detection gaps <span class="muted">(${gaps.length})</span></h3>
      <p class="tech">Techniques used by this threat model with no coverage in the selected control stack. Pick a provider above to close them.</p>
      <table class="ctl-table"><thead><tr><th>Technique</th><th class="num">Policy</th><th class="num">Rules</th><th class="num">Tests</th><th>Status</th></tr></thead>
      <tbody>${gaps.map(row).join('')}</tbody></table>` : ''}

    ${withCov.length ? `<h3 class="mt">Covered <span class="muted">(${withCov.length})</span></h3>
      <table class="ctl-table"><thead><tr><th>Technique</th><th class="num">Policy</th><th class="num">Rules</th><th class="num">Tests</th><th>Status</th></tr></thead>
      <tbody>${withCov.map(row).join('')}</tbody></table>` : ''}

    ${!total ? '<p class="muted">Select a threat model scope above to align it against your control stack.</p>' : ''}
    ${unknown.length ? `<p class="tech" style="margin-top:14px">${unknown.length} technique${unknown.length === 1 ? '' : 's'} in scope are not in the Control Validation Compass dataset: ${unknown.slice(0, 12).map((t) => `<span class="badge">${esc(t)}</span>`).join(' ')}</p>` : ''}`;
}

/* ---------------- 4. Knowledge Center ---------------- */

function linkify(text) {
  if (!text) return '';
  return esc(text).replace(/\[\[([^|\]]*)\|([^\]]+)\]\]/g,
    (_, label, href) => `<a href="${href}" target="_blank" rel="noopener">${label}</a>`);
}

const GUIDE = { data: null, promise: null };

function loadGuide() {
  if (GUIDE.promise) return GUIDE.promise;
  GUIDE.promise = fetch('data/resources_guide.json')
    .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
    .then((g) => { GUIDE.data = g; renderGuide(g); return g; })
    .catch((e) => { const box = $('#res-guide'); if (box) box.innerHTML = `<p class="tag-warn">Could not load: ${esc(e.message)}</p>`; throw e; });
  return GUIDE.promise;
}

const RESOURCES = [
  ['MITRE ATT&CK', 'Knowledge base of adversary tactics and techniques derived from real-world observations.', 'https://attack.mitre.org/'],
  ['MITRE D3FEND', 'Countermeasure knowledge base — a defensive counterpart to ATT&CK, indexed by technique.', 'https://d3fend.mitre.org/'],
  ['MITRE Engage', 'Engagement procedures for interacting with adversaries during response.', 'https://engage.mitre.org/'],
  ['MITRE Engage Matrix', 'Prepare, Expose, Affect and Respond — a planning framework for adversary engagement.', 'https://engage.mitre.org/stengage/'],
  ['Sigma', 'Generic signature format for SIEM systems; the de-facto standard for portable detection rules.', 'https://github.com/SigmaHQ/sigma'],
  ['Cyber Analytics Repository', 'Analytics and detection artifacts published by MITRE ATT&CK.', 'https://car.mitre.org'],
  ['Atomic Red Team', 'Executable test library mapped to ATT&CK, used to validate detection coverage.', 'https://github.com/redcanaryco/atomic-red-team'],
  ['Stratus Red Team', 'Cloud-focused adversary emulation for AWS, Azure and GCP.', 'https://github.com/redcanaryco/stratus-red-team'],
  ['Red Team Automation', 'Framework for automating adversary emulation and detection testing.', 'https://github.com/swimlane/redteam-automation'],
  ['CALDERA', 'Adversary emulation and command-and-control framework with a large Stockpile of TTPs.', 'https://github.com/mitre/caldera'],
  ['Prelude', 'Operator-first security automation for running adversary emulation locally.', 'https://docs.preludesecurity.com/'],
  ['Scythe', 'Security assessment and red teaming automation framework.', 'https://scythe.io/'],
  ['NIST SP 800-53', 'Security and privacy control catalogue the Compass maps techniques against.', 'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final'],
  ['CIS Controls', 'Prioritised safeguards for effective cyber defence.', 'https://www.cisecurity.org/controls'],
  ['Splunk Security Content', 'Analytic stories and detections for Splunk.', 'https://github.com/splunk/security_content'],
  ['Elastic Detection Rules', 'Detection rules and EQL analytics for Elastic Security.', 'https://github.com/elastic/detection-rules'],
  ['Microsoft Sentinel & Defender', 'Detection mappings and hunting queries across the Microsoft stack.', 'https://github.com/Azure/Azure-Sentinel'],
  ['Tanium Threat Response', 'Endpoint telemetry and response mappings.', 'https://www.tanium.com/'],
  ['Cyllex Encyclopedia', 'Adversary profiles and categorised threat intelligence behind this SPA.', 'https://cyllex.io/encyclopedia'],
  ['ETDA Threat Landscape', 'Public adversary profiles used for the profile metadata in this tool.', 'https://malpedia.caad.fkie.fraunhofer.de/'],
  ['Categorized Adversary TTPs', 'The unique, extensive collection of adversary TTP intelligence behind the category filters above.', 'https://github.com/tropChaud/Categorized-Adversary-TTPs'],
  ['Cyber Adversary Heatmaps', 'Library of recent adversary TTP intelligence heatmaps and their source content.', 'https://github.com/tropChaud/Cyber-Adversary-Heatmaps'],
  ['page2attack', 'Handy script to generate TTP heatmap files from open-source intel reports.', 'https://github.com/tropChaud/webpage2attack'],
  ['Control Validation Compass', 'The upstream project this purple-team layer is derived from.', 'https://github.com/ControlCompass/ControlCompass.github.io'],
  ['Feature tutorial', 'Walkthrough of the threat-model workflow, as published by the Compass authors.', 'https://youtu.be/fcFN1wxaihA'],
];

function renderResources() {
  const box = $('#res-list');
  if (!box) return;
  box.innerHTML = RESOURCES.map(([name, desc, url]) => `<a class="card res-card" href="${esc(url)}" target="_blank" rel="noopener">
    <h3>${esc(name)} ↗</h3>
    <p class="tech">${esc(desc)}</p>
  </a>`).join('');
}

/* ---------------- events ---------------- */
function bindKnowledge() {
  ['#kn-q', '#kn-tactic', '#kn-has'].forEach((s) => {
    const el = $(s);
    if (!el) return;
    el.addEventListener(el.tagName === 'SELECT' ? 'change' : 'input', () => {
      KNOW.pageLimit = 120;
      renderKnowledgeList();
    });
  });
  const knList = $('#kn-list');
  if (knList) {
    knList.addEventListener('click', (e) => {
      const c = e.target.closest('[data-tech]');
      if (c) openTechnique(c.dataset.tech);
    });
  }

  const prov = $('#ctl-providers');
  if (prov) {
    prov.addEventListener('change', (e) => {
      const k = e.target.dataset.provider;
      if (!k) return;
      e.target.checked ? KNOW.sel.add(k) : KNOW.sel.delete(k);
      renderMatrix();
      renderRisk();
    });
  }
  $('#ctl-check').addEventListener('click', () => {
    PROVIDERS.forEach(([k]) => KNOW.sel.add(k));
    syncProviderBoxes(); renderMatrix(); renderRisk();
  });
  $('#ctl-uncheck').addEventListener('click', () => {
    KNOW.sel.clear();
    syncProviderBoxes(); renderMatrix(); renderRisk();
  });
  $('#ctl-apply').addEventListener('click', () => { renderMatrix(); renderRisk(); });
  $('#ctl-lowest').addEventListener('change', (e) => {
    KNOW.lowestOnly = e.target.checked;
    renderMatrix();
  });
  $('#ctl-tactics').addEventListener('change', (e) => {
    const t = e.target.value;
    e.target.checked ? KNOW.tactics.add(t) : KNOW.tactics.delete(t);
    renderMatrix();
  });
  $$('#ctl-sorts button').forEach((b) => b.addEventListener('click', () => {
    const [dir, key] = b.dataset.sort.split(':');
    if (KNOW.sort.key === key) KNOW.sort.dir = KNOW.sort.dir === 'asc' ? 'desc' : 'asc';
    else { KNOW.sort.dir = dir; KNOW.sort.key = key; }
    $$('#ctl-sorts button').forEach((x) => x.classList.toggle('active', x === b));
    renderMatrix();
  }));

  ['#ctl-out', '#risk-out'].forEach((s) => {
    const el = $(s);
    if (!el) return;
    el.addEventListener('click', (e) => {
      const tr = e.target.closest('[data-tech]');
      if (tr) openTechnique(tr.dataset.tech);
    });
  });

  $('#risk-trickbot').addEventListener('click', async () => {
    const btn = $('#risk-trickbot');
    btn.disabled = true;
    try {
      if (!HEATMAP.example) {
        const layer = await (await fetch('data/intel/trickbot.json')).json();
        HEATMAP.example = {
          name: layer.name || 'TrickBot',
          layer,
          techniques: [...new Set((layer.techniques || []).map((t) => t.techniqueID))],
        };
      }
      $('#hm-scope').value = 'example';
      $('#hm-category').value = '';
      renderHeatmap();
      renderRisk();
      $('#risk-out').scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (e) {
      $('#risk-summary').innerHTML = `<p class="tag-warn">Could not load the example layer: ${esc(e.message)}</p>`;
    } finally {
      btn.disabled = false;
    }
  });
}

function syncProviderBoxes() {
  $$('#ctl-providers input[data-provider]').forEach((i) => {
    i.checked = KNOW.sel.has(i.dataset.provider);
  });
}

function buildTacticFilters() {
  const box = $('#ctl-tactics');
  if (!box) return;
  const tactics = uniq(KNOW.matrix.flatMap((t) => (t.tactics || '').split(/,\s*/)).filter(Boolean));
  box.innerHTML = tactics.map((t) => `<label class="chip">
    <input type="checkbox" value="${esc(t)}"><span>${esc(t)}</span></label>`).join('');
}

function buildKnowledgeTactics() {
  const sel = $('#kn-tactic');
  if (!sel) return;
  const tactics = uniq(KNOW.index.flatMap((p) => p.tactics || []).filter(Boolean));
  sel.innerHTML = '<option value="">All tactics</option>'
    + tactics.map((t) => `<option>${esc(t)}</option>`).join('');
}
const DETAIL_ANCHOR = {
  d3fend: '#mitre-d3fend',
  car: '#cyber-analytics-repository',
  car_red: '#cyber-analytics-repository-1',
  sigma: '#sigma-rules-public-repository',
  splunk: '#splunk-security-content',
  elastic: '#elastic-detection-rules',
  sentinel_defender: '#microsoft-sentinel-and-microsoft-365-defender-repository',
  art: '#atomic-red-team',
  rta: '#stratus-red-team',
};
function guideCard(p) {
  const host = p.url ? esc(p.url.replace(/^https?:\/\//, '').replace(/\/$/, '')) : '';
  return `<div class="card res-card"${p.id ? ` id="res-${esc(p.id)}"` : ''}>
    <h3>${esc(p.name)}</h3>
    ${p.url ? `<div class="meta"><a href="${esc(p.url)}" target="_blank" rel="noopener">${host} ↗</a></div>` : ''}
    <div class="badges">
      ${p.repoUpdated ? `<span class="badge">repo updated ${esc(p.repoUpdated)}</span>` : ''}
      ${p.accessed ? `<span class="badge">read by Compass ${esc(p.accessed)}</span>` : ''}
    </div>
    ${p.overview ? `<p class="tech">${linkify(p.overview)}</p>` : ''}
    ${p.navigate ? `<p class="tech"><b>How to navigate:</b> ${linkify(p.navigate)}</p>` : ''}
  </div>`;
}
function linkGroup(title, items, withVideo) {
  if (!items || !items.length) return '';
  const video = withVideo ? items.find((i) => /youtube-nocookie\.com\/embed/.test(i.url)) : null;
  const rest = items.filter((i) => i !== video);
  return `<h3 class="mt">${esc(title)}</h3>
    ${video ? `<div class="card" style="padding:12px;margin-bottom:14px"><div class="embedwrap"><iframe src="${esc(video.url)}" title="CVC tutorial" loading="lazy" allowfullscreen></iframe></div></div>` : ''}
    ${rest.length ? `<div class="grid">${rest.map((i) => `<a class="card res-card" href="${esc(i.url)}" target="_blank" rel="noopener"><h3>${esc(i.label)} ↗</h3></a>`).join('')}</div>` : ''}`;
}
function renderGuide(g) {
  const intro = $('#res-intro'); if (intro) intro.innerHTML = linkify(g.intro);
  const links = $('#res-links'); if (links) links.innerHTML = linkGroup('Tutorials', g.tutorials.items, true) + linkGroup('General knowledge', g.general.items, false);
  const faq = $('#res-faq'); if (faq) faq.innerHTML = (g.faq||[]).length ? `<h3 class="mt">Frequently asked questions</h3>` + g.faq.map((q) => `<details class="filter-box"><summary>${esc(q.q)}</summary>${q.a.map((p)=>`<p class="prose">${linkify(p)}</p>`).join('')}</details>`).join('') : '';
  const guide = $('#res-guide'); if (guide) guide.innerHTML = `<h3 class="mt">How to use each resource repository</h3><p class="tech">CVC points at these sources rather than hosting them…</p>` + (g.groups||[]).map((grp)=>`<h4 class="mt">${esc(grp.title)}</h4><div class="grid">${grp.providers.map(guideCard).join('')}</div>`).join('');
}

async function updateAttackDatasets() {
  const btn = $('#update-btn');
  const status = $('#update-status');
  const log = $('#update-log');
  if (!btn) return;
  btn.disabled = true;
  if (log) { log.style.display = 'block'; log.textContent = 'Updating datasets… this can take a minute.\n'; }
  try {
    const res = await fetch('tools/update_attack.py');
    const text = await res.text();
    if (!res.ok) throw new Error('cannot fetch update script: HTTP ' + res.status);
    if (logEl) logEl.textContent += '\nRun locally:\n$ python3 tools/update_attack.py\n\nThis updates data/* and data/intel/*; commit and push to publish.\n';
  } catch (e) {
    if (logEl) logEl.textContent += '\nError: ' + e.message + '\n';
  } finally {
    btn.disabled = false;
  }
}
