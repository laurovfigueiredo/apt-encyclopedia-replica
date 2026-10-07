const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const uniq = (a) => [...new Set(a.filter(Boolean))].sort((x, y) => x.localeCompare(y));

let ACTORS = [], TECHS = [], CVC = [], INTEL = [];

/* ---- cross-page scope persistence (localStorage) ---- */
const SCOPE_KEY = 'encyc.scope.v1';
function saveScope() {
  try {
    localStorage.setItem(SCOPE_KEY, JSON.stringify({
      cat: { motive: [...CAT.motive], industry: [...CAT.industry], base: [...CAT.base], country: [...CAT.country] },
      selected: [...HEATMAP.selected],
      advSel: [...HEATMAP.advSel],
      adversary: HEATMAP.selectedAdversary || '',
      providers: (typeof KNOW !== 'undefined' && KNOW.sel) ? [...KNOW.sel] : [],
    }));
  } catch { /* private mode — non-fatal */ }
}
function loadScope() {
  let s = null;
  try { s = JSON.parse(localStorage.getItem(SCOPE_KEY) || 'null'); } catch { return; }
  if (!s) return;
  if (s.cat) {
    ['motive', 'industry', 'base', 'country'].forEach((g) => (s.cat[g] || []).forEach((v) => CAT[g].add(v)));
  }
  (s.selected || []).forEach((v) => HEATMAP.selected.add(v));
  (s.advSel || []).forEach((v) => HEATMAP.advSel.add(v));
  if (s.adversary) HEATMAP.selectedAdversary = s.adversary;
  if (Array.isArray(s.providers) && s.providers.length && typeof KNOW !== 'undefined' && KNOW.sel) {
    KNOW.sel.clear();
    s.providers.forEach((k) => KNOW.sel.add(k));
  }
}
function syncFilterBoxes() {
  const boxes = { motive: '#f-motive', industry: '#f-industry', base: '#f-base', country: '#f-country' };
  Object.entries(boxes).forEach(([g, sel]) => {
    const box = $(sel);
    if (!box) return;
    box.querySelectorAll('input[data-group]').forEach((i) => { i.checked = CAT[g].has(i.value); });
  });
}

Promise.all([
  fetch('data/actors.json').then((r) => r.json()),
  fetch('data/techniques.json').then((r) => r.json()),
  fetch('data/cvc.json').then((r) => r.json()),
  fetch('data/intel/index.json').then((r) => r.json()).catch(() => []),
  fetch('data/technique_index.json').then((r) => r.json()).catch(() => []),
  fetch('data/controls.json').then((r) => r.json()).catch(() => ({ providers: [], techniques: [] })),
]).then(([actors, techs, cvc, intel, pages, ctrl]) => {
  ACTORS = actors; TECHS = techs; CVC = cvc; INTEL = intel;
  HEATMAP.cvc = cvc;
  buildCategories(cvc);
  initKnowledge(pages, ctrl);
  loadScope();
  buildTacticFilters();
  buildKnowledgeTactics();
  renderStats();
  buildFilters();
  syncFilterBoxes();
  buildHeatmapUI();
  buildIntelUI();
  renderCategories();
  renderReview();
  renderGroups();
  renderTechs();
  renderSources();
  bind();
  bindKnowledge();
  if (typeof syncProviderBoxes === 'function') syncProviderBoxes();
  renderHeatmap();
  renderIntelList();
  renderRisk();
}).catch((e) => {
  const m = document.querySelector('main');
  if (m) {
    const d = document.createElement('p');
    d.className = 'tag-warn';
    d.textContent = `Could not load local datasets (data/*.json): ${e.message}. Serve via "python3 -m http.server" from the repo root.`;
    m.prepend(d);
  }
});

/* ---------------- overview ---------------- */
function renderStats() {
  const active = ACTORS.filter((a) => a.active).length;
  const campaigns = ACTORS.reduce((s, a) => s + (Number(a.campaigns) || 0), 0);
  const sources = uniq(ACTORS.flatMap((a) => (a.reports || []).map((r) => r.publisher))).length;
  const vals = {
    groups: ACTORS.length,
    active,
    campaigns,
    techniques: TECHS.length,
    sources: sources + '+',
    adversaries: CVC.length,
    resources: KNOW.index.length
      ? KNOW.index.reduce((n, p) => n + (p.c || []).reduce((m, v) => m + v, 0), 0).toLocaleString('en-US')
      : '—',
  };
  $$('[data-stat]').forEach((el) => { el.textContent = vals[el.dataset.stat]; });
}

/* ---------------- categorized threats ---------------- */
const CAT = { motive: new Set(), industry: new Set(), base: new Set(), country: new Set() };

function chip(label, group) {
  return `<label class="chip"><input type="checkbox" data-group="${group}" value="${esc(label)}"><span>${esc(label)}</span></label>`;
}

function setHTML(sel, html) { const el = $(sel); if (el) el.innerHTML = html; }

function buildFilters() {
  setHTML('#f-motive', uniq(CVC.flatMap((x) => x.motivation)).map((v) => chip(v, 'motive')).join(''));
  setHTML('#f-industry', uniq(CVC.flatMap((x) => x.industries)).map((v) => chip(v, 'industry')).join(''));
  setHTML('#f-base', uniq(CVC.map((x) => x.country)).map((v) => chip(v, 'base')).join(''));
  setHTML('#f-country', uniq(CVC.flatMap((x) => x.victimCountries || [])).map((v) => chip(v, 'country')).join(''));

  const gc = uniq(ACTORS.map((a) => a.country));
  setHTML('#groups-country', '<option value="">All countries</option>' + gc.map((c) => `<option>${esc(c)}</option>`).join(''));
  const gt = uniq(ACTORS.map((a) => a.threatLevel));
  setHTML('#groups-threat', '<option value="">All threat levels</option>' + gt.map((c) => `<option>${esc(c)}</option>`).join(''));
  const tac = uniq(TECHS.map((t) => t.tactic).filter(Boolean));
  setHTML('#tech-tactic', '<option value="">All tactics</option>' + tac.map((c) => `<option>${esc(c)}</option>`).join(''));
}

function catMatch(x) {
  const m = [...CAT.motive], i = [...CAT.industry];
  const b = [...CAT.base], c = [...CAT.country];
  if (m.length && !(x.motivation || []).some((v) => m.includes(v))) return false;
  if (i.length && !(x.industries || []).some((v) => i.includes(v))) return false;
  if (b.length && !b.includes(x.country)) return false;
  if (c.length && !(x.victimCountries || []).some((v) => c.includes(v))) return false;
  return true;
}

function renderCategories() {
  const box = $('#cat-list');
  if (!box) return;
  const q = ($('#cat-q')?.value || '').trim().toLowerCase();
  const res = CVC.filter(catMatch)
    .filter((x) => !q || (x.name || '').toLowerCase().includes(q))
    .sort((a, b) => (a.name || '').localeCompare(b.name || ''));

  const total = $('#cat-total');
  if (total) total.textContent = res.length;
  if (!res.length) {
    box.innerHTML = '<p class="muted">No adversaries match selected criteria</p>';
    return;
  }
  box.innerHTML = res.map((x, n) => {
    const meta = [
      `Country: ${x.country || '—'}`,
      x.motivation?.length ? `Motive: ${x.motivation.join(', ')}` : '',
      x.industries?.length ? `Industry: ${x.industries.slice(0, 4).join(', ')}${x.industries.length > 4 ? '…' : ''}` : '',
      `${x.ttps?.length || 0} TTPs`,
    ].filter(Boolean).join(' &nbsp;·&nbsp; ');
    return `<div class="row" data-idx="${n}">
      <div class="row-main">
        <div class="row-title">${esc(x.name)}</div>
        <div class="tech">${meta}</div>
      </div>
      <div class="row-actions">
        <div class="row-check">
          <input type="checkbox" class="adversary_select" data-name="${esc(x.name)}" id="adv-${n}" ${HEATMAP.advSel.has(x.name) ? 'checked' : ''}>
          <label for="adv-${n}">select</label>
        </div>
        <button class="btn btn-ghost" data-ttp="${esc(x.mitre || '')}">TTPs</button>
        ${x.url ? `<a class="btn btn-ghost" href="${esc(x.url)}" target="_blank" rel="noopener">Source</a>` : ''}
      </div>
    </div>`;
  }).join('');
}

/* ---------------- selection review (mirrors the original's pink panel) --- */
function renderReview() {
  const box = $('#review');
  if (!box) return;

  const cats = [...HEATMAP.selected];
  const advs = [...HEATMAP.advSel];

  // live resolution: individual picks narrow the criteria result further
  const base = adversariesForScope('criteria', $('#hm-mode')?.value || 'union');
  const eff = advs.length ? base.filter((x) => advs.includes(x.name)) : base;
  HEATMAP.effective = eff;

  const catList = cats.length
    ? cats.map((c) => {
      const n = (HEATMAP.BY_ID.get(c)?.adversaries || []).length;
      return `<li>${esc(c)} <span class="muted">(${n})</span></li>`;
    }).join('')
    : '<li class="none">no threat categories selected</li>';

  const advList = advs.length
    ? advs.map((a) => `<li>${esc(a)}</li>`).join('')
    : '<li class="none">no individual adversaries selected</li>';

  box.innerHTML = `
    <h3>Selection Review</h3>
    <div class="review-grid">
      <div class="review-col">
        <h4>Threat categories (<span class="review-count">${cats.length}</span>)</h4>
        <ul>${catList}</ul>
      </div>
      <div class="review-col">
        <h4>Individual adversaries (<span class="review-count">${advs.length}</span>)</h4>
        <ul>${advList}</ul>
      </div>
      <div class="review-col">
        <h4>Effective scope (<span class="review-count">${eff.length}</span>)</h4>
        <ul>${eff.length
    ? eff.slice(0, 60).map((x) => `<li>${esc(x.name)}</li>`).join('')
    : '<li class="none">nothing selected</li>'}</ul>
        ${advs.length ? '<p class="tech" style="color:#4a1620;margin-top:8px">Individual picks are narrowing the criteria result.</p>' : ''}
      </div>
    </div>`;
}

/* ---------------- groups ---------------- */
function renderGroups() {
  const grid = $('#groups-grid');
  if (!grid) return;
  const q = ($('#groups-q')?.value || '').trim().toLowerCase();
  const c = $('#groups-country')?.value || '', t = $('#groups-threat')?.value || '', s = $('#groups-status')?.value || '';

  const res = ACTORS.filter((a) => {
    const hay = [a.name, (a.aliases || []).join(' '), (a.malware || []).join(' '), a.country,
      (a.techniques || []).map((x) => `${x.id} ${x.name}`).join(' ')].join(' ').toLowerCase();
    if (q && !hay.includes(q)) return false;
    if (c && a.country !== c) return false;
    if (t && a.threatLevel !== t) return false;
    if (s === 'active' && !a.active) return false;
    if (s === 'inactive' && a.active) return false;
    return true;
  }).sort((a, b) => a.name.localeCompare(b.name));

  const gc = $('#groups-count');
  if (gc) gc.textContent = `(${res.length})`;
  grid.innerHTML = res.map((a) => `
    <article class="card clickable" data-id="${esc(a.id)}">
      <h3>${esc(a.name)}</h3>
      ${a.aliases?.length ? `<div class="meta">Aliases: ${esc(a.aliases.slice(0, 5).join(', '))}${a.aliases.length > 5 ? '…' : ''}</div>` : ''}
      <div class="badges">
        ${a.country ? `<span class="badge">${esc(a.country)}</span>` : ''}
        ${a.threatLevel ? `<span class="badge badge-${esc(String(a.threatLevel).toLowerCase())}">${esc(a.threatLevel)}</span>` : ''}
        <span class="badge">${a.active ? 'Active' : 'Inactive'}</span>
        <span class="badge">${(a.techniques || []).length} TTPs</span>
      </div>
    </article>`).join('') || '<p class="muted">No groups match the filters.</p>';
}

/* ---------------- techniques ---------------- */
function renderTechs() {
  const grid = $('#tech-grid');
  if (!grid) return;
  const q = ($('#tech-q')?.value || '').trim().toLowerCase();
  const tac = $('#tech-tactic')?.value || '';

  const res = TECHS.filter((t) => {
    const hay = [t.id, t.name, t.tactic, (t.tactics || []).join(' '), (t.platforms || []).join(' '), (t.groups || []).join(' ')].join(' ').toLowerCase();
    if (q && !hay.includes(q)) return false;
    if (tac && t.tactic !== tac) return false;
    return true;
  }).sort((a, b) => a.id.localeCompare(b.id));

  const tc = $('#tech-count');
  if (tc) tc.textContent = `(${res.length})`;
  grid.innerHTML = res.map((t) => `
    <article class="card">
      <h3><span class="mono">${esc(t.id)}</span> ${esc(t.name || '')}</h3>
      <div class="meta">
        ${t.tactic ? `Tactic: ${esc(t.tactic)}` : 'Tactic: —'}
        ${t.status && t.status !== 'active' ? ` · <span class="tag-warn">${esc(t.status)}</span>` : ''}
        · <a href="${esc(t.url)}" target="_blank" rel="noopener">attack.mitre.org</a>
      </div>
      ${t.groups?.length ? `<div class="badges">${t.groups.slice(0, 6).map((g) => `<span class="badge">${esc(g)}</span>`).join('')}${t.groups.length > 6 ? `<span class="badge">+${t.groups.length - 6}</span>` : ''}</div>` : ''}
      ${t.description || t.usage ? `<div class="tech clamp">${esc(t.description || t.usage)}</div>` : ''}
    </article>`).join('') || '<p class="muted">No techniques match the filters.</p>';
}

/* ---------------- ATT&CK Navigator heatmap ---------------- */
const TYPE_LABEL = { motive: 'Motive', industry: 'Industry', base: 'Adversary Base', victim: 'Victim Location' };

function buildHeatmapUI() {
  const sel = $('#hm-category');
  if (!sel) return;
  const groups = { motive: [], industry: [], base: [], victim: [] };
  HEATMAP.CATS.forEach((c) => groups[c.type].push(c));
  sel.innerHTML = '<option value="">— usar os critérios marcados acima —</option>' +
    Object.entries(groups).map(([type, list]) => !list.length ? '' :
      `<optgroup label="${TYPE_LABEL[type]} (${list.length})">` +
      list.map((c) => `<option value="${esc(c.id)}">${esc(c.id)} — ${c.adversaries.length} adv</option>`).join('') +
      '</optgroup>').join('');
}

function currentScope() {
  const scope = $('#hm-scope')?.value || 'criteria';
  const mode = $('#hm-mode')?.value || 'union';
  const catId = $('#hm-category')?.value || '';
  if (catId) {
    const cat = HEATMAP.BY_ID.get(catId);
    if (cat) return { adversaries: cat.adversaries, name: cat.id, desc: `All adversaries matching: ${cat.id}`, ids: [cat.id] };
  }

  // the Trickbot example layer ships with the Compass as a worked risk scenario
  if (scope === 'example' && HEATMAP.example?.layer) {
    return {
      adversaries: [{ name: HEATMAP.example.name, ttps: HEATMAP.example.techniques }],
      name: HEATMAP.example.name,
      desc: `Example threat scope from the Control Validation Compass. Score = 1 for each technique attributed to ${HEATMAP.example.name}.`,
      ids: [],
      raw: HEATMAP.example.layer,
    };
  }

  const adv = adversariesForScope(scope, mode);
  // individual picks narrow the criteria result, same as the original's checkboxes
  const narrowed = HEATMAP.advSel.size ? adv.filter((x) => HEATMAP.advSel.has(x.name)) : adv;
  const ids = selectedCategoryIds();
  const label = ids.length ? ids.join(' + ') : 'All adversaries';
  const name = scope === 'adversary' && !HEATMAP.selectedAdversary ? 'Select an adversary' : label;
  return {
    adversaries: narrowed,
    name,
    desc: `Threat actor heatmap for ${narrowed.length} adversar${narrowed.length === 1 ? 'y' : 'ies'} in scope. Score = number of adversaries using the technique.`,
    ids,
  };
}

function renderHeatmap() {
  const meta = $('#hm-meta');
  if (!meta) return;
  const { adversaries, name, desc, raw } = currentScope();
  const counts = tally(adversaries);
  const layer = raw || buildLayer(name, desc, counts);
  HEATMAP.current = { layer, adversaries, name };

  const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12);
  const nameOf = (id) => TECHS.find((t) => t.id === id)?.name || '';
  const empty = adversaries.length === 0;

  meta.innerHTML = `
    <div class="row-main">
      <div class="row-title">${esc(layer.name)}</div>
      <div class="tech">${empty
      ? '<span class="tag-warn">escopo vazio</span> — marque critérios acima ou escolha uma categoria'
      : `${adversaries.length} adversários no escopo · <b>${layer.techniques.length}</b> técnicas distintas · score máximo <b>${layer.gradient.maxValue}</b>`}</div>
    </div>
    <div class="badges" style="margin-top:10px">
      ${top.map(([id, s]) => `<span class="badge" title="${esc(nameOf(id))}">${esc(id)} · ${s}</span>`).join('') || '<span class="muted">—</span>'}
    </div>`;

  const j = $('#hm-json');
  if (j) j.value = JSON.stringify(layer, null, 2);
  const f = $('#hm-frame');
  if (f) f.src = empty
    ? 'https://mitre-attack.github.io/attack-navigator/#leave_site_dialog=false&domain=enterprise-attack'
    : navigatorUrl(layer);
}

/* ---------------- autocomplete over the criterion chips ---------------- */
function setupAutocomplete(inputSel, chipsSel, group) {
  const input = $(inputSel);
  const box = $(chipsSel);
  if (!input || !box) return;

  let items = [];
  let active = -1;
  let menu = null;

  const labels = () => [...box.querySelectorAll('.chip')].map((c) => ({
    el: c,
    text: (c.textContent || '').trim(),
    input: c.querySelector('input'),
  }));

  function close() { menu?.remove(); menu = null; active = -1; }

  function open(list) {
    close();
    if (!list.length) return;
    menu = document.createElement('div');
    menu.className = 'ac-menu';
    menu.innerHTML = list.map((it, i) => `<div class="ac-item${i === 0 ? ' active' : ''}" data-i="${i}">${esc(it.text)}</div>`).join('');
    input.parentNode.appendChild(menu);
    items = list;
    active = 0;
  }

  function pick(i) {
    const it = items[i];
    if (!it || !it.input) return close();
    it.input.checked = !it.input.checked;
    const ev = new Event('change');
    toggle({ target: { value: it.input.value, checked: it.input.checked } }, group);
    input.value = '';
    close();
  }

  input.addEventListener('input', () => {
    const q = input.value.trim().toLowerCase();
    if (!q) return close();
    open(labels().filter((x) => x.text.toLowerCase().includes(q)).slice(0, 12));
  });

  input.addEventListener('keydown', (e) => {
    if (!menu) return;
    if (e.key === 'ArrowDown') { e.preventDefault(); active = Math.min(active + 1, items.length - 1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); active = Math.max(active - 1, 0); }
    else if (e.key === 'Enter') { e.preventDefault(); pick(active); return; }
    else if (e.key === 'Escape') { close(); return; }
    menu.querySelectorAll('.ac-item').forEach((n, i) => n.classList.toggle('active', i === active));
  });

  input.addEventListener('blur', () => setTimeout(close, 140));
}

/* ---------------- recent intelligence reports ---------------- */
let intelLayer = null;
let intelIndex = new Map();

function buildIntelUI() {
  INTEL.forEach((r) => intelIndex.set(r.id, r));
}

function renderIntelList() {
  const list = $('#intel-list');
  if (!list) return;
  const qEl = $('#intel-q');
  const q = (qEl?.value || '').trim().toLowerCase();
  const res = INTEL.filter((r) => !q || r.title.toLowerCase().includes(q));
  list.innerHTML = res.map((r) => `
    <label class="chip chip-report" data-id="${esc(r.id)}">
      <input type="radio" name="intel" value="${esc(r.id)}" ${r.id === intelIndex.get(qEl?.dataset.sel)?.id ? 'checked' : ''}>
      <span>${esc(r.title)}</span>
    </label>`).join('') || '<p class="muted">No reports match that search.</p>';
  list.dataset.count = res.length;
}

async function loadIntel(forceId) {
  const list = $('#intel-list');
  if (!list) return;
  const id = forceId
    || list.querySelector('input:checked')?.value
    || list.querySelector('input')?.value
    || INTEL[0]?.id;
  if (!id) return;

  const rec = intelIndex.get(id);
  if (!rec) return;
  const qEl = $('#intel-q');
  if (qEl) qEl.dataset.sel = id;
  const meta = $('#intel-meta');
  try {
    const layer = await (await fetch(rec.file)).json();
    intelLayer = layer;
    const j = $('#intel-json');
    if (j) j.value = JSON.stringify(layer, null, 2);
    const f = $('#intel-frame');
    if (f) f.src = navigatorUrl(layer);

    const top = [...(layer.techniques || [])].sort((a, b) => b.score - a.score).slice(0, 12);
    const nameOf = (t) => TECHS.find((z) => z.id === t.techniqueID)?.name || '';
    if (!meta) return;
    meta.innerHTML = `
      <div class="row-main">
        <div class="row-title">${esc(rec.title)}</div>
        <div class="tech"><b>${(layer.techniques || []).length}</b> técnicas · score máximo <b>${layer.gradient?.maxValue ?? 1}</b></div>
      </div>
      <div class="badges" style="margin-top:10px">
        ${top.map((t) => `<span class="badge" title="${esc(nameOf(t))}">${esc(t.techniqueID)} · ${t.score}</span>`).join('')}
      </div>
      <p class="tech" style="margin:12px 0 0"><a href="${esc(rec.source)}" target="_blank" rel="noopener">Layer source ↗</a></p>`;
  } catch (e) {
    if (meta) meta.innerHTML = `<p class="muted">Could not load this layer: ${esc(e.message)}</p>`;
  }
}

/* ---------------- sources ---------------- */
function renderSources() {
  const map = new Map();
  ACTORS.forEach((a) => (a.reports || []).forEach((r) => {
    if (!r.publisher) return;
    if (!map.has(r.publisher)) map.set(r.publisher, []);
    map.get(r.publisher).push(r.url);
  }));
  const total = uniq([...map.keys()]);
  const box = $('#sources-list');
  if (!box) return;
  box.innerHTML = `<div class="meta" style="margin-bottom:8px">${total.length} distinct publishers</div>` +
    total.map((p) => `<span class="badge">${esc(p)}</span>`).join('');
}

/* ---------------- group modal (with Diamond Model) ---------------- */
function openGroup(id) {
  const a = ACTORS.find((x) => x.id === id);
  if (!a) return;
  const dm = a.diamondModel || {};
  const refs = a.reports || [];
  const counts = tally([a]);
  const layer = buildLayer(a.name, `Techniques attributed to ${a.name}.`, counts);
  $('#modal-body').innerHTML = `
    <h2>${esc(a.name)}</h2>
    <div class="meta">${a.mitreId ? `MITRE: ${esc(a.mitreId)} · ` : ''}${a.country ? `Country: ${esc(a.country)} · ` : ''}Threat: ${esc(a.threatLevel || '—')} · ${a.active ? 'Active' : 'Inactive'}</div>
    ${a.aliases?.length ? `<div class="meta">Aliases: ${esc(a.aliases.join(', '))}</div>` : ''}
    ${a.description ? `<p class="tech">${esc(a.description)}</p>` : ''}

    <h3 class="mt">Diamond Model of Intrusion Analysis</h3>
    <div class="diamond">
      <div class="dcell d-adv"><h4>Adversary</h4>
        <p>${esc(a.name)}</p>
        ${a.attribution ? `<p class="tech">${esc(a.attribution)}</p>` : ''}
        ${a.country ? `<p class="tech">Base: ${esc(a.country)}</p>` : ''}
      </div>
      <div class="dcell d-cap"><h4>Capability</h4>
        <p>${(a.techniques || []).length} techniques</p>
        ${a.sophistication ? `<p class="tech">Sophistication: ${esc(a.sophistication)}</p>` : ''}
        ${a.malware?.length ? `<p class="tech">Malware: ${esc(a.malware.slice(0, 6).join(', '))}${a.malware.length > 6 ? '…' : ''}</p>` : ''}
      </div>
      <div class="dcell d-inf"><h4>Infrastructure</h4>
        <p>${esc(dm.infrastructure?.notes || 'C2 / domains / IPs — see linked reporting')}</p>
      </div>
      <div class="dcell d-vic"><h4>Victim</h4>
        ${a.targetSectors?.length ? `<p class="tech">Sectors: ${esc(a.targetSectors.slice(0, 6).join(', '))}${a.targetSectors.length > 6 ? '…' : ''}</p>` : '<p class="tech">—</p>'}
        ${a.victimCountries?.length ? `<p class="tech">Victim geo: ${esc(a.victimCountries.slice(0, 6).join(', '))}${a.victimCountries.length > 6 ? '…' : ''}</p>` : ''}
      </div>
    </div>

    <h3 class="mt">Techniques (${(a.techniques || []).length})</h3>
    <div class="card" style="padding:0;overflow:hidden;margin-top:10px">
      <iframe title="ATT&CK Navigator" width="100%" height="620" style="border:0;display:block;background:#fff"
        src="${esc(navigatorUrl(layer))}"></iframe>
    </div>
    <div class="techlist" style="margin-top:12px">
      ${(a.techniques || []).map((t) => `<div class="techitem">
          <div class="mono">${esc(t.id)}</div>
          <div><b>${esc(t.name || '')}</b>${t.tactic ? ` <span class="tech">· ${esc(t.tactic)}</span>` : ''}</div>
          ${t.usage ? `<div class="tech">${esc(t.usage)}</div>` : ''}
        </div>`).join('') || '<p class="muted">No techniques listed.</p>'}
    </div>

    ${refs.length ? `<h3 class="mt">Intelligence Sources (${refs.length})</h3>
      <div class="badges">${refs.slice(0, 30).map((r) => `<a class="badge" href="${esc(r.url)}" target="_blank" rel="noopener">${esc(r.publisher || r.title || r.url)}</a>`).join('')}</div>` : ''}
  `;
  $('#modal').classList.add('open');
  document.body.style.overflow = 'hidden';
}

/* ---------------- adversary profile: Diamond Model + ETDA metadata ---- */
function diamondBlock(x) {
  if (!x?.diamond) {
    return `<p class="muted">No Diamond Model graphic for this adversary.</p>`;
  }
  const alt = `${x.name} Diamond Model`;
  return `
    <div class="diamond-wrap">
      <img src="${esc(x.diamond)}" alt="${esc(alt)}" loading="lazy" width="100%">
    </div>
    <p class="tech" style="text-align:center">Modified Diamond Model of Intrusion Analysis — right-click the image to open it full size.</p>`;
}

function profileBlock(x) {
  const links = [
    x?.mitreUrl ? `<a class="btn btn-ghost" href="${esc(x.mitreUrl)}" target="_blank" rel="noopener">ATT&amp;CK Profile ↗</a>` : '',
    x?.etdaUrl ? `<a class="btn btn-ghost" href="${esc(x.etdaUrl)}" target="_blank" rel="noopener">ETDA Profile ↗</a>` : '',
    x?.url ? `<a class="btn btn-ghost" href="${esc(x.url)}" target="_blank" rel="noopener">Heatmap source ↗</a>` : '',
  ].filter(Boolean).join(' ');

  const facts = [
    ['ATT&amp;CK ID', x?.mitre],
    ['Aliases', (x?.aliases || []).join(', ') || null],
    ['Adversary base', (x?.country || '').replace(' (Base)', '') || null],
    ['Motive', (x?.motivation || []).join(', ') || null],
    ['Victim industries', (x?.industries || []).join(', ') || null],
    ['Victim countries', (x?.victimCountries || []).join(', ') || null],
    ['First seen', x?.firstSeen],
    ['ATT&amp;CK last modified', x?.lastModified],
  ].filter(([, v]) => v);

  return `
    <div class="badges" style="margin:10px 0 14px">${links}</div>
    <dl class="facts">
      ${facts.map(([k, v]) => `<div class="fact"><dt>${k}</dt><dd>${esc(v)}</dd></div>`).join('')}
    </dl>
    ${x?.description ? `<h3 class="mt">Adversary Profile</h3><p class="prose">${esc(x.description)}</p>` : ''}`;
}

function openTtpPanel(mitreName) {
  const x = CVC.find((c) => (c.mitre || '').toLowerCase() === (mitreName || '').toLowerCase());
  const list = x?.ttps || [];
  HEATMAP.selectedAdversary = x?.mitre || '';

  // layer for this adversary
  const counts = tally(x ? [x] : []);
  const layer = buildLayer(x?.name || mitreName || 'TTPs',
    `Adversary-specific layer. Score = 1 when the adversary is attributed to the technique.`, counts);

  $('#modal-body').innerHTML = `
    <h2>${esc(x?.name || mitreName || 'TTPs')}</h2>
    <div class="meta">${list.length} techniques mapped</div>
    <div class="badges">${(x?.motivation || []).map((m) => `<span class="badge">${esc(m)}</span>`).join('')}${(x?.industries || []).slice(0, 6).map((m) => `<span class="badge">${esc(m)}</span>`).join('')}</div>

    <div class="tabs" role="tablist">
      <button class="tab active" data-tab="ttp" role="tab">ATT&amp;CK Heatmap</button>
      <button class="tab" data-tab="profile" role="tab">Adversary Profile</button>
      <button class="tab" data-tab="diamond" role="tab">Diamond Model</button>
    </div>

    <div class="tabpanel active" data-panel="ttp">
      <div class="card" style="padding:0;overflow:hidden;margin-top:14px">
        <iframe title="ATT&CK Navigator" width="100%" height="620" style="border:0;display:block;background:#fff"
          src="${esc(navigatorUrl(layer))}"></iframe>
      </div>
      <div class="techlist" style="margin-top:12px">
        ${list.map((t) => {
        const id = typeof t === 'string' ? t : (t.technique_id || t.id || '');
        const meta = TECHS.find((z) => z.id === id);
        return `<div class="techitem">
        <div class="mono">${esc(id)}</div>
        <div><b>${esc(meta?.name || (typeof t === 'string' ? '' : (t.technique || t.name || '')))}</b>${meta?.tactic ? ` <span class="tech">· ${esc(meta.tactic)}</span>` : ''}</div>
      </div>`;
      }).join('') || '<p class="muted">No TTP data available.</p>'}
      </div>
    </div>

    <div class="tabpanel" data-panel="profile">${profileBlock(x)}</div>
    <div class="tabpanel" data-panel="diamond">${diamondBlock(x)}</div>
  `;
  $('#modal').classList.add('open');
  document.body.style.overflow = 'hidden';

  $$('.tabs .tab', $('#modal-body')).forEach((t) => t.addEventListener('click', () => {
    $$('.tabs .tab', $('#modal-body')).forEach((b) => b.classList.toggle('active', b === t));
    $$('.tabpanel', $('#modal-body')).forEach((p) => p.classList.toggle('active', p.dataset.panel === t.dataset.tab));
  }));

  const hmScope = $('#hm-scope');
  if (hmScope) hmScope.value = 'adversary';
  renderHeatmap();
}

function closeModal() {
  $('#modal').classList.remove('open');
  document.body.style.overflow = '';
}

/* ---------------- events ---------------- */
/* on(): attach only when the element exists on this page (multi-page safe) */
function on(sel, ev, fn) { const el = $(sel); if (el) el.addEventListener(ev, fn); }

function bind() {
  setupAutocomplete('#ac-motive', '#f-motive', 'motive');
  setupAutocomplete('#ac-industry', '#f-industry', 'industry');
  setupAutocomplete('#ac-base', '#f-base', 'base');
  setupAutocomplete('#ac-country', '#f-country', 'country');

  on('#f-motive', 'change', (e) => toggle(e, 'motive'));
  on('#f-industry', 'change', (e) => toggle(e, 'industry'));
  on('#f-base', 'change', (e) => toggle(e, 'base'));
  on('#f-country', 'change', (e) => toggle(e, 'country'));
  on('#cat-q', 'input', renderCategories);
  on('#cat-clear', 'click', () => {
    $$('#categorized input[type=checkbox]').forEach((c) => (c.checked = false));
    Object.values(CAT).forEach((s) => s.clear());
    clearCriteria();
    HEATMAP.advSel.clear();
    renderCategories();
    renderReview();
    renderHeatmap();
    renderRisk();
    saveScope();
  });
  on('#cat-list', 'click', (e) => {
    const b = e.target.closest('[data-ttp]');
    if (b) openTtpPanel(b.dataset.ttp);
  });
  on('#cat-list', 'change', (e) => {
    const b = e.target.closest('.adversary_select');
    if (!b) return;
    const name = b.dataset.name;
    b.checked ? HEATMAP.advSel.add(name) : HEATMAP.advSel.delete(name);
    renderReview();
    renderHeatmap();
    renderRisk();
    saveScope();
  });

  on('#hm-render', 'click', () => { renderHeatmap(); renderRisk(); });
  on('#hm-scope', 'change', () => { renderHeatmap(); renderRisk(); });
  on('#hm-mode', 'change', () => { renderHeatmap(); renderRisk(); renderReview(); saveScope(); });
  on('#hm-category', 'change', () => { renderHeatmap(); renderRisk(); });
  on('#hm-copy', 'click', async () => {
    const t = $('#hm-json');
    if (!t) return;
    try { await navigator.clipboard.writeText(t.value); } catch { t.select(); document.execCommand('copy'); }
    flash($('#hm-copy'), 'Copiado!');
  });
  on('#hm-download', 'click', () => {
    const src = $('#hm-json');
    if (!src) return;
    const blob = new Blob([src.value], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${(HEATMAP.current?.name || 'layer').replace(/[^\w.-]+/g, '_')}_attack_layer.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  });
  on('#hm-open', 'click', () => { if (HEATMAP.current?.layer) window.open(navigatorUrl(HEATMAP.current.layer), '_blank', 'noopener'); });

  on('#intel-q', 'input', renderIntelList);
  on('#intel-load', 'click', () => loadIntel());
  on('#intel-list', 'change', () => loadIntel());
  on('#intel-copy', 'click', async () => {
    const t = $('#intel-json');
    if (!t) return;
    try { await navigator.clipboard.writeText(t.value); } catch { t.select(); document.execCommand('copy'); }
    flash($('#intel-copy'), 'Copiado!');
  });
  on('#intel-open', 'click', () => {
    if (intelLayer) window.open(navigatorUrl(intelLayer), '_blank', 'noopener');
  });

  on('#groups-q', 'input', renderGroups);
  ['#groups-country', '#groups-threat', '#groups-status'].forEach((s) => on(s, 'change', renderGroups));
  on('#groups-grid', 'click', (e) => {
    const c = e.target.closest('[data-id]');
    if (c) openGroup(c.dataset.id);
  });

  on('#tech-q', 'input', renderTechs);
  on('#tech-tactic', 'change', renderTechs);

  on('#modal-close', 'click', closeModal);
  on('#modal', 'click', (e) => { if (e.target.id === 'modal') closeModal(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });

  // multi-page nav: links to *.html navigate normally; in-page #anchors smooth-scroll
  $$('nav.nav a').forEach((a) => a.addEventListener('click', (e) => {
    const href = a.getAttribute('href') || '';
    if (!href.startsWith('#')) return; // separate page — let the browser navigate
    e.preventDefault();
    $(href)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }));
}

function toggle(e, group) {
  const v = e.target.value;
  e.target.checked ? CAT[group].add(v) : CAT[group].delete(v);
  setCriterionSelected(v, e.target.checked);
  renderCategories();
  renderReview();
  renderHeatmap();
  renderRisk();
  saveScope();
}

function flash(btn, msg) {
  if (!btn) return;
  const old = btn.textContent;
  btn.textContent = msg;
  setTimeout(() => (btn.textContent = old), 1200);
}