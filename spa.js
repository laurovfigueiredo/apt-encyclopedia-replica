const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const uniq = (a) => [...new Set(a.filter(Boolean))].sort((x, y) => x.localeCompare(y));

let ACTORS = [], TECHS = [], CVC = [];

Promise.all([
  fetch('data/actors.json').then((r) => r.json()),
  fetch('data/techniques.json').then((r) => r.json()),
  fetch('data/cvc.json').then((r) => r.json()),
]).then(([actors, techs, cvc]) => {
  ACTORS = actors; TECHS = techs; CVC = cvc;
  HEATMAP.cvc = cvc;
  buildCategories(cvc);
  renderStats();
  buildFilters();
  buildHeatmapUI();
  renderCategories();
  renderGroups();
  renderTechs();
  renderSources();
  bind();
  renderHeatmap();
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
  };
  $$('[data-stat]').forEach((el) => { el.textContent = vals[el.dataset.stat]; });
}

/* ---------------- categorized threats ---------------- */
const CAT = { motive: new Set(), industry: new Set(), country: new Set() };

function chip(label, group) {
  return `<label class="chip"><input type="checkbox" data-group="${group}" value="${esc(label)}"><span>${esc(label)}</span></label>`;
}

function buildFilters() {
  $('#f-motive').innerHTML = uniq(CVC.flatMap((x) => x.motivation)).map((v) => chip(v, 'motive')).join('');
  $('#f-industry').innerHTML = uniq(CVC.flatMap((x) => x.industries)).map((v) => chip(v, 'industry')).join('');
  const loc = uniq(CVC.flatMap((x) => [x.country].concat(x.victimCountries || [])));
  $('#f-country').innerHTML = loc.map((v) => chip(v, 'country')).join('');

  const gc = uniq(ACTORS.map((a) => a.country));
  $('#groups-country').innerHTML = '<option value="">All countries</option>' + gc.map((c) => `<option>${esc(c)}</option>`).join('');
  const gt = uniq(ACTORS.map((a) => a.threatLevel));
  $('#groups-threat').innerHTML = '<option value="">All threat levels</option>' + gt.map((c) => `<option>${esc(c)}</option>`).join('');
  const tac = uniq(TECHS.map((t) => t.tactic).filter(Boolean));
  $('#tech-tactic').innerHTML = '<option value="">All tactics</option>' + tac.map((c) => `<option>${esc(c)}</option>`).join('');
}

function catMatch(x) {
  const m = [...CAT.motive], i = [...CAT.industry], c = [...CAT.country];
  if (m.length && !(x.motivation || []).some((v) => m.includes(v))) return false;
  if (i.length && !(x.industries || []).some((v) => i.includes(v))) return false;
  if (c.length && ![x.country].concat(x.victimCountries || []).filter(Boolean).some((v) => c.includes(v))) return false;
  return true;
}

function renderCategories() {
  const q = $('#cat-q').value.trim().toLowerCase();
  const res = CVC.filter(catMatch)
    .filter((x) => !q || (x.name || '').toLowerCase().includes(q))
    .sort((a, b) => (a.name || '').localeCompare(b.name || ''));

  $('#cat-total').textContent = res.length;
  const box = $('#cat-list');
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
        <button class="btn btn-ghost" data-ttp="${esc(x.mitre || '')}">TTPs</button>
        ${x.url ? `<a class="btn btn-ghost" href="${esc(x.url)}" target="_blank" rel="noopener">Source</a>` : ''}
      </div>
    </div>`;
  }).join('');
}

/* ---------------- groups ---------------- */
function renderGroups() {
  const q = $('#groups-q').value.trim().toLowerCase();
  const c = $('#groups-country').value, t = $('#groups-threat').value, s = $('#groups-status').value;

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

  $('#groups-count').textContent = `(${res.length})`;
  $('#groups-grid').innerHTML = res.map((a) => `
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
  const q = $('#tech-q').value.trim().toLowerCase();
  const tac = $('#tech-tactic').value;

  const res = TECHS.filter((t) => {
    const hay = [t.id, t.name, t.tactic, (t.tactics || []).join(' '), (t.platforms || []).join(' '), (t.groups || []).join(' ')].join(' ').toLowerCase();
    if (q && !hay.includes(q)) return false;
    if (tac && t.tactic !== tac) return false;
    return true;
  }).sort((a, b) => a.id.localeCompare(b.id));

  $('#tech-count').textContent = `(${res.length})`;
  $('#tech-grid').innerHTML = res.map((t) => `
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
  const groups = { motive: [], industry: [], base: [], victim: [] };
  HEATMAP.CATS.forEach((c) => groups[c.type].push(c));
  sel.innerHTML = '<option value="">— usar os critérios marcados acima —</option>' +
    Object.entries(groups).map(([type, list]) => !list.length ? '' :
      `<optgroup label="${TYPE_LABEL[type]} (${list.length})">` +
      list.map((c) => `<option value="${esc(c.id)}">${esc(c.id)} — ${c.adversaries.length} adv</option>`).join('') +
      '</optgroup>').join('');
}

function currentScope() {
  const scope = $('#hm-scope').value;
  const mode = $('#hm-mode').value;
  const catId = $('#hm-category').value;
  if (catId) {
    const cat = HEATMAP.BY_ID.get(catId);
    if (cat) return { adversaries: cat.adversaries, name: cat.id, desc: `All adversaries matching: ${cat.id}`, ids: [cat.id] };
  }
  const adv = adversariesForScope(scope, mode);
  const ids = selectedCategoryIds();
  const label = ids.length ? ids.join(' + ') : 'All adversaries';
  const name = scope === 'adversary' && !HEATMAP.selectedAdversary ? 'Select an adversary' : label;
  return {
    adversaries: adv,
    name,
    desc: `Threat actor heatmap for ${adv.length} adversar${adv.length === 1 ? 'y' : 'ies'} in scope. Score = number of adversaries using the technique.`,
    ids,
  };
}

function renderHeatmap() {
  const { adversaries, name, desc } = currentScope();
  const counts = tally(adversaries);
  const layer = buildLayer(name, desc, counts);
  HEATMAP.current = { layer, adversaries, name };

  const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12);
  const nameOf = (id) => TECHS.find((t) => t.id === id)?.name || '';
  const empty = adversaries.length === 0;

  $('#hm-meta').innerHTML = `
    <div class="row-main">
      <div class="row-title">${esc(layer.name)}</div>
      <div class="tech">${empty
      ? '<span class="tag-warn">escopo vazio</span> — marque critérios acima ou escolha uma categoria'
      : `${adversaries.length} adversários no escopo · <b>${layer.techniques.length}</b> técnicas distintas · score máximo <b>${layer.gradient.maxValue}</b>`}</div>
    </div>
    <div class="badges" style="margin-top:10px">
      ${top.map(([id, s]) => `<span class="badge" title="${esc(nameOf(id))}">${esc(id)} · ${s}</span>`).join('') || '<span class="muted">—</span>'}
    </div>`;

  $('#hm-json').value = JSON.stringify(layer, null, 2);
  $('#hm-frame').src = empty
    ? 'https://mitre-attack.github.io/attack-navigator/#leave_site_dialog=false&domain=enterprise-attack'
    : navigatorUrl(layer);
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
  $('#sources-list').innerHTML = `<div class="meta" style="margin-bottom:8px">${total.length} distinct publishers</div>` +
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

  $('#hm-scope').value = 'adversary';
  renderHeatmap();
}

function closeModal() {
  $('#modal').classList.remove('open');
  document.body.style.overflow = '';
}

/* ---------------- events ---------------- */
function bind() {
  $('#f-motive').addEventListener('change', (e) => toggle(e, 'motive'));
  $('#f-industry').addEventListener('change', (e) => toggle(e, 'industry'));
  $('#f-country').addEventListener('change', (e) => toggle(e, 'country'));
  $('#cat-q').addEventListener('input', renderCategories);
  $('#cat-clear').addEventListener('click', () => {
    $$('#categorized input[type=checkbox]').forEach((c) => (c.checked = false));
    Object.values(CAT).forEach((s) => s.clear());
    clearCriteria();
    renderCategories();
    renderHeatmap();
  });
  $('#cat-list').addEventListener('click', (e) => {
    const b = e.target.closest('[data-ttp]');
    if (b) openTtpPanel(b.dataset.ttp);
  });

  $('#hm-render').addEventListener('click', renderHeatmap);
  $('#hm-scope').addEventListener('change', renderHeatmap);
  $('#hm-mode').addEventListener('change', renderHeatmap);
  $('#hm-category').addEventListener('change', renderHeatmap);
  $('#hm-copy').addEventListener('click', async () => {
    const t = $('#hm-json');
    try { await navigator.clipboard.writeText(t.value); } catch { t.select(); document.execCommand('copy'); }
    flash($('#hm-copy'), 'Copiado!');
  });
  $('#hm-download').addEventListener('click', () => {
    const blob = new Blob([$('#hm-json').value], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${(HEATMAP.current?.name || 'layer').replace(/[^\w.-]+/g, '_')}_attack_layer.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  });
  $('#hm-open').addEventListener('click', () => window.open(navigatorUrl(HEATMAP.current.layer), '_blank', 'noopener'));

  $('#groups-q').addEventListener('input', renderGroups);
  ['#groups-country', '#groups-threat', '#groups-status'].forEach((s) => $(s).addEventListener('change', renderGroups));
  $('#groups-grid').addEventListener('click', (e) => {
    const c = e.target.closest('[data-id]');
    if (c) openGroup(c.dataset.id);
  });

  $('#tech-q').addEventListener('input', renderTechs);
  $('#tech-tactic').addEventListener('change', renderTechs);

  $('#modal-close').addEventListener('click', closeModal);
  $('#modal').addEventListener('click', (e) => { if (e.target.id === 'modal') closeModal(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });

  $$('nav.nav a').forEach((a) => a.addEventListener('click', (e) => {
    e.preventDefault();
    $(a.getAttribute('href'))?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }));
}

function toggle(e, group) {
  const v = e.target.value;
  e.target.checked ? CAT[group].add(v) : CAT[group].delete(v);
  setCriterionSelected(v, e.target.checked);
  renderCategories();
  renderHeatmap();
}

function flash(btn, msg) {
  const old = btn.textContent;
  btn.textContent = msg;
  setTimeout(() => (btn.textContent = old), 1200);
}