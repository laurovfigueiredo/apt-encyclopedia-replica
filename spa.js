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
  renderStats();
  buildFilters();
  renderCategories();
  renderGroups();
  renderTechs();
  renderSources();
  bind();
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
  const tac = uniq(TECHS.map((t) => t.tactic));
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
    const hay = [t.id, t.name, t.tactic, (t.groups || []).join(' ')].join(' ').toLowerCase();
    if (q && !hay.includes(q)) return false;
    if (tac && t.tactic !== tac) return false;
    return true;
  }).sort((a, b) => a.id.localeCompare(b.id));

  $('#tech-count').textContent = `(${res.length})`;
  $('#tech-grid').innerHTML = res.map((t) => `
    <article class="card">
      <h3><span class="mono">${esc(t.id)}</span> ${esc(t.name || '')}</h3>
      ${t.tactic ? `<div class="meta">Tactic: ${esc(t.tactic)}</div>` : ''}
      ${t.groups?.length ? `<div class="badges">${t.groups.slice(0, 6).map((g) => `<span class="badge">${esc(g)}</span>`).join('')}${t.groups.length > 6 ? `<span class="badge">+${t.groups.length - 6}</span>` : ''}</div>` : ''}
      ${t.description || t.usage ? `<div class="tech clamp">${esc(t.description || t.usage)}</div>` : ''}
    </article>`).join('') || '<p class="muted">No techniques match the filters.</p>';
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
    <div class="techlist">
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

function openTtpPanel(mitreName) {
  const x = CVC.find((c) => (c.mitre || '').toLowerCase() === (mitreName || '').toLowerCase());
  const list = x?.ttps || [];
  $('#modal-body').innerHTML = `
    <h2>${esc(x?.name || mitreName || 'TTPs')}</h2>
    <div class="meta">${list.length} techniques mapped</div>
    <div class="techlist">
      ${list.map((t) => {
        const id = typeof t === 'string' ? t : (t.technique_id || t.id || '');
        const nm = typeof t === 'string' ? (TECHS.find((z) => z.id === t)?.name || '') : (t.technique || t.name || '');
        const tc = typeof t === 'string' ? (TECHS.find((z) => z.id === t)?.tactic || '') : (t.tactic || '');
        return `<div class="techitem">
        <div class="mono">${esc(id)}</div>
        <div><b>${esc(nm)}</b>${tc ? ` <span class="tech">· ${esc(tc)}</span>` : ''}</div>
      </div>`;
      }).join('') || '<p class="muted">No TTP data available.</p>'}
    </div>
    ${x?.url ? `<p style="margin-top:14px"><a href="${esc(x.url)}" target="_blank" rel="noopener">Open source reference →</a></p>` : ''}
  `;
  $('#modal').classList.add('open');
  document.body.style.overflow = 'hidden';
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
    renderCategories();
  });
  $('#cat-list').addEventListener('click', (e) => {
    const b = e.target.closest('[data-ttp]');
    if (b) openTtpPanel(b.dataset.ttp);
  });

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
  renderCategories();
}