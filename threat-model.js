/* =====================================================================
   threat-model.js — faithful functional clone of the Control Validation
   Compass "Threat Model" page (https://controlcompass.github.io/threat-model).

   Data model (mirrors data/cvc.json):
     adversary = { name, mitre, aliases[], country (base), motivation[],
                   industries[], victimCountries[], ttps[] (ATT&CK IDs),
                   description?, url? }

   COMBINE RULE (documented): OR within the same filter group, AND across
   different filter groups. No active filter in a group = that group does
   not restrict. No active filters at all = every adversary matches.

   Scoring: score(technique) = number of in-scope adversaries/sources that
   use it (same model as heatmap.js tally()). Navigator layer objects are
   built with heatmap.js buildLayer() (layer 4.x, domain enterprise-attack).

   Boot order: fetch('data/cvc.json') [REAL data] -> fetch intel index ->
   fetch techniques map -> render. If any fetch fails, embedded fallback
   data (10 realistic adversaries + 3 intel reports) is used instead.
   ===================================================================== */

const TM$ = (s, r = document) => r.querySelector(s);
const TM$$ = (s, r = document) => [...r.querySelectorAll(s)];
const TMesc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/* ---------------- Canonical filter options (exact, unabridged) ----------------
   These lists are reproduced verbatim from the original page, in order.
   Any extra values found in the loaded dataset are appended (sorted) so
   nothing present in the data is ever hidden. */
const TM_MOTIVES = [
  'Financial Crime',
  'Financial Gain',
  'Information Theft & Espionage',
  'Sabotage & Destruction',
];

const TM_INDUSTRIES = [
  'Aerospace', 'Automotive', 'Aviation', 'Casinos & Gambling', 'Chemical',
  'Construction', 'Critical Infrastructure', 'Defense', 'Education', 'Embassies',
  'Energy', 'Engineering', 'Entertainment', 'Financial (Finance)',
  'Food & Agriculture', 'Gaming', 'Government', 'Healthcare',
  'High Tech (High-Tech)', 'Hospitality', 'Industrial',
  'Information Technology (IT)', 'Law Enforcement', 'Manufacturing', 'Media',
  'Mining', 'Non-Governmental Organizations (NGOs)',
  'Non-Profit Organizations (Non Profits)', 'Oil & Gas',
  'Online Video Game Companies (Online Gaming)', 'Petrochemical',
  'Pharmaceuticals', 'Research', 'Retail', 'Satellites', 'Shipping & Logistics',
  'Technology', 'Telecommunications (Telecoms)', 'Think Tanks', 'Transportation',
  'Utilities',
];

const TM_BASES = [
  'Brazil', 'China', 'Colombia', 'India', 'Iran', 'Lebanon',
  'North Korea (Democratic People\'s Republic of Korea, DPRK)', 'Pakistan',
  'Romania', 'Russia', 'South Korea (Republic of Korea, ROK)', 'Turkey',
  'Ukraine', 'United Arab Emirates (UAE)', 'United States of America (USA)',
  'Vietnam',
];

const TM_VICTIMS = [
  'ASEAN', 'Afghanistan', 'Albania', 'Algeria', 'Angola', 'Antigua and Barbuda',
  'Argentina', 'Armenia', 'Australia', 'Austria', 'Azerbaijan', 'Bahamas',
  'Bahrain', 'Bangladesh', 'Barbados', 'Belarus', 'Belgium', 'Belize', 'Bhutan',
  'Bolivia', 'Bosnia and Herzegovina', 'Botswana', 'Brazil', 'Brunei', 'Bulgaria',
  'Cambodia', 'Canada', 'Chechnya', 'Chile', 'China', 'Colombia', 'Congo',
  'Costa Rica', "Cote d'Ivoire", 'Croatia', 'Cuba', 'Cyprus', 'Czech', 'Denmark',
  'Djibouti', 'Dominican Republic', 'Ecuador', 'Egypt', 'El Salvador',
  'Equatorial Guinea', 'Estonia', 'Ethiopia', 'Finland', 'France', 'Georgia',
  'Germany', 'Ghana', 'Gibraltar', 'Greece', 'Guatemala', 'Honduras', 'Hong Kong',
  'Hungary', 'Iceland', 'India', 'Indonesia', 'Iran', 'Iraq', 'Ireland', 'Israel',
  'Italy', 'Jamaica', 'Japan', 'Jordan', 'Kazakhstan', 'Kenya', 'Kuwait',
  'Kyrgyzstan', 'Laos', 'Latvia', 'Lebanon', 'Libya', 'Lithuania', 'Luxembourg',
  'Macao', 'Macedonia', 'Malaysia', 'Mali', 'Malta', 'Mauritius', 'Mexico',
  'Moldova', 'Mongolia', 'Montenegro', 'Morocco', 'Mozambique', 'Myanmar', 'NATO',
  'Namibia', 'Nepal', 'Netherlands', 'New Zealand', 'Nicaragua', 'Nigeria',
  'North Korea', 'Norway', 'Oman', 'Pakistan', 'Palestine', 'Panama',
  'Papua New Guinea', 'Paraguay', 'Peru', 'Philippines', 'Poland', 'Portugal',
  'Qatar', 'Romania', 'Russia', 'Rwanda', 'Saudi Arabia', 'Senegal', 'Serbia',
  'Seychelles', 'Singapore', 'Slovakia', 'Slovenia', 'Somalia', 'South Africa',
  'South Korea', 'South Sudan', 'Spain', 'Sri Lanka', 'Suriname', 'Swaziland',
  'Sweden', 'Switzerland', 'Syria', 'Taiwan', 'Tajikistan', 'Tanzania',
  'Thailand', 'Tibet', 'Trinidad and Tobago', 'Tunisia', 'Turkey', 'Turkmenistan',
  'Uganda', 'Ukraine', 'United Arab Emirates (UAE)', 'United Kingdom (UK)',
  'United States of America (USA)', 'Uruguay', 'Uzbekistan', 'Venezuela',
  'Vietnam', 'Yemen',
];

const TM_TACTIC_ORDER = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
];

/* ---------------- Embedded fallback data (used only if fetch fails) ----------------
   Same schema as data/cvc.json. 10 realistic adversaries covering all four
   motives, many industries and bases. */
const TM_FALLBACK_ADVERSARIES = [
  { name: 'APT29', mitre: 'APT29', aliases: ['Cozy Bear', 'NOBELIUM'], country: 'Russia', motivation: ['Information Theft & Espionage'], industries: ['Government', 'Healthcare', 'Technology'], victimCountries: ['United States of America (USA)', 'United Kingdom (UK)', 'Germany'], ttps: ['T1566.001', 'T1566.002', 'T1078', 'T1059.001', 'T1021.004', 'T1003.001', 'T1048', 'T1071.001', 'T1105', 'T1016'] },
  { name: 'APT28', mitre: 'APT28', aliases: ['Fancy Bear', 'Sofacy'], country: 'Russia', motivation: ['Information Theft & Espionage'], industries: ['Government', 'Defense', 'Media'], victimCountries: ['United States of America (USA)', 'Ukraine', 'France'], ttps: ['T1566.001', 'T1566.002', 'T1078', 'T1059.001', 'T1021.001', 'T1003.001', 'T1041', 'T1071.001', 'T1083', 'T1018'] },
  { name: 'APT41', mitre: 'APT41', aliases: ['Double Dragon', 'Wicked Panda'], country: 'China', motivation: ['Information Theft & Espionage', 'Financial Gain'], industries: ['Healthcare', 'Telecommunications (Telecoms)', 'Technology', 'Gaming'], victimCountries: ['United States of America (USA)', 'Japan', 'India'], ttps: ['T1566.001', 'T1190', 'T1078', 'T1059.003', 'T1021.001', 'T1003.001', 'T1048', 'T1071.001', 'T1105', 'T1057'] },
  { name: 'FIN7', mitre: 'FIN7', aliases: ['Carbanak'], country: 'Russia', motivation: ['Financial Crime', 'Financial Gain'], industries: ['Retail', 'Hospitality', 'Financial (Finance)'], victimCountries: ['United States of America (USA)', 'United Kingdom (UK)'], ttps: ['T1566.001', 'T1059.001', 'T1059.003', 'T1021.001', 'T1003.001', 'T1048', 'T1071.001', 'T1105', 'T1083', 'T1016'] },
  { name: 'Turla', mitre: 'Turla', aliases: ['Snake', 'Uroburos'], country: 'Russia', motivation: ['Information Theft & Espionage'], industries: ['Government', 'Defense', 'Education'], victimCountries: ['Ukraine', 'Georgia', 'Germany'], ttps: ['T1566.002', 'T1078', 'T1059.003', 'T1021.004', 'T1003.002', 'T1041', 'T1071.004', 'T1018', 'T1082', 'T1033'] },
  { name: 'Lazarus Group', mitre: 'Lazarus Group', aliases: ['HIDDEN COBRA'], country: 'North Korea', motivation: ['Financial Crime', 'Information Theft & Espionage', 'Sabotage & Destruction'], industries: ['Financial (Finance)', 'Media', 'Energy'], victimCountries: ['United States of America (USA)', 'South Korea', 'Japan'], ttps: ['T1566.001', 'T1078', 'T1059.001', 'T1021.002', 'T1003.001', 'T1048', 'T1071.001', 'T1105', 'T1485', 'T1486'] },
  { name: 'OilRig', mitre: 'OilRig', aliases: ['APT34', 'Helix Kitten'], country: 'Iran', motivation: ['Information Theft & Espionage'], industries: ['Energy', 'Oil & Gas', 'Government', 'Telecommunications (Telecoms)'], victimCountries: ['Saudi Arabia', 'United Arab Emirates (UAE)', 'United States of America (USA)'], ttps: ['T1566.002', 'T1078', 'T1059.001', 'T1021.001', 'T1003.001', 'T1041', 'T1071.001', 'T1083', 'T1016', 'T1057'] },
  { name: 'Mustang Panda', mitre: 'Mustang Panda', aliases: ['TA416'], country: 'China', motivation: ['Information Theft & Espionage'], industries: ['Government', 'Education', 'Non-Governmental Organizations (NGOs)'], victimCountries: ['Myanmar', 'Mongolia', 'Vietnam'], ttps: ['T1566.002', 'T1059.001', 'T1021.001', 'T1003.001', 'T1041', 'T1071.001', 'T1105', 'T1083', 'T1018', 'T1057'] },
  { name: 'Scattered Spider', mitre: 'Scattered Spider', aliases: ['UNC3944', 'Octo Tempest'], country: 'United States of America (USA)', motivation: ['Financial Gain'], industries: ['Telecommunications (Telecoms)', 'Technology', 'Hospitality'], victimCountries: ['United States of America (USA)', 'United Kingdom (UK)'], ttps: ['T1078', 'T1566.002', 'T1059.001', 'T1021.001', 'T1003.001', 'T1048', 'T1071.001', 'T1105', 'T1083', 'T1016'] },
  { name: 'Storm-3069', mitre: 'Storm-3069', aliases: ['NeedyMantis operator'], country: 'China', motivation: ['Sabotage & Destruction', 'Information Theft & Espionage'], industries: ['Critical Infrastructure', 'Telecommunications (Telecoms)', 'Government'], victimCountries: ['Taiwan', 'Philippines', 'United States of America (USA)'], ttps: ['T1566.002', 'T1078', 'T1059.007', 'T1021.004', 'T1003.002', 'T1041', 'T1071.001', 'T1105', 'T1018', 'T1033'] },
];

const TM_FALLBACK_INTEL = [
  { id: 'ci_00', title: 'CISA Alert AA22-216A: 2021 Top Malware Strains - All Malware TTPs Combined (August 2022)', techniques: [{ techniqueID: 'T1059.001', score: 10 }, { techniqueID: 'T1059.003', score: 9 }, { techniqueID: 'T1059.007', score: 6 }, { techniqueID: 'T1021.001', score: 9 }, { techniqueID: 'T1021.004', score: 8 }, { techniqueID: 'T1078', score: 10 }, { techniqueID: 'T1003.001', score: 7 }, { techniqueID: 'T1003.002', score: 5 }, { techniqueID: 'T1048', score: 8 }, { techniqueID: 'T1041', score: 9 }, { techniqueID: 'T1105', score: 10 }, { techniqueID: 'T1071.001', score: 9 }, { techniqueID: 'T1083', score: 8 }, { techniqueID: 'T1057', score: 7 }, { techniqueID: 'T1016', score: 6 }] },
  { id: 'ci_01', title: 'The DFIR Report BumbleBee Roasts Its Way to Domain Admin (August 2022)', techniques: [{ techniqueID: 'T1566.002', score: 2 }, { techniqueID: 'T1059.001', score: 3 }, { techniqueID: 'T1021.001', score: 3 }, { techniqueID: 'T1003.001', score: 2 }, { techniqueID: 'T1071.001', score: 2 }, { techniqueID: 'T1083', score: 2 }] },
  { id: 'ci_02', title: "LockBit 3.0 Update | Unpicking the Ransomware's Latest Anti-Analysis and Evasion Techniques - SentinelOne (July 2022)", techniques: [{ techniqueID: 'T1027', score: 4 }, { techniqueID: 'T1059.001', score: 2 }, { techniqueID: 'T1486', score: 3 }, { techniqueID: 'T1070.004', score: 2 }, { techniqueID: 'T1112', score: 2 }] },
];

/* ---------------- State ---------------- */
const TM = {
  adversaries: [],   // normalized adversary records
  intel: [],         // {id,title,file?,techniques?[{techniqueID,score}]}
  tactics: new Map(),// techniqueID -> {tactic, name}
  sel: { motive: new Set(), industry: new Set(), base: new Set(), victim: new Set() },
  category: '',      // selected whole-category id
  adversary: '',     // selected adversary name
  intelId: '',       // selected intel report id
  scope: null,       // {name, desc, scores: Map(id->score), groups?: string[]}
  layer: null,
};

/* Normalize one cvc.json record into the working schema. */
function tmNorm(r) {
  return {
    name: r.name || r.mitre || 'Unknown',
    mitre: r.mitre || r.name || '',
    aliases: r.aliases || [],
    base: r.country || '',
    motivation: r.motivation || [],
    industries: r.industries || [],
    victimCountries: r.victimCountries || r.victim_countries || [],
    ttps: (r.ttps || []).map((t) => (typeof t === 'string' ? t : (t.technique_id || t.id || ''))).filter(Boolean),
    description: r.description || '',
    url: r.url || r.mitreUrl || '',
  };
}

/* Merge canonical option list with values actually present in data. */
function tmOptions(canonical, present) {
  const out = [...canonical];
  [...new Set(present.filter(Boolean))]
    .filter((v) => !out.includes(v))
    .sort((a, b) => a.localeCompare(b))
    .forEach((v) => out.push(v));
  // keep canonical order; drop canonical entries with zero coverage? NO —
  // spec requires every listed option present, so keep all of them.
  return out;
}

/* ---------------- Boot ---------------- */
async function tmBoot() {
  let dataNote = '';
  try {
    const r = await fetch('data/cvc.json');
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const raw = await r.json();
    TM.adversaries = (Array.isArray(raw) ? raw : []).map(tmNorm).filter((a) => a.name);
    if (!TM.adversaries.length) throw new Error('empty cvc.json');
  } catch (e) {
    TM.adversaries = TM_FALLBACK_ADVERSARIES.map(tmNorm);
    dataNote = `Local data/cvc.json unavailable (${e.message}) — showing embedded sample data.`;
  }

  try {
    const r = await fetch('data/intel/index.json');
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    TM.intel = await r.json();
  } catch {
    TM.intel = TM_FALLBACK_INTEL.map(({ id, title, techniques }) => ({ id, title, techniques }));
  }

  try {
    const r = await fetch('data/techniques.json');
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const techs = await r.json();
    const order = new Map(TM_TACTIC_ORDER.map((t, i) => [t.toLowerCase(), i]));
    (Array.isArray(techs) ? techs : []).forEach((t) => {
      if (!t || !t.id) return;
      TM.tactics.set(t.id, {
        tactic: t.tactic || (Array.isArray(t.tactics) && t.tactics[0]) || 'Other',
        name: t.name || t.id,
        url: t.url || `https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`,
      });
    });
    TM._tacticRank = (name) => {
      const i = order.get(String(name || '').toLowerCase());
      return i === undefined ? 999 : i;
    };
  } catch {
    TM._tacticRank = () => 999;
  }

  tmBuildFilters();
  tmBuildIntel();
  tmBind();
  tmRecalc();
  if (dataNote) {
    const el = TM$('#tm-datanote');
    if (el) { el.textContent = dataNote; el.hidden = false; }
  }
}

/* ---------------- Filters ---------------- */
function tmChip(value, group) {
  return `<label class="tm-chip"><input type="checkbox" data-tm-group="${group}" value="${TMesc(value)}"><span>${TMesc(value)}</span></label>`;
}

function tmBuildFilters() {
  const A = TM.adversaries;
  const set = (sel, html) => { const el = TM$(sel); if (el) el.innerHTML = html; };
  set('#tm-f-motive', tmOptions(TM_MOTIVES, A.flatMap((x) => x.motivation)).map((v) => tmChip(v, 'motive')).join(''));
  set('#tm-f-industry', tmOptions(TM_INDUSTRIES, A.flatMap((x) => x.industries)).map((v) => tmChip(v, 'industry')).join(''));
  set('#tm-f-base', tmOptions(TM_BASES, A.map((x) => x.base)).map((v) => tmChip(v, 'base')).join(''));
  set('#tm-f-victim', tmOptions(TM_VICTIMS, A.flatMap((x) => x.victimCountries)).map((v) => tmChip(v, 'victim')).join(''));
}

function tmBuildIntel() {
  const sel = TM$('#tm-intel');
  if (!sel) return;
  sel.innerHTML = '<option value="">— Select a report —</option>' + TM.intel.map((r) =>
    `<option value="${TMesc(r.id)}">${TMesc(r.title)}</option>`).join('');
}

/* OR within a group, AND across groups. */
function tmMatch(a) {
  const s = TM.sel;
  if (s.motive.size && !(a.motivation || []).some((v) => s.motive.has(v))) return false;
  if (s.industry.size && !(a.industries || []).some((v) => s.industry.has(v))) return false;
  if (s.base.size && !s.base.has(a.base)) return false;
  if (s.victim.size && !(a.victimCountries || []).some((v) => s.victim.has(v))) return false;
  return true;
}

function tmFiltered() {
  return TM.adversaries.filter(tmMatch).sort((a, b) => a.name.localeCompare(b.name));
}

/* Categories present in the current scope, grouped by kind. */
function tmCategoriesIn(scope) {
  const groups = [
    ['Motive', 'motive', (a) => a.motivation || []],
    ['Victim industry', 'industry', (a) => a.industries || []],
    ['Adversary base', 'base', (a) => (a.base ? [a.base] : [])],
    ['Victim location', 'victim', (a) => a.victimCountries || []],
  ];
  return groups.map(([label, kind, get]) => {
    const map = new Map();
    scope.forEach((a) => get(a).forEach((v) => {
      if (!v) return;
      if (!map.has(v)) map.set(v, []);
      map.get(v).push(a);
    }));
    return {
      label, kind,
      items: [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]))
        .map(([id, advs]) => ({ id, kind, adversaries: advs })),
    };
  }).filter((g) => g.items.length);
}

/* ---------------- Render: results + tags ---------------- */
function tmRecalc() {
  const scope = tmFiltered();
  tmRenderCats(scope);
  tmRenderAdvs(scope);
  tmRenderTags();
}

function tmRenderCats(scope) {
  const box = TM$('#tm-cat-list');
  if (!box) return;
  const groups = tmCategoriesIn(scope);
  if (!groups.length) {
    box.innerHTML = '<p class="tm-empty">No adversaries match selected criteria</p>';
    return;
  }
  box.innerHTML = groups.map((g) => `
    <div class="tm-cat-group">${TMesc(g.label)}</div>
    ${g.items.map((c) => `
      <button class="tm-item${TM.category === c.kind + ':' + c.id ? ' selected' : ''}"
        data-tm-cat="${TMesc(c.kind + ':' + c.id)}">
        <span>${TMesc(c.id)}</span><span class="count">${c.adversaries.length} adv</span>
      </button>`).join('')}`).join('');
}

function tmRenderAdvs(scope) {
  const box = TM$('#tm-adv-list');
  if (!box) return;
  const q = (TM$('#tm-adv-q')?.value || '').trim().toLowerCase();
  const res = scope.filter((a) => !q || a.name.toLowerCase().includes(q)
    || (a.aliases || []).join(' ').toLowerCase().includes(q));
  const count = TM$('#tm-adv-count');
  if (count) count.textContent = `${res.length} of ${TM.adversaries.length} adversaries`;
  box.innerHTML = res.length ? res.map((a) => `
    <button class="tm-item${TM.adversary === a.name ? ' selected' : ''}" data-tm-adv="${TMesc(a.name)}">
      <span>${TMesc(a.name)}${a.aliases?.length ? ` <span class="count">${TMesc(a.aliases.slice(0, 2).join(', '))}</span>` : ''}</span>
      <span class="count">${(a.ttps || []).length} TTPs</span>
    </button>`).join('')
    : '<p class="tm-empty">No adversaries match selected criteria</p>';
}

function tmRenderTags() {
  const box = TM$('#tm-tags');
  if (!box) return;
  const tags = [];
  [['motive', 'Motive'], ['industry', 'Industry'], ['base', 'Base'], ['victim', 'Victim']].forEach(([k, label]) =>
    [...TM.sel[k]].forEach((v) => tags.push({ k, v, label: `${label}: ${v}` })));
  box.innerHTML = tags.length
    ? `<span class="tm-help">Active filters:</span>` + tags.map((t) =>
      `<span class="tm-tag">${TMesc(t.label)}<button data-tm-untag="${TMesc(t.k + ':' + t.v)}" aria-label="Remove filter ${TMesc(t.label)}">×</button></span>`).join('')
    : '';
}

/* ---------------- Render: output (matrix + layer) ---------------- */
function tmSetScope(name, desc, scores) {
  TM.scope = { name, desc, scores };
  const counts = scores instanceof Map ? scores : new Map(Object.entries(scores || {}));
  TM.layer = (typeof buildLayer === 'function')
    ? buildLayer(name, desc, counts)
    : { name, description: desc, techniques: [...counts.entries()].map(([techniqueID, score]) => ({ techniqueID, score })) };
  tmRenderOutput();
}

function tmHeatColor(score, max) {
  // gradient #ffffff -> #ff6666
  const t = max > 0 ? score / max : 0;
  const g = Math.round(255 - 153 * t);
  return `rgb(255, ${g}, ${g})`;
}

function tmRenderOutput() {
  const head = TM$('#tm-output-name');
  const empty = TM$('#tm-output-empty');
  const body = TM$('#tm-output-body');
  if (!head || !body) return;
  if (!TM.scope) {
    head.textContent = '—';
    if (empty) empty.hidden = false;
    body.innerHTML = '';
    return;
  }
  head.textContent = TM.scope.name;
  if (empty) empty.hidden = true;

  const entries = [...TM.scope.scores.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const max = entries.reduce((m, [, s]) => Math.max(m, s), 0) || 1;

  // group technique IDs by tactic
  const cols = new Map(); // tactic -> [{id, score, name, url}]
  entries.forEach(([id, score]) => {
    const meta = TM.tactics.get(id) || { tactic: 'Other', name: id, url: `https://attack.mitre.org/techniques/${id.replace('.', '/')}/` };
    const tac = meta.tactic || 'Other';
    if (!cols.has(tac)) cols.set(tac, []);
    cols.get(tac).push({ id, score, name: meta.name, url: meta.url });
  });
  const rank = TM._tacticRank || (() => 999);
  const ordered = [...cols.entries()].sort((a, b) => rank(a[0]) - rank(b[0]) || a[0].localeCompare(b[0]));

  const layerJson = JSON.stringify(TM.layer, null, 2);
  const jsonBox = TM$('#tm-layer-json');
  if (jsonBox) jsonBox.value = layerJson;

  body.innerHTML = `
    <p class="tm-help">${TMesc(TM.scope.desc)} · <b>${entries.length}</b> techniques · max score <b>${max}</b></p>
    <div class="tm-toolbar">
      <button class="tm-btn" id="tm-dl">ATT&amp;CK Navigator Layer (TTPs)</button>
      <button class="tm-btn-ghost" id="tm-copy">Copy JSON</button>
      <button class="tm-btn-ghost" id="tm-open">Open in Navigator</button>
    </div>
    <div class="tm-matrix-wrap" role="region" aria-label="ATT&CK matrix" tabindex="0">
      <div class="tm-matrix" style="grid-template-columns:repeat(${ordered.length || 1},minmax(150px,1fr))">
        ${ordered.map(([tac, cells]) => `
        <div class="tm-tactic-col">
          <h4>${TMesc(tac)} · ${cells.length}</h4>
          ${cells.sort((a, b) => b.score - a.score || a.id.localeCompare(b.id)).map((c) => `
          <button class="tm-cell" style="background:${tmHeatColor(c.score, max)}"
            title="${TMesc(c.id)} · ${TMesc(c.name)} — score ${c.score}"
            data-tm-url="${TMesc(c.url)}">
            <span class="tid">${TMesc(c.id)} · ${c.score}</span>
            <span class="tname">${TMesc(c.name)}</span>
          </button>`).join('')}
        </div>`).join('') || '<p class="tm-empty">No techniques in scope.</p>'}
      </div>
    </div>
    <details style="margin-top:12px">
      <summary style="cursor:pointer;font-weight:600">ATT&amp;CK Navigator Layer (JSON)</summary>
      <textarea class="tm-json" rows="10" readonly spellcheck="false">${TMesc(layerJson)}</textarea>
    </details>`;

  const dl = TM$('#tm-dl');
  if (dl) dl.addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(TM.layer, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${(TM.scope.name || 'layer').replace(/[^\w.-]+/g, '_')}_attack_layer.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  });
  const cp = TM$('#tm-copy');
  if (cp) cp.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(JSON.stringify(TM.layer, null, 2)); cp.textContent = 'Copied!'; }
    catch { cp.textContent = 'Copy failed — select the JSON below'; }
    setTimeout(() => (cp.textContent = 'Copy JSON'), 1500);
  });
  const op = TM$('#tm-open');
  if (op) op.addEventListener('click', () => {
    const url = (typeof navigatorUrl === 'function')
      ? navigatorUrl(TM.layer)
      : 'https://mitre-attack.github.io/attack-navigator/';
    window.open(url, '_blank', 'noopener');
  });
  body.querySelectorAll('[data-tm-url]').forEach((b) => b.addEventListener('click', () =>
    window.open(b.dataset.tmUrl, '_blank', 'noopener')));
}

/* ---------------- Select: category / adversary / intel ---------------- */
function tmSelectCategory(kind, id) {
  TM.category = kind + ':' + id;
  TM.adversary = '';
  TM.intelId = '';
  const syncSel = TM$('#tm-intel');
  if (syncSel) syncSel.value = '';
  const scope = tmFiltered();
  const advs = scope.filter((a) => {
    if (kind === 'motive') return (a.motivation || []).includes(id);
    if (kind === 'industry') return (a.industries || []).includes(id);
    if (kind === 'base') return a.base === id;
    return (a.victimCountries || []).includes(id);
  });
  const counts = new Map();
  advs.forEach((a) => new Set(a.ttps || []).forEach((t) => counts.set(t, (counts.get(t) || 0) + 1)));
  tmSetScope(id, `All adversaries matching: ${id} (${advs.length} in scope)`, counts);
  tmRenderCats(scope);
  tmRenderAdvs(scope);
}

function tmSelectAdversary(name) {
  const a = TM.adversaries.find((x) => x.name === name);
  if (!a) return;
  TM.adversary = name;
  TM.category = '';
  TM.intelId = '';
  const syncSel = TM$('#tm-intel');
  if (syncSel) syncSel.value = '';
  const counts = new Map();
  new Set(a.ttps || []).forEach((t) => counts.set(t, 1));
  tmSetScope(a.name, `Adversary-specific layer. Score = 1 when the adversary is attributed to the technique.`, counts);
  tmRenderCats(tmFiltered());
  tmRenderAdvs(tmFiltered());
  TM$('#tm-output')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function tmSelectIntel(id) {
  const rec = TM.intel.find((r) => r.id === id);
  if (!rec) return;
  TM.intelId = id;
  TM.adversary = '';
  TM.category = '';
  let techs = rec.techniques || null;
  if (!techs && rec.file) {
    try {
      const r = await (await fetch(rec.file)).json();
      techs = r.techniques || [];
    } catch { techs = []; }
  }
  const counts = new Map((techs || []).map((t) => [t.techniqueID, t.score ?? 1]));
  tmSetScope(rec.title, `Pre-computed intelligence layer (${counts.size} techniques).`, counts);
  tmRenderCats(tmFiltered());
  tmRenderAdvs(tmFiltered());
  TM$('#tm-output')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* ---------------- Events ---------------- */
function tmBind() {
  const on = (sel, ev, fn) => { const el = TM$(sel); if (el) el.addEventListener(ev, fn); };

  ['#tm-f-motive', '#tm-f-industry', '#tm-f-base', '#tm-f-victim'].forEach((box) => {
    const el = TM$(box);
    if (!el) return;
    el.addEventListener('change', (e) => {
      const input = e.target.closest('input[data-tm-group]');
      if (!input) return;
      const set = TM.sel[input.dataset.tmGroup];
      if (!set) return;
      input.checked ? set.add(input.value) : set.delete(input.value);
      // a manual filter change clears any pinned selection
      TM.category = ''; TM.adversary = ''; TM.intelId = '';
      const syncSel = TM$('#tm-intel');
      if (syncSel) syncSel.value = '';
      TM.scope = null; TM.layer = null;
      tmRenderOutput();
      tmRecalc();
    });
  });

  on('#tm-cat-list', 'click', (e) => {
    const b = e.target.closest('[data-tm-cat]');
    if (!b) return;
    const [kind, ...rest] = b.dataset.tmCat.split(':');
    tmSelectCategory(kind, rest.join(':'));
  });
  on('#tm-adv-list', 'click', (e) => {
    const b = e.target.closest('[data-tm-adv]');
    if (!b) return;
    tmSelectAdversary(b.dataset.tmAdv);
  });
  on('#tm-adv-q', 'input', () => tmRenderAdvs(tmFiltered()));
  on('#tm-tags', 'click', (e) => {
    const b = e.target.closest('[data-tm-untag]');
    if (!b) return;
    const [k, ...rest] = b.dataset.tmUntag.split(':');
    const v = rest.join(':');
    TM.sel[k]?.delete(v);
    // uncheck the matching box directly
    TM$$(`#tm-filters input[data-tm-group="${k}"]`).forEach((i) => { if (i.value === v) i.checked = false; });
    TM.category = ''; TM.adversary = ''; TM.intelId = '';
    TM.scope = null; TM.layer = null;
    tmRenderOutput();
    tmRecalc();
  });
  on('#tm-clear', 'click', () => {
    Object.values(TM.sel).forEach((s) => s.clear());
    TM$$('#tm-filters input[type=checkbox]').forEach((c) => (c.checked = false));
    const q = TM$('#tm-adv-q');
    if (q) q.value = '';
    TM.category = ''; TM.adversary = ''; TM.intelId = '';
    const syncSel = TM$('#tm-intel');
    if (syncSel) syncSel.value = '';
    TM.scope = null; TM.layer = null;
    tmRenderOutput();
    tmRecalc();
  });
  on('#tm-intel', 'change', (e) => { if (e.target.value) tmSelectIntel(e.target.value); });
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', tmBoot);
else tmBoot();
