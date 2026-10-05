/* ------------------------------------------------------------------
   ATT&CK Navigator layer builder
   Scores are computed client-side from the 117 adversary TTP dumps:
   score = number of adversaries (in scope) that use the technique.
   Same scoring model used by the Control Validation Compass heatmaps
   (gradient #ffffff -> #ff6666).
------------------------------------------------------------------- */

const ATTACK_VERSIONS = { attack: '14', navigator: '4.9.1', layer: '4.5' };
const GRADIENT = ['#ffffff', '#ff6666'];
const PLATFORMS = ['Windows', 'Linux', 'macOS', 'Cloud', 'Containers', 'Network', 'IaaS', 'SaaS', 'Office 365', 'Google Workspace', 'Azure AD'];

const HEATMAP = {
  CATS: [],           // {id, type, adversaries:[]}
  BY_ID: new Map(),
  cvc: [],
  selected: new Set(), // category ids currently ticked in the filter panel
  advSel: new Set(),   // adversary names ticked individually in the list
  effective: [],       // adversaries left after individual picks narrow the criteria
  current: null,          // {layer, adversaries, name}
  selectedAdversary: '',  // mitre slug chosen via the "TTPs" button
};

const uniqIn = (a) => [...new Set(a.filter(Boolean))].sort((x, y) => x.localeCompare(y));

function buildCategories(cvc) {
  const cats = [];
  const push = (id, type, filter) => {
    const adversaries = cvc.filter(filter);
    if (!adversaries.length) return;
    const c = { id, type, adversaries };
    cats.push(c);
    HEATMAP.BY_ID.set(id, c);
  };

  uniqIn(cvc.flatMap((x) => x.motivation)).forEach((m) =>
    push(m, 'motive', (x) => (x.motivation || []).includes(m)));

  uniqIn(cvc.flatMap((x) => x.industries)).forEach((i) =>
    push(i, 'industry', (x) => (x.industries || []).includes(i)));

  uniqIn(cvc.map((x) => x.country).filter(Boolean)).forEach((c) =>
    push(c, 'base', (x) => x.country === c));

  uniqIn(cvc.flatMap((x) => x.victimCountries || [])).forEach((c) =>
    push(c, 'victim', (x) => (x.victimCountries || []).includes(c)));

  HEATMAP.CATS = cats;
}

function tally(adversaries) {
  const counts = new Map();
  adversaries.forEach((a) => {
    new Set(a.ttps || []).forEach((t) => counts.set(t, (counts.get(t) || 0) + 1));
  });
  return counts;
}

function buildLayer(name, description, counts) {
  const techniques = [...counts.entries()]
    .map(([id, score]) => ({ techniqueID: id, score }))
    .sort((a, b) => b.score - a.score || a.techniqueID.localeCompare(b.techniqueID));

  const maxValue = techniques.reduce((m, t) => Math.max(m, t.score), 0) || 1;

  return {
    name: (name || 'Threat Model').slice(0, 300),
    versions: { ...ATTACK_VERSIONS },
    domain: 'enterprise-attack',
    description: (description || '').slice(0, 500),
    filters: { platforms: PLATFORMS },
    sorting: 3,
    layout: { layout: 'side', showID: false, showName: true, showAggregateScores: false, countUnscored: false },
    hideDisabled: false,
    techniques,
    gradient: { colors: GRADIENT, minValue: 0, maxValue },
    legendItems: [],
    metadata: [],
    links: [],
    showTacticRowBackground: true,
    tacticRowBackground: '#dddddd',
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: false,
    selectVisibleTechniques: false,
  };
}

function navigatorUrl(layer) {
  const json = JSON.stringify(layer);
  return 'https://mitre-attack.github.io/attack-navigator/#leave_site_dialog=false&layer='
    + encodeURIComponent(json) + '&domain=enterprise-attack';
}

/* ---- selection resolution (mirrors the original combine semantics) ---- */
function selectedCategoryIds() {
  return [...HEATMAP.selected];
}

function setCriterionSelected(id, on) {
  on ? HEATMAP.selected.add(id) : HEATMAP.selected.delete(id);
}

function clearCriteria() {
  HEATMAP.selected.clear();
}

function adversariesForScope(scope, mode) {
  const cvc = HEATMAP.cvc;
  if (scope === 'adversary') {
    const mitre = HEATMAP.selectedAdversary;
    if (!mitre) return [];
    const x = cvc.find((c) => (c.mitre || '').toLowerCase() === String(mitre).toLowerCase());
    return x ? [x] : [];
  }
  const ids = selectedCategoryIds();
  if (!ids.length) return cvc;

  const sets = ids.map((id) => new Set((HEATMAP.BY_ID.get(id)?.adversaries || []).map((a) => a.name)));
  if (mode === 'intersect') {
    return cvc.filter((x) => sets.every((s) => s.has(x.name)));
  }
  return cvc.filter((x) => sets.some((s) => s.has(x.name)));  // union (default)
}