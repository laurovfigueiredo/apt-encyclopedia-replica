/* actor.js — dedicated actor profile page (actor.html?id=<actor-id>).
   Renders every field in data/actors.json, including the ones the groups
   modal skips: profile.overview/mandate/origin, notableOperations,
   cyllexPosts, firstSeen/lastSeen, industries, motivation, victimCountries,
   malpediaSlug, verifiedOn, and per-technique sources. */

(function () {
  const $ = (s, r = document) => r.querySelector(s);
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  function srcLink(s) {
    if (!s) return '';
    const label = esc(s.publisher || s.title || s.url || 'source');
    const extra = [s.title && s.publisher ? ` · ${esc(s.title)}` : '', s.date ? ` · ${esc(s.date)}` : ''].join('');
    return s.url
      ? `<a class="badge" href="${esc(s.url)}" target="_blank" rel="noopener">${label}${extra}</a>`
      : `<span class="badge">${label}${extra}</span>`;
  }

  function renderActor(a, all) {
    const body = $('#actor-body');
    if (!body) return;
    document.title = `APT Encyclopedia — ${a.name}`;

    const facts = [
      ['Country', a.country],
      ['Attribution', a.attribution],
      ['Threat level', a.threatLevel],
      ['Sophistication', a.sophistication],
      ['Status', a.active ? 'Active' : 'Inactive'],
      ['Campaigns', a.campaigns],
      ['First seen', a.firstSeen],
      ['Last seen', a.lastSeen],
      ['MITRE ID', a.mitreId],
      ['Malpedia', a.malpediaSlug],
      ['Verified on', a.verifiedOn],
      ['Motivation', (a.motivation || []).join(', ')],
    ].filter(([, v]) => v !== undefined && v !== null && v !== '');

    const prof = a.profile || {};
    const dm = a.diamondModel || {};
    const techs = a.techniques || [];
    const ops = a.notableOperations || [];
    const posts = a.cyllexPosts || [];
    const refs = a.reports || [];

    const tactics = [...new Set(techs.map((t) => t.tactic).filter(Boolean))];

    body.innerHTML = `
      <h2>${esc(a.name)}</h2>
      <div class="meta">${[a.mitreId ? `MITRE: ${esc(a.mitreId)}` : '', a.country ? `Country: ${esc(a.country)}` : '', `Threat: ${esc(a.threatLevel || '—')}`, a.active ? 'Active' : 'Inactive'].filter(Boolean).join(' · ')}</div>
      ${a.aliases?.length ? `<div class="badges" style="margin-top:8px">${a.aliases.map((x) => `<span class="badge">${esc(x)}</span>`).join('')}</div>` : ''}
      ${a.description ? `<p class="prose" style="margin-top:12px">${esc(a.description)}</p>` : ''}

      <dl class="facts" style="margin-top:16px">
        ${facts.map(([k, v]) => `<div class="fact"><dt>${esc(k)}</dt><dd>${esc(String(v))}</dd></div>`).join('')}
      </dl>

      ${(a.industries?.length || a.targetSectors?.length || a.victimCountries?.length) ? `
      <h3 class="mt">Targeting</h3>
      <div class="badges">
        ${(a.targetSectors || []).map((x) => `<span class="badge">sector: ${esc(x)}</span>`).join('')}
        ${(a.industries || []).map((x) => `<span class="badge">industry: ${esc(x)}</span>`).join('')}
        ${(a.victimCountries || []).slice(0, 30).map((x) => `<span class="badge">${esc(String(x).replace(' (Victim Country)', ''))}</span>`).join('')}
        ${(a.victimCountries || []).length > 30 ? `<span class="badge">+${(a.victimCountries || []).length - 30} more</span>` : ''}
      </div>` : ''}

      ${(prof.overview?.length || prof.mandate || prof.origin || prof.attribution) ? `
      <h3 class="mt">Profile</h3>
      ${(prof.overview || []).map((p) => `<p class="prose">${esc(p)}</p>`).join('')}
      ${prof.mandate ? `<p class="tech"><b>Mandate:</b> ${esc(prof.mandate)}</p>` : ''}
      ${prof.origin ? `<p class="tech"><b>Origin:</b> ${esc(prof.origin)}</p>` : ''}
      ${prof.attribution ? `<p class="tech"><b>Attribution:</b> ${esc(prof.attribution)}</p>` : ''}` : ''}

      ${a.malware?.length ? `
      <h3 class="mt">Malware &amp; Tools (${a.malware.length})</h3>
      <div class="badges">${a.malware.map((x) => `<span class="badge">${esc(x)}</span>`).join('')}</div>` : ''}

      ${ops.length ? `
      <h3 class="mt">Notable Operations (${ops.length})</h3>
      ${ops.map((o) => `<div class="card" style="margin-top:10px">
        <div class="row-title">${esc(o.name || '')} ${o.year ? `<span class="muted">· ${esc(o.year)}</span>` : ''}</div>
        ${o.summary ? `<p class="tech">${esc(o.summary)}</p>` : ''}
        ${o.affectedSectors?.length ? `<div class="badges">${o.affectedSectors.map((x) => `<span class="badge">${esc(x)}</span>`).join('')}</div>` : ''}
        ${o.primaryMalware?.length ? `<p class="tech">Malware: ${o.primaryMalware.map((x) => esc(x)).join(', ')}</p>` : ''}
        ${(o.sources || []).length ? `<div class="badges">${o.sources.map(srcLink).join('')}</div>` : ''}
      </div>`).join('')}` : ''}

      ${techs.length ? (() => {
        const byTactic = new Map();
        techs.forEach((t) => {
          const k = (t.tactic || 'Uncategorized').trim() || 'Uncategorized';
          if (!byTactic.has(k)) byTactic.set(k, []);
          byTactic.get(k).push(t);
        });
        const ordered = [...byTactic.entries()].sort((a, b) => a[0].localeCompare(b[0]));
        ordered.forEach(([, list]) => list.sort((x, y) => String(x.id).localeCompare(String(y.id), undefined, { numeric: true })));
        return `
      <h3 class="mt">Tactics, Techniques &amp; Procedures (${techs.length} techniques · ${ordered.length} tactics)</h3>
      ${ordered.map(([tactic, list]) => `
      <h4 class="mt" style="text-transform:uppercase;letter-spacing:.04em;font-size:13px;color:var(--muted)">${esc(tactic)} [${list.length}]</h4>
      <div class="techlist">
        ${list.map((t) => `<div class="techitem">
          <div class="mono">${esc(t.id)}</div>
          <div><b>${esc(t.name || '')}</b></div>
          ${t.usage ? `<div class="tech">${esc(t.usage)}</div>` : ''}
          ${(t.sources || []).length ? `<div class="tech sources">${t.sources.slice(0, 4).map(srcLink).join('')}</div>` : ''}
        </div>`).join('')}
      </div>`).join('')}`;
      })() : '<h3 class="mt">Tactics, Techniques &amp; Procedures</h3><p class="muted">No techniques listed for this actor.</p>'}

      ${(() => {
        const peers = (all || [])
          .filter((x) => x.id !== a.id && (x.country || '') === (a.country || '') && a.country)
          .sort((x, y) => String(x.name).localeCompare(String(y.name)))
          .slice(0, 6);
        if (!peers.length) return '';
        return `
      <h3 class="mt">Related Groups (Same Country)</h3>
      <div class="grid">
        ${peers.map((x) => `<a class="card res-card" href="actor.html?id=${esc(x.id)}">
          <h3>${esc(x.name)}</h3>
          <p class="tech">${esc((x.aliases || []).slice(0, 3).join(' · '))}</p>
          <div class="meta">${esc(x.country || '')}${x.threatLevel ? ` · ${esc(x.threatLevel)}` : ''}${x.active ? ' · Active' : ''}</div>
        </a>`).join('')}
      </div>`;
      })()}

      <h3 class="mt">Diamond Model of Intrusion Analysis</h3>
      <div class="diamond">
        <div class="dcell d-adv"><h4>Adversary</h4>
          <p>${esc(a.name)}</p>
          ${a.attribution ? `<p class="tech">${esc(a.attribution)}</p>` : ''}
          ${a.country ? `<p class="tech">Base: ${esc(a.country)}</p>` : ''}
          ${dm.adversary ? `<p class="tech">${esc(typeof dm.adversary === 'string' ? dm.adversary : JSON.stringify(dm.adversary))}</p>` : ''}
        </div>
        <div class="dcell d-cap"><h4>Capability</h4>
          <p>${techs.length} techniques</p>
          ${a.sophistication ? `<p class="tech">Sophistication: ${esc(a.sophistication)}</p>` : ''}
          ${a.malware?.length ? `<p class="tech">Malware: ${esc(a.malware.slice(0, 6).join(', '))}${a.malware.length > 6 ? '…' : ''}</p>` : ''}
          ${dm.capability ? `<p class="tech">${esc(typeof dm.capability === 'string' ? dm.capability : JSON.stringify(dm.capability))}</p>` : ''}
        </div>
        <div class="dcell d-inf"><h4>Infrastructure</h4>
          ${dm.infrastructure ? `<p class="tech">${esc(typeof dm.infrastructure === 'string' ? dm.infrastructure : (dm.infrastructure.notes || JSON.stringify(dm.infrastructure)))}</p>` : '<p class="tech">C2 / domains / IPs — see linked reporting</p>'}
        </div>
        <div class="dcell d-vic"><h4>Victim</h4>
          ${a.targetSectors?.length ? `<p class="tech">Sectors: ${esc(a.targetSectors.slice(0, 6).join(', '))}${a.targetSectors.length > 6 ? '…' : ''}</p>` : '<p class="tech">—</p>'}
          ${a.victimCountries?.length ? `<p class="tech">Victim geo: ${esc(a.victimCountries.slice(0, 6).map((x) => String(x).replace(' (Victim Country)', '')).join(', '))}${a.victimCountries.length > 6 ? '…' : ''}</p>` : ''}
          ${dm.victim ? `<p class="tech">${esc(typeof dm.victim === 'string' ? dm.victim : JSON.stringify(dm.victim))}</p>` : ''}
        </div>
      </div>

      ${posts.length ? `
      <h3 class="mt">Cyllex Research (${posts.length})</h3>
      ${posts.map((p) => `<div class="card" style="margin-top:10px">
        <div class="row-title">${p.path ? `<a href="https://cyllex.io${esc(p.path)}" target="_blank" rel="noopener">${esc(p.title || p.path)}</a>` : esc(p.title || '')}</div>
        ${p.publishedDate ? `<div class="meta">Published: ${esc(p.publishedDate)}</div>` : ''}
        ${p.summary ? `<p class="tech">${esc(p.summary)}</p>` : ''}
      </div>`).join('')}` : ''}

      ${refs.length ? `<h3 class="mt">Intelligence Sources (${refs.length})</h3>
        <div class="techlist">${refs.slice(0, 40).map((r) => `<div class="techitem">
          <div class="mono">${esc(r.publisherType || r.type || '')}</div>
          <div><b>${r.url ? `<a href="${esc(r.url)}" target="_blank" rel="noopener">${esc(r.title || r.url)}</a>` : esc(r.title || '')}</b>
          ${r.publisher ? ` <span class="tech">· ${esc(r.publisher)}</span>` : ''}</div>
          ${r.summary ? `<div class="tech">${esc(r.summary)}</div>` : ''}
          <div class="tech">${[r.publishedDate ? `Published: ${esc(r.publishedDate)}` : '', r.verifiedOn ? `Verified: ${esc(r.verifiedOn)}` : '', r.linkStatus ? `Link: ${esc(r.linkStatus)}` : ''].filter(Boolean).join(' · ')}</div>
        </div>`).join('')}</div>
        ${refs.length > 40 ? `<p class="muted">showing 40 of ${refs.length}</p>` : ''}` : ''}
    `;
  }

  async function boot() {
    const body = $('#actor-body');
    const id = new URLSearchParams(location.search).get('id');
    if (!id) {
      if (body) body.innerHTML = '<p class="tag-warn">Missing actor id. Pick one in <a href="groups.html">APT Groups</a>.</p>';
      return;
    }
    try {
      const r = await fetch('data/actors.json');
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const actors = await r.json();
      const a = actors.find((x) => x.id === id);
      if (!a) {
        if (body) body.innerHTML = `<p class="tag-warn">Unknown actor: ${esc(id)}. Pick one in <a href="groups.html">APT Groups</a>.</p>`;
        return;
      }
      renderActor(a, actors);
    } catch (e) {
      if (body) body.innerHTML = `<p class="tag-warn">Could not load actor data: ${esc(e.message)}</p>`;
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
