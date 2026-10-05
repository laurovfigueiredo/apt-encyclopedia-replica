const params = new URLSearchParams(location.search);
const id = params.get('id');
fetch('data/actors.json').then(r=>r.json()).then(actors=>{
  const a = actors.find(x=>x.id===id);
  const main = document.getElementById('main');
  if(!a){ main.innerHTML='<p>Not found</p>'; return; }
  const tech = (a.techniques||[]).map(t=>{
    return `<div class="card"><h3>${t.id} - ${t.name}</h3><div class="meta">Tactic: ${t.tactic||'-'}</div><div class="tech">${t.usage||t.description||''}</div></div>`;
  }).join('');
  const diamond = a.diamondModel || {};
  const dm = `
    <div class="card" style="margin-bottom:16px">
      <h3 style="margin:0 0 10px">Diamond Model of Intrusion Analysis</h3>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px">
        <div>
          <h4 style="margin:0 0 6px;color:#3b82f6">Adversary</h4>
          <div class="meta">${diamond.adversary?.name||a.name}</div>
          ${diamond.adversary?.aliases?.length?'<div class="meta">Aliases: '+diamond.adversary.aliases.join(', ')+'</div>':''}
          ${diamond.adversary?.country?'<div class="meta">Country: '+diamond.adversary.country+'</div>':''}
        </div>
        <div>
          <h4 style="margin:0 0 6px;color:#10b981">Capability</h4>
          ${diamond.capability?.sophistication?'<div class="meta">Sophistication: '+diamond.capability.sophistication+'</div>':''}
          ${diamond.capability?.malware?.length?'<div class="meta">Malware: '+diamond.capability.malware.join(', ')+'</div>':''}
          <div class="meta">${(diamond.capability?.techniques||[]).length} key techniques</div>
        </div>
        <div>
          <h4 style="margin:0 0 6px;color:#f59e0b">Infrastructure</h4>
          <div class="meta">${diamond.infrastructure?.notes||'-'}</div>
        </div>
        <div>
          <h4 style="margin:0 0 6px;color:#ef4444">Victim</h4>
          ${diamond.victim?.sectors?.length?'<div class="meta">Sectors: '+diamond.victim.sectors.join(', ')+'</div>':''}
          <div class="meta">${diamond.meta?.model||'Diamond Model'}</div>
        </div>
      </div>
    </div>
  `;
  main.innerHTML = `
    <div class="card" style="margin-bottom:16px">
      <h2 style="margin:0 0 10px">${a.name}</h2>
      ${a.aliases&&a.aliases.length?'<div class="meta">Aliases: '+a.aliases.join(', ')+'</div>':''}
      <div class="badges">${(a.tags||[]).map(t=>'<span class="badge">'+t+'</span>').join('')}</div>
      <div class="meta">Country: ${a.country||'-'} · MITRE: ${a.mitreId||'-'}</div>
      ${(a.references||[]).slice(0,8).map(r=>'<div><a href="'+r.url+'" target="_blank">'+r.publisher+': '+r.title+'</a></div>').join('')}
    </div>
    ${dm}
    <h3 style="margin:20px 0 12px">Techniques (${a.techniques?a.techniques.length:0})</h3>
    <div class="grid">${tech||'<p class="muted">No techniques listed</p>'}</div>
  `;
});
