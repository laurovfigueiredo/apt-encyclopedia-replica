const params = new URLSearchParams(location.search);
const id = params.get('id');
fetch('data/actors.json').then(r=>r.json()).then(actors=>{
  const a = actors.find(x=>x.id===id);
  const main = document.getElementById('main');
  if(!a){ main.innerHTML='<p>Not found</p>'; return; }
  const tech = (a.techniques||[]).map(t=>{
    return `<div class="card"><h3>${t.id} - ${t.name}</h3><div class="meta">Tactic: ${t.tactic||'-'}</div><div class="tech">${t.usage||t.description||''}</div></div>`;
  }).join('');
  main.innerHTML = `
    <div class="card" style="margin-bottom:16px">
      <h2 style="margin:0 0 10px">${a.name}</h2>
      ${a.aliases&&a.aliases.length?'<div class="meta">Aliases: '+a.aliases.join(', ')+'</div>':''}
      <div class="badges">${(a.tags||[]).map(t=>'<span class="badge">'+t+'</span>').join('')}</div>
      <div class="meta">Country: ${a.country||'-'} · MITRE: ${a.mitreId||'-'}</div>
      ${(a.references||[]).slice(0,8).map(r=>'<div><a href="'+r.url+'" target="_blank">'+r.publisher+': '+r.title+'</a></div>').join('')}
    </div>
    <h3 style="margin:20px 0 12px">Techniques (${a.techniques?a.techniques.length:0})</h3>
    <div class="grid">${tech||'<p class="muted">No techniques listed</p>'}</div>
  `;
});
