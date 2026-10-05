fetch('data/summary.json').then(r=>r.json()).then(data=>{
  const grid = document.getElementById('grid');
  const search = document.getElementById('search');
  const count = document.getElementById('count');
  function render(list){
    grid.innerHTML = '';
    list.forEach(a=>{
      const card = document.createElement('div');
      card.className = 'card';
      const aliases = (a.aliases||[]).slice(0,4).join(', ');
      const tags = (a.tags||[]).slice(0,5).map(t=>`<span class="badge">${t}</span>`).join('');
      card.innerHTML = `
        <h3><a href="group.html?id=${a.id}">${a.name}</a></h3>
        ${a.aliases&&a.aliases.length?'<div class="meta">Aliases: '+aliases+(a.aliases.length>4?'...':'')+'</div>':''}
        <div class="badges">${tags}</div>
        <div class="tech">${a.techniqueCount} techniques · ${a.country||'Unknown'}</div>
      `;
      grid.appendChild(card);
    });
    count.textContent = list.length;
  }
  search.addEventListener('input', ()=>{
    const q = search.value.toLowerCase();
    const f = data.filter(x=>{
      return x.name.toLowerCase().includes(q) || (x.aliases||[]).join(' ').toLowerCase().includes(q) || (x.id||'').includes(q);
    });
    render(f);
  });
  render(data);
});
