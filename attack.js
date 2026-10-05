fetch('data/techniques.json').then(r=>r.json()).then(data=>{
  const grid = document.getElementById('grid');
  const search = document.getElementById('search');
  const count = document.getElementById('count');
  // sort by id
  data.sort((a,b)=>a.id.localeCompare(b.id));
  function render(list){
    grid.innerHTML = '';
    list.forEach(t=>{
      const card = document.createElement('div');
      card.className = 'card';
      card.innerHTML = `
        <h3>${t.id} - ${t.name||''}</h3>
        ${t.tactic?'<div class="meta">Tactic: '+t.tactic+'</div>':''}
        ${t.groups&&t.groups.length?'<div class="meta">Used by: '+t.groups.slice(0,6).join(', ')+(t.groups.length>6?'... ('+t.groups.length+')':'')+'</div>':''}
        ${t.description?'<div class="tech">'+t.description+'</div>':''}
      `;
      grid.appendChild(card);
    });
    count.textContent = list.length;
  }
  search.addEventListener('input', ()=>{
    const q = search.value.toLowerCase();
    const f = data.filter(x=>{
      return (x.id||'').toLowerCase().includes(q) || (x.name||'').toLowerCase().includes(q) || (x.tactic||'').toLowerCase().includes(q) || (x.groups||[]).join(' ').toLowerCase().includes(q);
    });
    render(f);
  });
  render(data);
});
