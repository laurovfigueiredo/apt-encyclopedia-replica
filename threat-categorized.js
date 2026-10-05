fetch('data/cvc.json').then(r=>r.json()).then(data=>{
  const all = document.getElementById('adversary-all');
  data.sort((a,b)=>(a.name||'').localeCompare(b.name||'')).forEach(x=>{
    const parts = [];
    if(x.name) parts.push(x.name);
    if(x.aliases && x.aliases.length) parts.push(x.aliases.join(', '));
    const span = document.createElement('div');
    span.textContent = parts.join(', ');
    all.appendChild(span);
  });
});
