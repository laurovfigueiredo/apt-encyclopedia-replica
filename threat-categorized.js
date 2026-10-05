fetch('data/cvc.json?v=1').then(r=>r.json()).then(data=>{
  const all = document.getElementById('adversary-all');
  if(!all) return;
  const items = [];
  data.forEach(x=>{
    const parts = [];
    if(x.name) parts.push(x.name);
    (x.aliases||[]).forEach(a=>{ if(a && a!==x.name) parts.push(a); });
    items.push(parts.join(', '));
  });
  items.sort();
  all.innerHTML = items.map(i=>`<div>${i}</div>`).join('');
});
