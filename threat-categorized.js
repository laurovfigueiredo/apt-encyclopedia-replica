fetch('data/cvc.json?v=2').then(r=>r.json()).then(data=>{
  const all = document.getElementById('adversary-all');
  if(!all) return;
  const items = [];
  data.forEach(x=>{
    items.push(x.name);
  });
  items.sort((a,b)=>a.localeCompare(b));
  all.innerHTML = items.map(i=>`<div>${i}</div>`).join('');
  document.getElementById('count').textContent = data.length;
});
