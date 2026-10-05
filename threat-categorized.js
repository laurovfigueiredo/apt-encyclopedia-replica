fetch('data/cvc.json').then(r=>r.json()).then(data=>{
  const all = document.getElementById('adversary-all');
  if(!all) return;
  const items = data.map(x=>x.name).sort();
  all.innerHTML = items.map(i=>'<div>'+i+'</div>').join('');
});
