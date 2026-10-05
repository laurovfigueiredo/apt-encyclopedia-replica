fetch('data/cvc.json').then(r=>r.json()).then(data=>{
  // full adversary list with aliases
  const all = document.getElementById('adversary-all');
  data.sort((a,b)=>a.name.localeCompare(b.name)).forEach(x=>{
    const line = (x.name + (x.aliases&&x.aliases.length? ', '+x.aliases.join(', '):''));
    const span = document.createElement('div');
    span.textContent = line;
    all.appendChild(span);
  });
  
  const motivesDiv = document.getElementById('motives');
  const indsDiv = document.getElementById('industries');
  const cDiv = document.getElementById('countries');
  const listDiv = document.getElementById('list');
  const count = document.getElementById('count');
  const clear = document.getElementById('clear');
  
  const motives = [...new Set(data.flatMap(x=>x.motivation||[]))].sort();
  const inds = [...new Set(data.flatMap(x=>x.industries||[]))].sort();
  const countries = [...new Set(data.flatMap(x=>[x.country].concat(x.victimCountries||[])).filter(Boolean))].sort();
  
  function cb(id, group){
    const el = document.createElement('label');
    el.style.display='block';
    el.innerHTML = `<input type="checkbox" class="${group}" value="${id}" style="margin-right:6px">${id}`;
    return el;
  }
  motives.forEach(m=>motivesDiv.appendChild(cb(m,'motive')));
  inds.forEach(i=>indsDiv.appendChild(cb(i,'industry')));
  countries.forEach(c=>cDiv.appendChild(cb(c,'country')));
  
  function getSel(cls){ return [...document.querySelectorAll('.'+cls+':checked')].map(e=>e.value); }
  function match(x){
    const selM=getSel('motive'), selI=getSel('industry'), selC=getSel('country');
    if(selM.length && !(x.motivation||[]).some(m=>selM.includes(m))) return false;
    if(selI.length && !(x.industries||[]).some(i=>selI.includes(i))) return false;
    if(selC.length){ const allc=[x.country].concat(x.victimCountries||[]).filter(Boolean); if(!allc.some(c=>selC.includes(c))) return false; }
    return true;
  }
  function render(){
    const res = data.filter(match).sort((a,b)=>a.name.localeCompare(b.name));
    listDiv.innerHTML = res.map(x=>{
      const ttps = (x.ttps||[]).slice(0,5).map(t=>t.technique_id).join(', ');
      return `<div class="card" style="margin-bottom:8px;padding:12px">
        <div style="font-weight:600">${x.name} ${(x.aliases||[]).length? '· '+x.aliases.slice(0,3).join(', '):''}</div>
        <div class="meta">Motives: ${(x.motivation||[]).join(', ')||'-'} | Industries: ${(x.industries||[]).slice(0,4).join(', ')}${(x.industries||[]).length>4?'...':''}</div>
        <div class="meta">Country: ${x.country||'-'} | TTPs: ${ttps}${(x.ttps||[]).length>5?'...':''}</div>
      </div>`;
    }).join('');
    count.textContent = res.length;
    if(!res.length) listDiv.innerHTML='<div class="meta">No adversaries match selected criteria</div>';
  }
  document.querySelectorAll('input[type=checkbox]').forEach(e=>e.addEventListener('change',render));
  clear.addEventListener('click',()=>{ document.querySelectorAll('input[type=checkbox]').forEach(e=>e.checked=false); render(); });
  render();
});
