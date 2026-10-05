fetch('data/actors.json').then(r=>r.json()).then(data=>{
  const grid = document.getElementById('grid');
  const q = document.getElementById('q');
  const country = document.getElementById('country');
  const threat = document.getElementById('threat');
  const status = document.getElementById('status');
  const count = document.getElementById('count');
  const clear = document.getElementById('clear');
  
  // populate filters
  const countries = [...new Set(data.map(x=>x.country).filter(Boolean))].sort();
  const threats = [...new Set(data.map(x=>x.threatLevel).filter(Boolean))].sort();
  countries.forEach(c=>{ const o=document.createElement('option'); o.value=c; o.textContent=c; country.appendChild(o); });
  threats.forEach(t=>{ const o=document.createElement('option'); o.value=t; o.textContent=t; threat.appendChild(o); });
  
  function match(a){
    const txt = (a.name+' '+(a.aliases||[]).join(' ')+' '+(a.malware||[]).join(' ')+' '+(a.techniques||[]).map(x=>x.name+x.id).join(' ')).toLowerCase();
    if(q.value && !txt.includes(q.value.toLowerCase())) return false;
    if(country.value && a.country !== country.value) return false;
    if(threat.value && a.threatLevel !== threat.value) return false;
    if(status.value){
      const act = !!a.active;
      if(status.value==='active' && !act) return false;
      if(status.value==='inactive' && act) return false;
    }
    return true;
  }
  function render(){
    const list = data.filter(match);
    grid.innerHTML = '';
    list.forEach(a=>{
      const card = document.createElement('div');
      card.className = 'card';
      card.innerHTML = `
        <h3><a href="group.html?id=${a.id}">${a.name}</a></h3>
        ${a.aliases&&a.aliases.length?'<div class="meta">Aliases: '+a.aliases.slice(0,3).join(', ')+'</div>':''}
        <div class="tech">Country: ${a.country||'-'} · Threat: ${a.threatLevel||'-'} · Active: ${a.active?'Yes':'No'}</div>
      `;
      grid.appendChild(card);
    });
    count.textContent = list.length;
  }
  [q,country,threat,status].forEach(el=>el.addEventListener('input',render));
  clear.addEventListener('click',()=>{ q.value=''; country.value=''; threat.value=''; status.value=''; render(); });
  render();
});
