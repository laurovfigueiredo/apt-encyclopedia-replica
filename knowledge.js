async function updateAttackDatasets() {
  const btn = $('#update-btn');
  const logEl = $('#update-log');
  const lastEl = $('#last-updated');
  if (!btn) return;
  btn.disabled = true;
  if (logEl) {
    logEl.style.display = 'block';
    logEl.textContent = 'Updating MITRE ATT&CK datasets...\n\n';
  }
  try {
    const res = await fetch('tools/exec_update.py');
    const script = await res.text();
    const blob = new Blob([script], { type: 'text/python' });
    // We cannot execute server-side from static Pages; show execution log from local run instructions
    if (logEl) {
      logEl.textContent += 'The updater script is ready. Run locally to apply updates:\n\n  python3 tools/exec_update.py\n\n';
    }
  } catch (e) {
    if (logEl) logEl.textContent += 'Error: ' + e.message + '\n';
  }
  try {
    const r = await fetch('data/last_update.txt');
    if (r.ok && lastEl) lastEl.textContent = (await r.text()).trim();
  } catch (e) {}
  btn.disabled = false;
}
