// Encyclopedia.tsx — copiar para soc-os-v2/frontend/src/pages/Encyclopedia.tsx
// e registrar rota + item de menu em App.tsx (ver integration/README.md).
// Iframe same-origin (/encyclopedia/) => buscas, filtros, Threat Model,
// heatmaps, actor.html e localStorage funcionam sem alteração.
export default function Encyclopedia() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 'calc(100vh - 48px)' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 20px', borderBottom: '1px solid var(--border)' }}>
        <div style={{ fontSize: 15, fontWeight: 800 }}>
          Threat <span style={{ color: 'var(--accent)' }}>Encyclopedia</span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 400, marginLeft: 8 }}>
            58 grupos · TTPs · ATT&amp;CK · Threat Model
          </span>
        </div>
        <a href="/encyclopedia/index.html" target="_blank" rel="noopener"
          style={{ fontSize: 12, color: 'var(--accent)', textDecoration: 'none' }}>
          Abrir em nova aba ↗
        </a>
      </div>
      <iframe
        title="Threat Encyclopedia"
        src="/encyclopedia/index.html"
        style={{ flex: 1, border: 0, minHeight: '70vh', background: '#fff' }}
      />
    </div>
  )
}
