# APT Encyclopedia (Cyllex replica)

Single-page static replica of the Cyllex APT Encyclopedia UI, built from publicly
available data. Not affiliated with Cyllex.

## Sections (all in one page)

- **Overview** — groups tracked, active threats, campaigns, ATT&CK techniques, intel sources
- **Categorized Threats** — filter adversaries by motive, victim industry and location
- **APT Groups** — search + filters (country, threat level, status), click for detail
- **ATT&CK Techniques** — searchable technique matrix
- **Threat Model** — Diamond Model of Intrusion Analysis

## Run

```bash
python3 -m http.server 8080
```

Open http://localhost:8080

Data lives in `data/` (`actors.json`, `techniques.json`, `cvc.json`).
