# APT Encyclopedia (Cyllex replica)

Single-page static replica of the Cyllex APT Encyclopedia UI, built from publicly
available data. Not affiliated with Cyllex.

## Sections (all in one page)

- **Overview** — groups tracked, active threats, campaigns, ATT&CK techniques, intel sources
- **Categorized Threats** — filter adversaries by motive, victim industry and location
- **ATT&CK Navigator Heatmap** — generates an ATT&CK Navigator layer from the selected criteria
- **APT Groups** — search + filters (country, threat level, status), click for detail
- **ATT&CK Techniques** — searchable technique catalog (401 techniques, MITRE ATT&CK v14)
- **Threat Model** — Diamond Model of Intrusion Analysis

## ATT&CK Navigator heatmap

Scores are computed client-side from the 117 adversary TTP dumps: the **score of a
technique is the number of adversaries in scope that use it**. The layer is rendered in
an embedded MITRE ATT&CK Navigator iframe and can also be copied, downloaded as JSON, or
opened in the full Navigator.

213 categories are derived from the adversary data (4 motives, 42 industries, 17
adversary bases, 150 victim locations). Multiple selected criteria can be combined as a
**union** (default) or an **intersection**.

This scoring model was validated against the original Control Validation Compass
heatmaps — the generated layers for `Financial Crime` (203 techniques, max score 12) and
for APT1/APT28/APT29/APT41/FIN7/Turla are identical to the author's published files.

## Run

```bash
python3 -m http.server 8080
```

Open http://localhost:8080

Data lives in `data/` (`actors.json`, `techniques.json`, `cvc.json`).
Heatmap logic lives in `heatmap.js`.
## Adversary profile

Clicking **TTPs** on any adversary opens a three-tab modal:

- **ATT&CK Heatmap** — the adversary's Navigator layer plus the full technique list
- **Adversary Profile** — the ETDA threat description, ATT&CK and ETDA profile links,
  and a fact table (aliases, adversary base, motives, victim industries and countries,
  first seen, ATT&CK last modified)
- **Diamond Model** — the modified Diamond Model of Intrusion Analysis diagram

The 117 Diamond Model diagrams are the SVG files published with the Control Validation
Compass data, used here under the same terms as the rest of that dataset.
