# APT Encyclopedia (Cyllex replica)

Single-page static replica of the Cyllex APT Encyclopedia UI, built from publicly
available data. Not affiliated with Cyllex.

## Sections (all in one page)

- **Overview** — groups tracked, active threats, campaigns, ATT&CK techniques, intel sources, mapped defensive resources
- **Categorized Threats** — filter adversaries by motive, victim industry, base and victim location; tick individual adversaries to narrow further, with a live **Selection Review** panel
- **ATT&CK Navigator Heatmap** — generates an ATT&CK Navigator layer from the selected criteria
- **Recent Intelligence** — 11 pre-computed adversary report layers
- **TTP Research Knowledge Center** — all 578 ATT&CK techniques with their mapped policy/process controls, detection rules and offensive tests (D3FEND, CAR, Sigma, Splunk, Elastic, Microsoft Sentinel, Atomic Red Team, Stratus Red Team)
- **Lookup by Controls** — toggle the 27 control/detection/testing providers you run and align every technique against what your stack actually covers, with sorting and tactic/level filters
- **Threat Alignment Risk Workflow** — lines the threat model up against the control stack to surface technique-level detection gaps; includes the Trickbot worked example shipped with the Compass
- **APT Groups** — search + filters (country, threat level, status), click for detail
- **ATT&CK Techniques** — searchable technique catalog (401 techniques, MITRE ATT&CK v14)
- **Knowledge Center** — the upstream projects and reference material
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

Data lives in `data/`:

- `actors.json`, `techniques.json`, `cvc.json` — encyclopedia data
- `intel/` — pre-computed report layers, including the Trickbot example
- `controls.json` — 578 × 27 technique/provider coverage matrix
- `technique_index.json` — light index (578 techniques, ~300 KB) loaded on boot
- `technique_pages.json` — full per-technique detail (~2.7 MB), fetched on first open

Heatmap logic lives in `heatmap.js`; the purple-team sections live in `knowledge.js`.
## Adversary profile

Clicking **TTPs** on any adversary opens a three-tab modal:

- **ATT&CK Heatmap** — the adversary's Navigator layer plus the full technique list
- **Adversary Profile** — the ETDA threat description, ATT&CK and ETDA profile links,
  and a fact table (aliases, adversary base, motives, victim industries and countries,
  first seen, ATT&CK last modified)
- **Diamond Model** — the modified Diamond Model of Intrusion Analysis diagram

The 117 Diamond Model diagrams are the SVG files published with the Control Validation
Compass data, used here under the same terms as the rest of that dataset.

## Recent Intelligence

The 11 named threat-intelligence reports published by the Control Validation Compass
authors are available as pre-built Navigator layers, searchable by name, with copy,
open-in-Navigator and a JSON view.

## Attribution

- Group and campaign data extracted from the public Cyllex APT Encyclopedia.
- Adversary categories, Diamond Model diagrams and intelligence layers from the
  [Control Validation Compass](https://github.com/ControlCompass/ControlCompass.github.io)
  project by tropChaud, via
  [Categorized-Adversary-TTPs](https://github.com/tropChaud/Categorized-Adversary-TTPs) and
  [Cyber-Adversary-Heatmaps](https://github.com/tropChaud/Cyber-Adversary-Heatmaps).
- Technique names, tactics, descriptions and platforms from
  [MITRE ATT&CK v14](https://github.com/mitre-attack/attack-stix-data).
