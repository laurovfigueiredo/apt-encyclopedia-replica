# APT Encyclopedia (Cyllex replica)

Static replica of the Cyllex APT Encyclopedia UI, built from publicly
available data. Not affiliated with Cyllex.

Each theme lives on its **own page** (URL per theme); `index.html` is the
Overview hub with cards linking to the rest. The threat-model scope and the
control-stack selection persist across pages via `localStorage`
(`encyc.scope.v1`).

## Pages

| Page | File | What it does |
|---|---|---|
| Overview | `index.html` | Group/adversary/technique stats + hub cards |
| Categorized Threats | `categorized.html` | Filter 117 adversaries by motive, victim industry, base and victim location; tick individual adversaries; live **Selection Review** panel |
| ATT&CK Heatmap | `heatmap.html` | ATT&CK Navigator layer from the selected scope (reads the scope built on Categorized Threats) |
| Recent Intelligence | `intel.html` | 11 pre-computed adversary report layers |
| TTP Research & Search | `research.html` | 578 ATT&CK techniques with mapped policy/process controls, detection rules and offensive tests (D3FEND, CAR, Sigma, Splunk, Elastic, Microsoft Sentinel, Atomic Red Team, Stratus Red Team) |
| Lookup by Controls | `controls.html` | Toggle the 27 control/detection/testing providers; aligns every technique against the stack (saved for Threat Alignment) |
| Threat Alignment | `alignment.html` | Threat model vs control stack → technique-level gaps; Trickbot worked example; bring-your-own layer via file upload or URL |
| Knowledge Center | `resources.html` | Upstream guide (tutorials, general knowledge, FAQ, provider groups) + the dataset updater |
| APT Groups | `groups.html` | Search + filters (country, threat level, status), click for detail |
| ATT&CK | `techniques.html` | Searchable technique catalog (MITRE ATT&CK, refreshed via `tools/update_mitre.py`) |
| Threat Model | `model.html` | Diamond Model of Intrusion Analysis + intelligence sources |

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

Open http://localhost:8080 — then navigate to any page above
(e.g. http://localhost:8080/categorized.html).

Data lives in `data/`:

- `actors.json`, `techniques.json`, `cvc.json` — encyclopedia data
- `intel/` — pre-computed report layers, including the Trickbot example
- `controls.json` — 578 × 27 technique/provider coverage matrix
- `technique_index.json` — light index loaded on boot
- `technique_pages.json` — full per-technique detail (~2.7 MB), fetched on first open
- `resources_guide.json` — upstream Knowledge Center guide (parsed from ControlCompass)
- `attack_version.txt` — ATT&CK major version + release tag + refresh timestamp
  (written by `tools/update_mitre.py`)
- `last_update.txt` — last Compass refresh timestamp (written by `tools/exec_update.py`)

Heatmap logic lives in `heatmap.js`; the purple-team sections live in `knowledge.js`;
page boot, filters and cross-page scope persistence live in `spa.js`.

Shared layout (header/nav/footer/modal/scripts) is copied into each page —
there is no build step. The nav marks the current page with
`aria-current="page"`. When editing the header, replicate the change to all
11 pages (or regenerate with `python3 tools/split_pages.py`).

## Updating the datasets

The **Check for dataset updates** button (Knowledge Center page) checks the
live upstream — MITRE
[attack-stix-data](https://github.com/mitre-attack/attack-stix-data/releases)
releases and the latest ControlCompass commit — against the local bundle and
tells you exactly what to run. The browser cannot rewrite `data/` by itself,
so the actual update runs locally:

```bash
python3 tools/update_mitre.py --check-only   # compare versions, change nothing
python3 tools/update_mitre.py                # refresh techniques from MITRE CTI
python3 tools/exec_update.py                 # refresh the Compass layer too
```

`update_mitre.py` (stdlib only, no new dependencies) merges MITRE-owned fields
into `data/techniques.json` and `data/technique_index.json`, preserving local
fields (`usage`, `groups`) and Compass counts, writing `.bak` backups first
and refusing to wipe on an empty bundle. It also bumps `ATTACK_VERSIONS` in
`heatmap.js` and writes `data/attack_version.txt`.

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
  [MITRE ATT&CK](https://github.com/mitre-attack/attack-stix-data)
  (local bundle version stamped in `data/attack_version.txt`).
