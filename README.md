# Shadow Triage

Explainable sign-in and phishing triage built for **Operation Shadow, Round 1: Detect the Breach**.
It never returns a bare "safe" or "hacked". Every verdict is a risk level with reasons, false-positive explanations, missing evidence, limitations and safe containment steps.

**Live demo:** `https://<your-username>.github.io/shadow-triage/` (see Deploy below)

## Evidence ladder
1. **Observation**: raw fact from the log or case file
2. **Anomaly**: deviation from baseline (new device, failed MFA, external forwarding)
3. **Correlation**: anomalies across independent categories and known attack sequences
4. **Hypothesis**: always labeled unproven
5. **Confirmation needed**: the missing evidence that would confirm or kill it

## How detection works
- Raw events (email, sign-in, MFA push, mailbox rule, telemetry) go through **feature extraction** against a configured baseline, including a lookalike-domain check.
- `src/detector.js` applies 11 weighted rules and 2 sequence patterns. Every rule carries its own false-positive explanation, hypothesis, missing-evidence note and containment action, so the report is generated from what actually fired.
- Event score = sum of matched weights (Low < 25, Medium 25-49, High 50+). Case score adds 10 per extra independent category and 15 for a matched attack sequence.
- Confidence is about the account being targeted or compromised, **not** data theft or attacker identity.
- Untick events in the UI to see the verdict respond; `npm test` includes ablation tests that prove it.

## Scenarios included
- **Northstar Labs (Mira):** lookalike payroll lure, unfamiliar sign-in, unrequested MFA approval, external forwarding rule.
- **Variant B (account recovery):** MFA fail, then pass, then recovery email change request. Sample data in `data/variant_b_sample.csv`.
- **Negative control:** a travelling employee with a known laptop and an internal forwarding rule, which must stay Low.
- **Your own input:** paste JSON events or Variant B style CSV.
- **Domain checker:** type a domain from a screenshot clue to test it for lookalike patterns (text only, nothing is opened).

## Run
Open `index.html` in a browser, or serve the folder. Tests:
```
npm test
```
(Node 14+, no dependencies; 16 tests)

## Deploy to GitHub Pages
1. Create a public repo named `shadow-triage` and push these files to `main`.
2. Settings, Pages, Source: *Deploy from a branch*, branch `main`, folder `/ (root)`.
3. The site appears at `https://<your-username>.github.io/shadow-triage/` within a minute or two.

## Limitations
Hand-set heuristic weights (not trained), small sample, no per-user baseline. No attribution or data-theft claims. See `docs/METHODOLOGY.md`.

## Safety
Synthetic data only. The tool never opens links, contacts accounts, sends messages or scans systems.
