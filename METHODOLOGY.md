# Methodology

## Pipeline
raw event (email, sign-in, MFA push, mailbox rule, telemetry row) → **feature extraction** → **weighted rules** → **sequence matching** → explained verdict.

Features are derived from the raw fields, not hand-labeled: IP and device are compared with a configured baseline; email text is scanned for urgency and credential-lure language; sender and link domains go through a lookalike check (brand token, edit distance of 1-2 to a trusted domain, TLD swap); forwarding destinations are checked against organization domains.

## Model choice
Inputs are structured tabular features, which is the ANN case. With only a handful of events, a trained network would overfit, so the shipped model is a transparent weighted rule set shaped like ANN input features; weights can be replaced by learned ones when labeled data exists. A CNN would only apply to the phishing screenshot (local visual patterns) and would be one signal beside domain checks, never a verdict. Ordered event logic (RNN/Transformer territory in Round 2) is approximated here by sequence rules.

## Rules
| ID | Category | Weight | Signal |
|----|----------|--------|--------|
| R1 | phishing | 30 | Urgent credential-lure email from an external sender |
| R2 | phishing | 15 | Sender or link domain imitates a trusted or brand domain |
| R3 | access | 25 | Unfamiliar device on a new network or location |
| R4 | mfa | 40 | MFA approved but user denies initiating |
| R5 | persistence | 50 | Mailbox rule forwarding outside the organization |
| R6 | mfa | 15 | MFA failed from an unfamiliar device |
| R7 | recovery | 15 | Recovery page opened from an unfamiliar device |
| R8 | recovery | 40 | Recovery email change requested from an unfamiliar device |
| R9 | recovery | 60 | Recovery email change completed from an unfamiliar device |
| R10 | mfa | 15 | MFA passed within 10 min of a failure, same unfamiliar context |
| R11 | context | 5 | Failed sign-in from the usual network (ambiguous) |

Event score = sum of matched weights (max 100). Low < 25, Medium 25-49, High 50+. Case score = strongest event + 10 per extra independent category + 15 if a known sequence matches.

## Validation
`npm test` runs 16 checks: expected levels per event, a negative control (travelling employee, internal forwarding), ablations (removing events must lower the score and break chains), lookalike-domain cases, determinism, parser, and a check that generated text never claims attribution or data theft.

## Output rule
Facts, hypotheses and missing evidence are generated per case from the rules that fired, and kept separate. No output claims attacker identity or data theft.
