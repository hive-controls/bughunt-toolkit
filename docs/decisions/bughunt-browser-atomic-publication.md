---
name: bughunt-browser-atomic-publication
title: "Scan browser publications with one metadata snapshot and observe native stat seams"
purpose: "Preserve the verified atomic-publication race and Windows test-observer distinction when maintaining owned browser output bounds."
subtype: lesson
metadata:
  type: project
files:
  - bughunt/integrations/browser_runtime.py
  - tests/test_browser_runtime.py
session: "2026-10-15"
---

VERIFIED on Windows Python 3.14.3, 2026-10-15: the pinned browser consumer
publishes READY, numbered requests and its result by renaming a temporary file.
The original host scan called is_file followed by repeated stat calls. A
deterministic owned-file control renamed READY.tmp after the first check and
reproduced FileNotFoundError. That valid transition could stop a job before
readiness/mediation. The exact exception in the earlier v5 consumer failure was
discarded, so attributing that particular failure to this race is UNVERIFIED.

The corrected scan uses one lstat snapshot. If one exact known producer-temp
name disappears, it requires the published destination to exist as a regular
file and still accounts for that snapshot's size. Only READY.tmp,
000001-000128.req.tmp and browser-result.json.tmp at their fixed locations
qualify. Committed/unknown/missing destinations, redirects and cap violations
do not become benign. Rescan outputs after consumer cleanup before accepting a
final observation; an oversized result must not bypass monitoring by racing
the last iteration. Three publication controls and an oversized-final control
failed before correction. The corrected focused suite passed 100 controls.

VERIFIED observer lesson: this runtime's Path.lstat calls os.lstat directly,
not Path.stat. Windows is_file/is_symlink also use native fast paths. The first
observer stopped firing after the source moved to lstat; its explicit scheduling
assertion caught that gap rather than creating a false green. Observe both
os.stat and os.lstat when exercising both old and new implementations, preserving
the scheduling and rejection assertions. A read-only diagnostic confirmed the
runtime call paths before the test observer was corrected.

Keep separate: a later actual run encountered prelaunch WinError5 replacing a
ledger manifest in a repository proof directory. Its cause is UNVERIFIED; no
shared storage retry or safety override was added. Fresh Temp acceptance is an
alternative fixture location, not a diagnosis or claimed fix.

Related: [browser sandbox requirements](bughunt-browser-sandbox-capdrop.md). None of these controls establishes
production HTTPS browsing, automatic login/crawling, or strict final-wire spacing.
