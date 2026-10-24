# Public implementation progress

This tracks the public Phase 6 continuation; private historical records are not
copied into this repository. Branch: `phase-6`; PR base: `main`.

## 2026-10-24 — context finalized and drift verified

- PR #3: https://github.com/SSC-SDE/CodeShouldBehave/pull/3 — merged
  `14eb601f117de04f7719ffc81143dec343e5c217`.
- PR #4: https://github.com/SSC-SDE/CodeShouldBehave/pull/4 — merged
  `c9a6f78dce6df5bb681a41eced9833df69710a2a`, provider verified.
- Owner accepted eight unsupported paths and unknown hosting; integrations deferred.
- Native context drift against that exact main: unchanged, reuse allowed. Evidence:
  `.codeshouldbehave/setup-proposal/context-drift.json`.
- Fixed exact manifest-file root recognition during drift; regression verifies
  existing manifest acceptance and missing manifest rejection. Three drift tests
  and Rust 1.87 strict all-target/all-feature Clippy passed.
- Next: merge correction, fresh budget observation, Linux release refresh and
  signature/native startup verification. Current engine pins remain unchanged.
- Activation OFF: export permission, review defaults, publication consent and
  analysis/publication/check operations remain false; consumer workflows staged only.

## 2026-10-24 — refreshed Linux release

- PR #5 merged: `39b89ac088beb8823da738e9587c6ab07c315676`.
- Current GitHub Free / USD 0 Actions and Packages hard stops verified by UI;
  fresh twelve-hour observation passed the hosted guard on build attempt 2.
- Release build and hosted attestation passed: run `40087980741`, attempt 2.
- Package hashes and exact-source hosted signatures verified. Canary tag:
  `canary-39b89ac088be`. Engine pins updated on `phase-6`, not main.
- Published bootstrap passed. Native sandbox startup passed in run `40088281103`
  on exact pin commit `e90ef4b6317451a4f6a0bd55155dc561109d6bcc`.
- Next checkpoint: review/merge the pin PR, then prepare the installation and
  consent diff for explicit owner approval. Do not activate on merge.
- Activation remains OFF; publication consent, export permission, defaults and
  runtime operations unchanged. No consumer workflows installed.

## 2026-10-24 — installation/consent review prepared

- PR #6 provider-confirmed merge: `bd5c06f6566c9523e48dddcefc10f85caf4c6236`.
- Prepared unapplied six-file installation patch, byte manifest and separate
  consent preview under `.codeshouldbehave/setup-proposal/installation-review/`.
- Pages read-only check: workflow source, expected project URL, status null.
- Export context regeneration, reviewed public budget proof, final hashes and
  complete activation diff remain pending explicit owner consent.
- Activation remains OFF. No installer execution or runtime workflow placement.

## 2026-10-25 — final activation prepared

PR #7 merge verified: `0e5403557bf36bb01aede19eb0d28062dbf93716`. Owner
requested activation. Fresh native export context retains the approved boundary,
gaps and deferred integrations. Verified-runtime installer prepared seven runtime
files including the public budget observation, policy and context. 82 public
tests passed, four skipped; config/hashes/budget and main-only Pages access pass.
See docs/ACTIVATION_STATUS.md. Pending final activation PR merge and actual live
PR-to-dashboard verification; no live completion claim.

## 2026-10-25 — live canary blocked, no success claim

PR #8 merged at `ad25c3feff864efb14c3187a08891e72bd588292`. Automatic
nudge and controller delivery verified with review-only PR #9. Budget evidence
was still fresh; no refresh was fabricated. Empty-queue run 40127428437 passed.
Canary run 40127500835 attempts 1 and 2 failed before producing a public report.

Read-only Linux probe 40127927031 identified tree_inventory/lstat racing native
temporary-file replacement. Active sampling now tolerates vanished entries only;
final inventories remain strict and links remain refused. Public tests: 83 passed,
four native-dependent tests skipped (Unix-socket suite requires local permissions).

Probe 40128351722 classified a second failure as exporter/limit. Local exact
comparison succeeded with 22 flow edits; local public export reproduced
Public projection file/byte limit, including with max_details=8. No budget was
raised, no report was published, and no HLD/LLD check link has passed acceptance.
PR #9 remains DO NOT MERGE: it includes synthetic unlinked code and diagnostic
workflow changes. A bounded public projection fix and fresh verified release are
required before the live journey can pass. Raw native stderr was not published;
diagnostics emitted only fixed categories and code locations.
