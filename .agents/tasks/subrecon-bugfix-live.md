# SubRecon Pro — Live Keyless Verification (A-record cloud verdict gap)

**Job:** `abdb24ff149c4a6c8780a930a8cd9706` — live keyless scan of `example.com`, **no API keys supplied**.
**Unit tests:** 176 passed.
**live_passed:** true

## The bug fixed
A detected cloud resource could end with an **empty** `takeover_verdict`:
- An A-record-PTR CloudFront host (e.g. `bimi.example.com`) was identified as `AWS CloudFront`
  but — depending on the detection path — risk/verdict could be left empty because the
  `verify_takeover` pass only ran for CNAME-detected `VERIFY`/`HIGH` rows.
- More broadly, any **LOW** row produced by cloud-resource detection (non-empty
  `takeover_service`, e.g. the held-LOW A-record S3 PTR path) was never routed through
  `verify_takeover`, so it ended as a dead-end `takeover_verdict=''`.

## The fix (main.py)
- `analyze_subdomain` now runs the active `verify_takeover` pass for flagged rows
  (`VERIFY`/`HIGH`) **and** for any `LOW` row whose `takeover_service` is set
  (`cloud_low`). A row with a detected cloud service always ends with a concrete verdict.
- `verify_takeover` early-return guard updated to the same gate, and its A-record
  fallback generalized: when there is no CNAME target but a cloud service was detected
  from the edge-IP PTR, it recovers the provider from `takeover_service` and probes the
  alias (the subdomain) itself — behind the SSRF guard + shared Semaphore, trailing dot
  stripped. CloudFront keeps its exact verdict logic (healthy 200/3xx -> NOT_VULNERABLE;
  'The request could not be satisfied' -> VULNERABLE; blocked/timeout -> INCONCLUSIVE
  with a manual action).
- No CNAME is fabricated for A-record hosts; `cname` stays null. All security guards and
  the 16-column CSV contract are untouched.

## Live results

### 1. Coverage
```
total: 353  (>= ~300 required)  PASS
```

### 2. ELB fix NOT regressed
```
gitlab.example.com       cname=app-abcdef0123456789.elb.us-east-1.amazonaws.com   risk=VERIFY  service=AWS ELB  verdict=NOT_VULNERABLE
openproject.example.com  cname=demo-common-1234567890.us-east-1.elb.amazonaws.com  risk=VERIFY  service=AWS ELB  verdict=NOT_VULNERABLE
docs.example.com         cname=demo-alb-1234567890.us-east-1.elb.amazonaws.com     risk=VERIFY  service=AWS ELB  verdict=NOT_VULNERABLE
```
PASS — all three NOT_VULNERABLE with full evidence.

### 3. bimi + every cloud-detected row has a NON-EMPTY verdict + action
```
bimi.example.com
  service=AWS CloudFront  risk=VERIFY
  verdict=INCONCLUSIVE
  evidence=AWS CloudFront target could not be probed (probe failed (TimeoutError: ...)) — manually verify the distribution in the AWS CloudFront console (...)
  recommended_action=Inconclusive (AWS CloudFront): manually verify resource ownership in the provider console and remove the record if it is dangling.
```
bimi is detected via the A-record PTR path, routed through `verify_takeover`, and now
carries a concrete verdict + action (the live probe timed out -> INCONCLUSIVE, per spec).

27 rows total have a non-empty `takeover_service` this run:
- 1 x AWS CloudFront (bimi) — VERIFY / INCONCLUSIVE
- 3 x AWS ELB (gitlab, openproject, docs) — VERIFY / NOT_VULNERABLE
- 23 x AWS S3 (A-record held-LOW) — LOW / INCONCLUSIVE, each with a concrete
  recommended_action (previously these were LOW with an empty verdict).

### 4. ZERO cloud-service rows with an empty verdict
```
count of (takeover_service set & takeover_verdict empty): 0   (must be 0)  PASS
cloud rows missing recommended_action: 0                                   PASS
```

### 5. CSV + validation
```
CSV header column count: 16  (ends in recommended_action)  PASS
invalid domain POST  -> 400  PASS
unknown job status   -> 404  PASS
unknown job results  -> 404  PASS
```

## Regression safety
- Plain non-cloud A-record subdomains still get `takeover_verdict=''` (empty is correct
  only when no cloud service is detected) — covered by a unit test.
- All existing ELB NOT_VULNERABLE tests remain green; full suite 176 passed.

Server was started on :8080, exercised with the real scan, then killed and `/health`
confirmed down. Temp files cleaned up.
