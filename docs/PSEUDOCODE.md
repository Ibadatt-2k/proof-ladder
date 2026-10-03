# Proof Ladder: Pseudocode

Plain-language pseudocode for every part of the project, in the order data flows through it.
File names in brackets point to the real code.

```
BIG PICTURE
  for each incoming alert:
      store alert + its threat-intel facts
      agent investigates it with tools (bounded loop)
      software checks the agent's evidence grades, may override verdict to "needs_human"
      compare AI verdict to the human verdict (shadow mode)
      recompute metrics for that alert type, recommend promotion or auto-demote
  analyst corrections -> memory (reused on similar alerts) + permanent regression tests
  CI runs tests + holdout evaluation, blocks deploy if anything regresses
```

---

## 1. Configuration  [app/config.py]

```
SETTINGS read from environment / .env:
    database_url            default sqlite file, Postgres in production
    llm_provider            "offline" | "anthropic" | "openai"
    llm_model, llm_api_key, llm_base_url
    llm_max_steps = 8       max tool calls per investigation
    llm_max_cost_usd = 0.05 max spend per investigation
    llm_price_in/out_per_mtok   for cost tracking
    memory_backend          "local" | "qdrant"
    memory_match_threshold = 0.92   how similar a past correction must be to count
    readonly, live_replay, live_replay_interval_sec, seed_on_start
```

## 2. Database tables  [app/db.py]

```
Alert          id, external_id, alert_type, payload, human_verdict, scenario, intel_snapshot
Intel          kind (domain | url | ip | user_profile), key, attrs
Investigation  alert_id, provider, proposed_verdict, ai_verdict, summary, findings,
               grading_violations, outcome (agree | disagree | deferred), critical_miss,
               autonomy_at_time, action_status, used_precedent, steps_used, cost, latency, corrected
AuditStep      investigation_id, seq, step_ref ("s1", "s2"...), kind, tool, input, output, ok
Correction     investigation_id, alert_type, signature, corrected_verdict, note
LadderState    alert_type, level, recommendation
LadderEvent    alert_type, event (recommend | promote | demote), from, to, reason, evidence, actor
```

## 3. The verdict contract  [app/schemas.py]

```
Finding:
    claim          one factual statement
    grade          confirmed | inferred | gap
    evidence_refs  list of audit step refs that back the claim
    reasoning      required when grade is inferred
    weight         supports_malicious | supports_benign | neutral

VerdictSubmission:
    verdict        malicious | benign | needs_human
    summary, findings[], recommended_action
```

---

## 4. Synthetic data  [app/data/]

```
FUNCTION generate_phishing(rng, idx):
    scenario = weighted random pick from:
        benign:    internal_notice, vendor_invoice_legit, newsletter,
                   newsletter_young_tracker (TRAP: legit sender, brand-new tracking domain),
                   external_colleague, password_reset_legit
        malicious: credential_harvest_lookalike, bec_reply_to_mismatch, malware_attachment,
                   compromised_vendor (TRAP: real vendor, SPF/DKIM pass, link to new domain),
                   shortened_link_harvest
    build email payload: sender, reply_to, subject, body, urls, attachments, SPF/DKIM/DMARC
    build intel records: domain ages, reputations, URL shortener destinations
    RETURN GeneratedAlert(id, "phishing", payload, human_verdict, scenario, intel)

FUNCTION generate_login(rng, idx):
    scenario = weighted random pick from:
        benign:    normal_login, travel_legit, new_device_legit,
                   corporate_vpn_egress (TRAP: Zscaler egress looks like impossible travel)
        malicious: impossible_travel_attack, password_spray_success,
                   token_replay (TRAP: home city, residential proxy, no MFA prompt)
    profile = stable per-user (home city, 2 known devices)
    build payload: user, ip, geo, device, auth method, MFA result, previous login + minutes ago
    build intel: IP (ASN, network type, reputation, failed logins), user profile
    RETURN GeneratedAlert(...)

FUNCTION alert_stream(n, types, seed):
    rng = Random(seed)
    repeat n times: pick a type, yield generate_<type>(rng, idx)
```

---

## 5. Agent tools  [app/agent/tools.py]

```
CLASS Toolbox(alert_type, payload, intel_lookup, memory_search):

    # phishing tools
    check_email_auth()      -> SPF/DKIM/DMARC, sender domain, reply_to, reply_to_mismatch
    lookup_domain(domain)   -> intel: age_days, reputation, category, age_bucket (new <30, young <365, aged)
    expand_url(url)         -> follow shortener to final URL and domain
    inspect_attachments()   -> each attachment + risky flag (.docm .iso .html .zip ...)
    analyze_language()      -> cue words: urgency, financial, secrecy, credential, exec_impersonation

    # login tools
    get_user_profile()      -> home city, known devices
    geo_velocity()          -> distance_km (haversine), minutes, km/h,
                               impossible_travel = distance > 500 AND speed > 900 km/h
    lookup_ip(ip)           -> ASN name, network type, reputation, failed_logins_24h
    check_device_history()  -> is device in user's known devices
    get_auth_details()      -> auth method, MFA result

    # shared
    search_past_corrections() -> memory_search(alert_type, signature())

    signature():  deterministic feature string used by memory, e.g.
        phishing: "spf:pass dmarc:pass sender_rep:good sender_age:aged url_rep:unknown url_age:new attach:none ..."
        login:    "travel:impossible asn_type:corporate_vpn asn:Zscaler device:known mfa:pass ..."

FUNCTION call_tool(toolbox, name, args):
    IF name not in allowed tools for this alert type: RAISE "outside allowed scope"
    IF any arg is not a safe string (regex): RAISE "invalid argument"
    RETURN toolbox.name(args)
```

## 6. Bounded executor  [app/agent/executor.py]

```
CLASS Executor(toolbox, max_steps, max_cost):
    steps = []        # the single audit trail
    tool_calls = 0, cost = 0

    call(name, args):
        IF tool_calls >= max_steps OR cost > max_cost: RAISE BudgetExceeded
        tool_calls += 1
        TRY   output = call_tool(toolbox, name, args); ok = true
        CATCH output = {error}; ok = false           # errors are recorded, not hidden
        ref = "s" + (len(steps) + 1)
        steps.append({ref, kind: "tool_call", tool: name, input: args, output, ok})
        RETURN ref, output

    note(kind, data):  append a non-tool step (model reasoning text, final verdict)
```

---

## 7. Reasoning providers

### 7a. Offline reasoner (deterministic, no API key)  [app/agent/offline.py]

```
FUNCTION reason_phishing(executor, payload):
    findings = [], mal = 0, ben = 0
    auth = call check_email_auth
        IF DMARC fail or SPF fail/softfail: add CONFIRMED supports_malicious, mal += 1
        ELIF SPF and DMARC pass:            add CONFIRMED supports_benign,  ben += 1
    sender = call lookup_domain(sender_domain)
        IF age < 30 days or reputation malicious: CONFIRMED malicious, mal += 1
        ELIF aged and good:                       CONFIRMED benign,    ben += 1
    FOR each url (max 3):
        final = call expand_url(url); dom = call lookup_domain(final.domain)
        IF dom new or malicious: CONFIRMED malicious (cite both steps), mal += 1
        IF no intel: GAP
    IF urls exist and none bad: INFERRED benign, ben += 1
    IF attachments: call inspect_attachments; risky -> CONFIRMED malicious
    lang = call analyze_language
        IF reply_to mismatch AND (financial or secrecy cue): CONFIRMED malicious
        IF exec title from external sender: INFERRED malicious
        ELIF urgency: INFERRED neutral
    RETURN decide(findings, mal, ben, check_precedent())

FUNCTION reason_login(executor, payload):
    profile = call get_user_profile
    v = call geo_velocity
        IF impossible travel:  CONFIRMED malicious     # known blind spot: VPN egress
        ELIF home city:        CONFIRMED benign
        ELSE                   CONFIRMED neutral (plausible travel)
    ip = call lookup_ip
        bad reputation         -> CONFIRMED malicious
        failed logins > 20     -> CONFIRMED malicious (spray)
        residential/corporate  -> CONFIRMED benign
        other (vpn, proxy)     -> CONFIRMED neutral    # does not know what corporate_vpn means
    dev = call check_device_history; auth = call get_auth_details
        known device           -> CONFIRMED benign
        new device + hosting   -> CONFIRMED malicious
        MFA push fatigue/retry -> CONFIRMED malicious
        MFA pass               -> CONFIRMED benign
        legacy basic auth      -> CONFIRMED malicious
        MFA not required       -> GAP "could not confirm who presented it"
    RETURN decide(findings, mal, ben, check_precedent())

FUNCTION check_precedent():
    matches = call search_past_corrections
    best = highest score match
    RETURN best IF best.score >= 0.92 ELSE none

FUNCTION decide(findings, mal, ben, precedent):
    IF precedent:
        add INFERRED finding "Analyst precedent #id: corrected to X", cite memory step
        verdict = precedent.verdict
    ELSE:
        add GAP "No prior analyst correction matches"
        IF mal > 0:      verdict = malicious
        ELIF ben >= 2:   verdict = benign
        ELSE:            verdict = needs_human
    RETURN VerdictSubmission(verdict, summary, findings, action)
```

### 7b. LLM providers  [app/agent/llm.py]

```
SYSTEM_PROMPT: "You are a tier-2 SOC analyst... every tool result has a step_ref...
                confirmed must cite refs, inferred must explain, gap if nothing found,
                verdict needs confirmed support or it becomes needs_human,
                weigh analyst precedent, budget = N tool calls"

FUNCTION run_llm(alert_type, payload, executor, settings):      # Anthropic and OpenAI-compatible
    tools = alert-type tool schemas + submit_verdict(VERDICT_SCHEMA)
    messages = [alert payload as JSON]
    LOOP up to max_steps + 2 times:
        response = POST to provider API (model, system prompt, tools, messages)
        executor.add_cost(tokens_in * price_in + tokens_out * price_out)
        IF response has text: executor.note("reasoning", text)
        FOR each tool call in response:
            IF name == submit_verdict: RETURN VerdictSubmission(parsed args)
            ref, output = executor.call(name, args)
            append tool result {step_ref: ref, output} to messages
        IF no tool calls: append "Call submit_verdict now."
    RAISE BudgetExceeded
```

---

## 8. Triage + grading enforcement  [app/agent/triage.py]

```
FUNCTION triage(alert_type, payload, intel_lookup, memory_search, settings):
    executor = Executor(Toolbox(...), max_steps, max_cost)
    start timer
    TRY
        submission = run offline OR anthropic OR openai provider
    CATCH BudgetExceeded:   submission = needs_human, record violation
    CATCH any error:        submission = needs_human, record "Provider error"   # fail safe, never open
    verdict, findings, violations, used_precedent = enforce_grading(submission, executor)
    executor.note("verdict", proposed vs final, violations)
    RETURN TriageResult(provider, proposed, final verdict, findings, violations, steps,
                        used_precedent, tool_calls, cost, latency, signature)

FUNCTION enforce_grading(submission, executor):
    FOR each finding:
        IF grade == confirmed:
            valid_refs = refs pointing to steps that are successful tool calls
            IF none valid: downgrade to INFERRED, record violation
        IF grade == inferred AND no reasoning: record violation
        IF finding cites a search_past_corrections step that had matches: used_precedent = true

    verdict = submission.verdict
    IF verdict is malicious or benign:
        IF no CONFIRMED finding supports it AND not used_precedent:
            verdict = needs_human, record violation          # "fails to the human"
        ELIF verdict benign AND a CONFIRMED finding supports malicious AND not used_precedent:
            verdict = needs_human, record violation
    RETURN verdict, findings, violations, used_precedent
```

---

## 9. Corrections memory  [app/memory/store.py]

```
FUNCTION embed(signature):
    vector = zeros(512)
    FOR each token in signature:
        h = md5(token); vector[h mod 512] += (+1 or -1 from a hash bit)
    RETURN normalized vector          # same pattern always gives the same vector

CLASS LocalStore / QdrantStore:
    add(correction_id, alert_type, signature, verdict, note):   store embed(signature) + payload
    search(alert_type, signature, k=3):
        score = cosine(embed(signature), stored vectors) filtered by alert_type
        RETURN top k with score > 0.5      # agent only USES matches >= 0.92

get_store(): LocalStore by default, QdrantStore if MEMORY_BACKEND=qdrant
```

---

## 10. Trust ladder  [app/ladder/]

```
FUNCTION wilson_lower_bound(agree, decided, z = 1.96):
    IF decided == 0: RETURN 0
    p = agree / decided
    RETURN (p + z²/2n - z * sqrt(p(1-p)/n + z²/4n²)) / (1 + z²/n)
    # 98% on 50 alerts -> about 0.89; 98% on 2,000 -> about 0.97

LEVELS = [assisted, ai_led, autonomous]
CRITERIA:
    ai_led:     decided >= 200, lower bound >= 0.95, critical misses = 0, deferral <= 20%
    autonomous: decided >= 500, lower bound >= 0.98, critical misses = 0, deferral <= 10%
HYSTERESIS = 0.02

FUNCTION compute_metrics(alert_type):
    rows = last 1000 investigations of this type
    count agree, disagree, deferred, critical misses, false alarms
    RETURN agreement rate, wilson lower bound, deferral rate, violation rate,
           precedent rate, avg cost, median latency

FUNCTION meets(metrics, level, margin = 0):
    RETURN (all criteria for level pass, list of blocking reasons)

FUNCTION evaluate(alert_type, critical_miss_now):
    state = current level, m = compute_metrics
    IF level above assisted:
        IF critical_miss_now OR NOT meets(m, level, margin = HYSTERESIS):
            drop one level immediately, log DEMOTE with evidence snapshot
            RETURN
    IF not at top:
        next = level + 1
        IF meets(m, next) AND not already recommended:
            set recommendation = next, log RECOMMEND with evidence snapshot
        ELIF criteria no longer met: clear recommendation

FUNCTION approve(alert_type, actor):
    IF no recommendation: ERROR
    re-check meets(current metrics, recommendation); IF fails: clear it, ERROR
    level = recommendation, log PROMOTE by actor with evidence snapshot
```

---

## 11. Pipeline  [app/pipeline.py]

```
ACTION_BY_LEVEL = {assisted: "shadow", ai_led: "drafted", autonomous: "executed"}

FUNCTION process_alert(generated):
    reject duplicates by external_id
    upsert generated.intel into Intel table
    save Alert (with intel snapshot)
    result = triage(alert, intel lookup from DB, memory.search)
    outcome = deferred IF result.verdict == needs_human
              agree    IF result.verdict == human_verdict
              disagree OTHERWISE
    critical_miss = human said malicious AND AI said benign
    level = ladder state for this type
    save Investigation + all AuditSteps,
         action_status = "none" if deferred else ACTION_BY_LEVEL[level]
    ladder.evaluate(alert_type, critical_miss)

FUNCTION correct(investigation_id, verdict, note):
    require verdict in {malicious, benign}
    signature = Toolbox(alert payload, alert's intel snapshot).signature()
    save Correction; mark investigation corrected
    memory.add(correction id, type, signature, verdict, note)

FUNCTION rebuild_memory():          # on startup, for the local store
    load every Correction from DB into memory

FUNCTION export_regressions(path):
    merge existing cases file with one case per Correction:
        {case_id, alert_type, payload, intel, expected = corrected verdict, note, signature}
    write as JSON lines
```

---

## 12. API + dashboard  [app/main.py, app/static/index.html]

```
ON STARTUP:
    create tables, rebuild memory
    IF database empty: replay seed_on_start alerts
    IF live_replay: background thread processes 1 alert every N seconds

GET  /                               dashboard page
GET  /api/health                     provider, memory backend, readonly
GET  /api/summary                    per type: level, recommendation, metrics, next-level blockers
GET  /api/timeline?alert_type        rolling lower bound every 25 investigations (chart)
GET  /api/investigations?type&outcome  list for the table
GET  /api/investigations/{id}        full detail: payload, findings, violations, audit steps
POST /api/investigations/{id}/correct  {verdict, note}  -> pipeline.correct     (blocked if readonly)
GET  /api/ladder/{type}/events       recommend / promote / demote history
POST /api/ladder/{type}/approve      -> ladder.approve                           (blocked if readonly)
GET  /api/ladder/{type}/report       markdown evidence report: measures vs requirements, blockers
POST /api/replay {n <= 500}          process n more alerts                       (blocked if readonly)
All writes go through one lock (safe for SQLite).

DASHBOARD (Vue, no build step):
    header: provider, alert count, correction count, "Replay 100 alerts"
    per alert type card: 3-rung ladder, metric tiles, lower-bound chart vs threshold,
        "Approve promotion" + "Evidence report" when recommended, else blocking reasons
    investigations table with type/outcome filters
    click row -> drawer: verdicts, grading violations, graded findings with refs,
        expandable audit trail, raw payload, correction form
    ladder history per type
    auto-refresh every 15 s
```

---

## 13. Scripts  [scripts/]

```
replay.py --n N [--reset]:   init DB, rebuild memory, process N alerts, print per-scenario table
seed_corrections.py:         play the analyst: correct the first wrong VPN-egress login and
                             the first wrong young-tracker newsletter
export_regressions.py:       write all corrections to tests/regression/cases.jsonl
```

## 14. Evaluation gate  [eval/run_eval.py, eval/thresholds.json]

```
FUNCTION run_eval(n = 600, seed = fixed, use_memory = true):
    memory = LocalStore loaded from regression cases (unless --no-memory)
    FOR each alert in alert_stream(n, seed):          # fresh holdout, no database
        result = triage(alert, intel from alert's own records, memory)
        tally agree / disagree / deferred / critical misses / violations / misses by scenario
    FOR each type: compare to thresholds
        critical misses <= 0, agreement >= 0.95, deferral <= limit, violation rate <= 0.05
    write eval/report.json
    EXIT 1 if any check fails (CI blocks the merge / deploy)
```

## 15. Tests  [tests/]

```
test_stats:          Wilson bound edge cases and known values
test_tools:          haversine, impossible travel, tool scope blocked, unsafe args blocked
test_grading:        fake "confirmed" is downgraded + deferred; real evidence stands;
                     benign against confirmed malicious defers
test_ladder:         150 agrees -> no rec; 300 -> recommend; approve -> ai_led;
                     critical miss -> demote; event log = recommend, promote, demote
test_regressions:    every analyst correction still produces the corrected verdict;
                     VPN precedent does NOT apply to a new device + MFA push fatigue
test_llm_providers:  mocked OpenAI-style and Anthropic-style loops, cost math,
                     provider 500 fails safe, out-of-scope tool refused
test_api:            seed, list, detail, correct, evidence report
```

## 16. CI/CD and deploy  [.github/workflows/eval-gate.yml, deploy/cloudrun.sh, Dockerfile]

```
ON every push / PR:
    install deps
    pytest                       # unit + regression suite
    run_eval --n 600             # offline holdout gate
    IF LLM_API_KEY secret set: run_eval --n 120 with the real model
    upload eval/report.json
ON push to main AND GCP variables set:
    authenticate with workload identity, run deploy/cloudrun.sh

deploy/cloudrun.sh:
    gcloud run deploy from source (Dockerfile), 1 instance, public URL
    env: seed 600 alerts, live replay on, provider, optional Postgres + Qdrant URLs
    secrets via Secret Manager

Dockerfile: python 3.12 slim, install deps, copy app, non-root user, uvicorn on $PORT
docker-compose: api + postgres + qdrant for a full local stack
```
