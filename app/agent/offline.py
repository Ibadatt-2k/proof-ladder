"""Deterministic built-in reasoner.

It plans tool calls, reads their outputs and writes graded findings, exactly like
an LLM provider must. It is intentionally imperfect in realistic ways (it does not
know that corporate VPN egress causes impossible travel, or that residential
proxies plus token reuse is suspicious) so the trust ladder and the corrections
loop have something real to measure and fix. It also lets CI run with no API key.
"""
from app.agent.executor import Executor
from app.schemas import Finding, VerdictSubmission


def _f(claim, grade, refs=(), weight="neutral", reasoning=""):
    return Finding(claim=claim, grade=grade, evidence_refs=list(refs), weight=weight, reasoning=reasoning)


def _precedent(ex: Executor, threshold: float):
    ref, out = ex.call("search_past_corrections")
    best = max(out.get("matches", []), key=lambda m: m["score"], default=None)
    if best and best["score"] >= threshold:
        return ref, best
    return ref, None


def reason_phishing(ex: Executor, p: dict, threshold: float) -> VerdictSubmission:
    findings: list[Finding] = []
    mal = ben = 0
    r_auth, auth = ex.call("check_email_auth")
    if auth["dmarc"] == "fail" or auth["spf"] in ("fail", "softfail"):
        findings.append(_f(f"Sender authentication failed (SPF {auth['spf']}, DMARC {auth['dmarc']}).", "confirmed", [r_auth], "supports_malicious")); mal += 1
    elif auth["spf"] == "pass" and auth["dmarc"] == "pass":
        findings.append(_f("SPF and DMARC pass for the sender domain.", "confirmed", [r_auth], "supports_benign")); ben += 1

    r_sd, sd = ex.call("lookup_domain", {"domain": auth["sender_domain"]})
    if sd.get("found") and (sd["age_days"] < 30 or sd["reputation"] == "malicious"):
        findings.append(_f(f"Sender domain {sd['domain']} is {sd['age_days']} days old with {sd['reputation']} reputation.", "confirmed", [r_sd], "supports_malicious")); mal += 1
    elif sd.get("found") and sd["age_bucket"] == "aged" and sd["reputation"] == "good":
        findings.append(_f(f"Sender domain {sd['domain']} is established ({sd['age_days']} days, good reputation).", "confirmed", [r_sd], "supports_benign")); ben += 1

    url_bad = False
    for u in p.get("urls", [])[:3]:
        r_x, x = ex.call("expand_url", {"url": u})
        refs = [r_x] if x["redirected"] else []
        r_d, d = ex.call("lookup_domain", {"domain": x["final_domain"]})
        refs.append(r_d)
        if d.get("found") and (d["age_days"] < 30 or d["reputation"] == "malicious"):
            via = f" (reached via redirect from {u})" if x["redirected"] else ""
            findings.append(_f(f"Link destination {d['domain']} is {d['age_days']} days old, reputation {d['reputation']}{via}.", "confirmed", refs, "supports_malicious")); mal += 1; url_bad = True
        elif not d.get("found"):
            findings.append(_f(f"No intel on link domain {x['final_domain']}.", "gap", refs))
    if p.get("urls") and not url_bad:
        findings.append(_f("All link destinations are established domains.", "inferred", [], "supports_benign", "Every looked-up link domain was aged with good reputation.")); ben += 1

    if p.get("attachments"):
        r_a, a = ex.call("inspect_attachments")
        if a["any_risky"]:
            names = ", ".join(i["name"] for i in a["attachments"] if i["risky"])
            findings.append(_f(f"Risky attachment type: {names}.", "confirmed", [r_a], "supports_malicious")); mal += 1

    r_l, lang = ex.call("analyze_language")
    cues = lang["cues"]
    external = not auth["sender_domain"].endswith("acme-corp.com")
    if auth["reply_to_mismatch"] and ({"financial", "secrecy"} & set(cues)):
        findings.append(_f(f"Reply-To ({auth['reply_to']}) differs from sender and the message asks for money or secrecy.", "confirmed", [r_auth, r_l], "supports_malicious")); mal += 1
    if "exec_impersonation" in cues and external:
        findings.append(_f("Message invokes an executive title from an external sender.", "inferred", [r_l], "supports_malicious", "Executive impersonation is a common BEC pattern.")); mal += 1
    elif "urgency" in cues:
        findings.append(_f("Urgent language present.", "inferred", [r_l], "neutral", "Urgency alone is weak; legitimate notices use it too."))

    r_m, prec = _precedent(ex, threshold)
    return _decide(findings, mal, ben, r_m, prec, "Email")


def reason_login(ex: Executor, p: dict, threshold: float) -> VerdictSubmission:
    findings: list[Finding] = []
    mal = ben = 0
    r_p, prof = ex.call("get_user_profile")
    r_v, v = ex.call("geo_velocity")
    if v["impossible_travel"]:
        findings.append(_f(f"Impossible travel: {v['from_city']} to {v['to_city']} ({v['distance_km']} km) in {v['minutes_between']} min, about {v['implied_speed_kmh']} km/h.", "confirmed", [r_v], "supports_malicious")); mal += 1
    elif v["to_city"] == prof.get("home_city"):
        findings.append(_f(f"Sign-in from the user's home city ({v['to_city']}).", "confirmed", [r_v, r_p], "supports_benign")); ben += 1
    else:
        findings.append(_f(f"Travel to {v['to_city']} is physically plausible ({v['implied_speed_kmh']} km/h).", "confirmed", [r_v], "neutral"))

    r_ip, ip = ex.call("lookup_ip", {"ip": p["src_ip"]})
    if ip.get("reputation") in ("malicious", "suspicious"):
        findings.append(_f(f"Source IP has {ip['reputation']} reputation ({ip['asn_name']}).", "confirmed", [r_ip], "supports_malicious")); mal += 1
    if ip.get("failed_logins_24h", 0) > 20:
        findings.append(_f(f"{ip['failed_logins_24h']} failed logins from this IP in 24h (spray pattern).", "confirmed", [r_ip], "supports_malicious")); mal += 1
    if ip.get("asn_type") in ("residential", "corporate"):
        findings.append(_f(f"Network is {ip['asn_type']} ({ip['asn_name']}).", "confirmed", [r_ip], "supports_benign")); ben += 1
    else:
        findings.append(_f(f"Network type is {ip.get('asn_type')} ({ip.get('asn_name')}).", "confirmed", [r_ip], "neutral"))

    r_d, dev = ex.call("check_device_history")
    r_a, au = ex.call("get_auth_details")
    if dev["known_device"]:
        findings.append(_f("Device has been seen for this user before.", "confirmed", [r_d], "supports_benign")); ben += 1
    elif ip.get("asn_type") == "hosting":
        findings.append(_f("New device from a hosting provider network.", "confirmed", [r_d, r_ip], "supports_malicious")); mal += 1
    if au["mfa_result"] in ("push_fatigue_pass", "fail_then_pass"):
        findings.append(_f(f"MFA result '{au['mfa_result']}' suggests push fatigue or retries.", "confirmed", [r_a], "supports_malicious")); mal += 1
    elif au["mfa_result"] == "pass":
        findings.append(_f("MFA passed on first attempt.", "confirmed", [r_a], "supports_benign")); ben += 1
    elif au["auth_method"] == "legacy_basic":
        findings.append(_f("Legacy basic auth used, MFA bypassed.", "confirmed", [r_a], "supports_malicious")); mal += 1
    else:
        findings.append(_f(f"MFA not required for this {au['auth_method']} sign-in; could not confirm who presented it.", "gap", [r_a]))

    r_m, prec = _precedent(ex, threshold)
    return _decide(findings, mal, ben, r_m, prec, "Sign-in")


def _decide(findings, mal, ben, r_mem, prec, noun) -> VerdictSubmission:
    if prec:
        findings.append(_f(
            f"Analyst precedent #{prec['correction_id']}: same pattern was corrected to {prec['verdict']} ({prec['note'] or 'no note'}).",
            "inferred", [r_mem], f"supports_{prec['verdict']}" if prec["verdict"] in ("malicious", "benign") else "neutral",
            f"Signature match score {prec['score']:.2f} against a prior correction.",
        ))
        verdict = prec["verdict"]
        summary = f"{noun} matches a pattern an analyst previously corrected to {verdict}."
    else:
        findings.append(_f("No prior analyst correction matches this pattern.", "gap", [r_mem]))
        if mal > 0:
            verdict, summary = "malicious", f"{noun} shows {mal} malicious indicator(s)."
        elif ben >= 2:
            verdict, summary = "benign", f"{noun} shows only benign indicators ({ben})."
        else:
            verdict, summary = "needs_human", f"{noun} has no decisive evidence either way; deferring to an analyst."
    action = {"malicious": "Quarantine message / revoke session and notify user.", "benign": "Close alert.", "needs_human": "Escalate to analyst queue."}[verdict]
    return VerdictSubmission(verdict=verdict, summary=summary, findings=findings, recommended_action=action)


def run_offline(alert_type: str, payload: dict, ex: Executor, threshold: float) -> VerdictSubmission:
    return reason_phishing(ex, payload, threshold) if alert_type == "phishing" else reason_login(ex, payload, threshold)
