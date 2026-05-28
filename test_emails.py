"""
PhishGuard v2 — Detection Test Suite
5 phishing emails + 2 legitimate emails, full pipeline, no DB required.
"""
import sys
import math
sys.stdout.reconfigure(encoding='utf-8')

from urllib.parse import urlparse

from backend.engine.email_parser import ParsedEmail
from backend.engine.feature_engine import FeatureEngine
from backend.engine.rule_engine import RuleEngine, _RuleProxy
from backend.engine.correlation_engine import CorrelationEngine
from backend.engine.legitimacy_engine import LegitimacyEngine
from backend.engine.scoring_engine import ScoringEngine
from backend.engine.rules_definitions import ALL_RULES


# ── Inject rules from definitions (no DB needed) ──────────────────────────────
proxies = []
for i, r in enumerate(ALL_RULES):
    proxies.append(_RuleProxy(
        id=i + 1,
        rule_id=r["rule_id"],
        name=r["name"],
        category=r["category"],
        weight=float(r["weight"]),
        description=r.get("description", ""),
        pattern=r.get("pattern", ""),
        is_enabled=r.get("is_enabled", True),
        is_custom=r.get("is_custom", False),
    ))
RuleEngine._rules_cache = proxies
RuleEngine._cache_ts = 9e18  # never expire

fe        = FeatureEngine()
re_engine = RuleEngine()
ce        = CorrelationEngine()
le        = LegitimacyEngine()
se        = ScoringEngine()


def make_email(
    sender="", subject="", body="", urls=None,
    dkim_pass=False, spf_pass=False, trusted=False,
    reply_to_domain="",
):
    p = ParsedEmail()
    p.sender_email   = sender
    p.sender_display = sender.split("@")[0] if "@" in sender else sender
    p.sender_domain  = sender.split("@")[1] if "@" in sender else ""
    p.sender_tld     = p.sender_domain.rsplit(".", 1)[-1] if "." in p.sender_domain else ""
    p.trusted_domain = trusted
    p.subject        = subject
    p.body_text      = body
    p.body_html      = ""
    p.body_text_from_html = ""
    p.body_visible   = body
    p.visible_text   = body
    p.urls           = urls or []
    p.unique_domains = set()
    for u in (urls or []):
        try:
            h = urlparse(u).hostname or ""
            if h:
                p.unique_domains.add(h)
        except Exception:
            pass

    import re as _re
    _ip_re = _re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    p.has_ip_url         = any(_ip_re.match(u) for u in p.urls)
    p.has_shortener      = False
    _abuse_tlds = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "pw", "loan", "win", "icu"}
    p.has_suspicious_tld = any(
        (urlparse(u).hostname or "").rsplit(".", 1)[-1] in _abuse_tlds
        for u in p.urls
    )
    p.link_text_mismatches = 0

    p.dkim_result   = "pass" if dkim_pass else ""
    p.dkim_present  = dkim_pass
    p.spf_result    = "pass" if spf_pass else "fail"
    p.dmarc_result  = ""
    p.x_mailer      = ""
    p.has_message_id = dkim_pass
    p.message_id    = "<test@domain.com>" if dkim_pass else ""
    p.has_mime_version = True
    p.x_priority    = ""
    p.headers       = {}
    p.reply_to_domain = reply_to_domain

    p.has_script        = False
    p.has_iframe        = False
    p.has_meta_refresh  = False
    p.hidden_text_count = 0
    p.html_nesting_depth = 0
    p.html_entity_count = 0
    p.inline_style_count = 0
    p.has_svg           = False
    p.has_canvas        = False
    p.external_image_count = 0
    p.has_base64_image  = False
    p.has_external_css  = False
    p.attachments       = []
    p.has_unsubscribe   = False
    p.has_list_id       = False
    p.send_hour         = 10
    return p


def analyse(label, expected, p):
    fs      = fe.extract(p)
    matches = re_engine.evaluate(p)
    corr    = ce.correlate(fs, matches)
    leg     = le.evaluate(fs)
    scoring = se.score(matches, corr, leg)

    ok     = scoring.classification == expected
    status = "PASS" if ok else "FAIL"

    print(f"  [{status}] {label}")
    print(f"         Score : {scoring.risk_score:.1f}/100")
    print(f"         Result: {scoring.classification.upper()}  (expected {expected.upper()})")

    top = sorted(matches, key=lambda m: m.weight, reverse=True)[:4]
    if top:
        rule_str = " | ".join(f"{m.rule_id} ({m.name})" for m in top)
        print(f"         Rules : {rule_str}")

    if corr.triggered_composites:
        comp_str = " | ".join(
            f"{c['name']} [{c['severity']}]" for c in corr.triggered_composites
        )
        print(f"         Comps : {comp_str}")

    leg_names = [d["signal"] for d in leg.deduction_reasons]
    print(f"         Legit : -{leg.legitimacy_deduction:.1f}  ({', '.join(leg_names) if leg_names else 'none'})")
    print()
    return ok


# ── Test cases ────────────────────────────────────────────────────────────────

SEPARATOR = "=" * 72

print()
print(SEPARATOR)
print("  PhishGuard v2  --  Detection Test Suite")
print("  5 Phishing  |  2 Legitimate")
print(SEPARATOR)
print()

results = []

# ─── PHISHING ────────────────────────────────────────────────────────────────
print(">>> PHISHING EMAILS")
print()

# P1: Job offer scam
results.append(analyse(
    "P1: Job Offer Scam  (remote position + salary + form)",
    "phishing",
    make_email(
        sender="hr@career-update-portal.example",
        subject="Remote Job Opportunity",
        body=(
            "Dear Candidate, We reviewed your online profile and are pleased to offer "
            "you a remote position with a starting salary of $5,000/month. Please "
            "download and complete the employment form below to proceed with onboarding: "
            "http://career-update-portal.example  "
            "Positions are limited and interviews close today.  Human Resources"
        ),
        urls=["http://career-update-portal.example"],
    ),
))

# P2: PayPal credential phishing
results.append(analyse(
    "P2: Credential Phishing  (PayPal suspended + verify password)",
    "phishing",
    make_email(
        sender="security@paypa1-alert.com",
        subject="URGENT: Your PayPal Account Has Been Suspended",
        body=(
            "Dear Customer, Your PayPal account has been temporarily suspended due to "
            "unusual activity detected on your account. To restore access immediately, "
            "please verify your account by clicking the link below and entering your "
            "password and credit card details. Act now -- your account will be "
            "permanently closed within 24 hours. http://paypa1-secure-verify.xyz/login"
        ),
        urls=["http://paypa1-secure-verify.xyz/login"],
    ),
))

# P3: CEO gift-card BEC scam
results.append(analyse(
    "P3: CEO Gift Card Scam  (BEC -- secrecy + gift card demand)",
    "phishing",
    make_email(
        sender="ceo-john@company-helpdesk.net",
        subject="Urgent - Confidential Task",
        body=(
            "Hi, I need you to handle something urgently and discreetly. I need you to "
            "purchase 5 Google Play gift cards worth $200 each. Please do not mention "
            "this to anyone in the office. Send me the gift card codes as soon as you "
            "buy them. This is time-sensitive. Do not forward this email. "
            "John Smith, CEO"
        ),
        urls=[],
    ),
))

# P4: Lottery / prize scam
results.append(analyse(
    "P4: Lottery Prize Scam  (Dear Winner + bank details request)",
    "phishing",
    make_email(
        sender="notification@intl-lottery-prize.tk",
        subject="Congratulations! You have won $1,500,000",
        body=(
            "Dear Winner, Congratulations! You have been selected as the lucky winner "
            "of our International Lottery draw. Your prize is $1,500,000 USD. To claim "
            "your prize, please reply with your full name, address, bank account number "
            "and date of birth to process the transfer immediately. "
            "Hurry -- this offer expires today!"
        ),
        urls=[],
    ),
))

# P5: Banking phishing — suspicious login + click to verify
results.append(analyse(
    "P5: Banking Phishing  (suspicious login + verify link + high-abuse TLD)",
    "phishing",
    make_email(
        sender="alerts@secure-crdb-bank.ml",
        subject="Suspicious Login Detected - Action Required",
        body=(
            "Dear Account Holder, We detected suspicious login activity on your CRDB "
            "Bank account. Your account has been temporarily limited. Click the link "
            "below to verify your identity and restore access immediately. Failure to "
            "verify within 30 minutes will result in permanent account suspension. "
            "http://crdb-secure-login.ml/verify"
        ),
        urls=["http://crdb-secure-login.ml/verify"],
    ),
))

# ─── LEGITIMATE ───────────────────────────────────────────────────────────────
print(">>> LEGITIMATE EMAILS")
print()

# L1: Genuine job application acknowledgment from Microsoft
results.append(analyse(
    "L1: Job Application Acknowledgment  (Microsoft, personalised, DKIM+SPF)",
    "legitimate",
    make_email(
        sender="careers@microsoft.com",
        subject="Your application to Microsoft - Software Engineer",
        body=(
            "Dear Julius, Thank you for applying for the Software Engineer position at "
            "Microsoft. We have received your application and our team will review it "
            "carefully. We will be in touch within 5-7 business days if your profile "
            "matches our requirements. In the meantime, feel free to explore our "
            "careers page for other opportunities at https://careers.microsoft.com. "
            "Best regards, Microsoft Careers Team"
        ),
        urls=["https://careers.microsoft.com"],
        dkim_pass=True,
        spf_pass=True,
        trusted=True,
    ),
))

# L2: Genuine CRDB Bank scheduled maintenance notice
results.append(analyse(
    "L2: Bank Maintenance Notice  (CRDB, personalised, DKIM+SPF)",
    "legitimate",
    make_email(
        sender="notifications@crdbbank.com",
        subject="Scheduled System Maintenance - Sunday 2am-4am",
        body=(
            "Dear Julius Mwangi, Please be informed that CRDB Bank online banking "
            "services will be temporarily unavailable on Sunday 25 May from 2:00 AM "
            "to 4:00 AM for scheduled system maintenance. During this window, mobile "
            "banking and internet banking will be offline. ATM services will remain "
            "available. We apologise for any inconvenience. For assistance, contact "
            "us at 0800 110 022. CRDB Bank Customer Support"
        ),
        urls=["https://www.crdbbank.com/support"],
        dkim_pass=True,
        spf_pass=True,
        trusted=True,
    ),
))

# ── Summary ───────────────────────────────────────────────────────────────────
print(SEPARATOR)
passed = sum(results)
total  = len(results)
verdict = "ALL PASS" if passed == total else f"{total - passed} FAILED"
print(f"  Result: {passed}/{total} correct  --  {verdict}")
print(SEPARATOR)
print()
