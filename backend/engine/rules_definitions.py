"""
backend/engine/rules_definitions.py
=====================================
Complete detection rule seed data for PhishGuard v2.

DESIGN PHILOSOPHY:
  Every rule is an ISOLATED signal — one pattern, one evidence type.
  Rules are NOT decisions; they are EVIDENCE.
  The CORRELATION ENGINE turns corroborated evidence into decisions.

  A single "urgent" keyword must NEVER classify an email as phishing alone.
  BUT: unusual_activity + credential_request + generic_greeting = phishing.

BINARY CLASSIFICATION (threshold = 35 / 100):
  Old three-class system: legitimate < 21, suspicious 21–54, phishing ≥ 55.
  New binary system: legitimate < 35, phishing ≥ 35.
  Rules that previously pushed emails into "suspicious" (21–54) now
  correctly push them into phishing when they accumulate at ≥ 35.

  With sigmoid k=0.085:
    3–4 content signals  → raw ~5–6  → normalised ~35–41%  → PHISHING
    1–2 weak signals     → raw ~2–3  → normalised ~15–23%  → LEGITIMATE
    Legitimacy deduction → −5 to −30 → can rescue borderline emails

RULE WEIGHT GUIDE (original calibration):
  3.0  = Near-certain phishing (IP-as-URL, .exe macro, double-extension)
  2.5  = Very strong indicator (@ in URL, typosquatting, gift card request)
  2.0  = Strong indicator (URL shortener, urgency language, missing DKIM)
  1.5  = Moderate indicator (free-email sender, excessive caps, high-abuse TLD)
  1.0  = Weak indicator (generic greeting, off-hours send, missing Message-ID)
  0.5  = Very weak / only meaningful in combination (exclamation marks)

Categories:
  url_analysis           – URL structure and destination analysis
  content_keyword        – Body and subject keyword patterns
  sender_verification    – Sender identity and domain analysis
  header_authentication  – SPF / DKIM / DMARC / header integrity
  html_obfuscation       – HTML tricks and obfuscation techniques
  behavioral             – Attachment and behavioral patterns
  linguistic_analysis    – Language style and obfuscation
"""

ALL_RULES: list = [

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 1: URL ANALYSIS  (multiplier × 1.4)
    # ═══════════════════════════════════════════════════════════════════

    {"rule_id": "URL_001", "name": "IP address as hostname",
     "category": "url_analysis", "weight": 3.0, "is_enabled": True, "is_custom": False,
     "description": "A bare IP address is used instead of a domain name. Legitimate services "
                    "never do this. Phishers use IPs to avoid domain-based reputation checks.",
     "pattern": r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"},

    {"rule_id": "URL_002", "name": "URL shortener service",
     "category": "url_analysis", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "A URL shortening service hides the real destination. "
                    "Phishers use these to prevent preview-based detection.",
     "pattern": r"https?://(bit\.ly|tinyurl\.com|goo\.gl|ow\.ly|t\.co|buff\.ly|is\.gd|rb\.gy|short\.link|cutt\.ly|shorte\.st)/"},

    {"rule_id": "URL_003", "name": "High-abuse TLD in URL",
     "category": "url_analysis", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "The URL uses a top-level domain with extremely high phishing abuse rates.",
     "pattern": r"https?://[^\s/]+\.(xyz|top|click|tk|ml|ga|cf|gq|pw|loan|win|bid|download|work|rest|buzz|icu)(/|$|\?)"},

    {"rule_id": "URL_004", "name": "Brand name in subdomain of unrelated domain",
     "category": "url_analysis", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "A well-known brand appears as a subdomain of an unrelated domain. "
                    "e.g. paypal.evil-site.com — the real domain is evil-site.com.",
     "pattern": r"https?://(paypal|amazon|google|microsoft|apple|facebook|netflix|crdb|nmb|equity|kcb|stanbic|barclays|mastercard|visa)\.[a-z0-9\-]+\.[a-z]{2,}/"},

    {"rule_id": "URL_005", "name": "Excessively long URL (>120 chars)",
     "category": "url_analysis", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "URLs longer than 120 characters obscure the real destination.",
     "pattern": r"https?://\S{121,}"},

    {"rule_id": "URL_006", "name": "Redirect chain in URL parameters",
     "category": "url_analysis", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "An embedded URL parameter indicates a redirect chain used to bypass "
                    "URL-based link scanners.",
     "pattern": r"[?&](url|redirect|next|goto|target|link|return_url|continue|forward)=https?://"},

    {"rule_id": "URL_007", "name": "@ symbol in URL (destination masking)",
     "category": "url_analysis", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "An @ symbol in a URL causes browsers to ignore everything before it. "
                    "http://legitimate.com@evil.com/phish goes to evil.com.",
     "pattern": r"https?://[^\s@]+@[^\s@]+"},

    {"rule_id": "URL_008", "name": "Too many subdomains (≥4 levels)",
     "category": "url_analysis", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "Excessive subdomains simulate legitimate-looking URL structure "
                    "while routing to a malicious domain.",
     "pattern": r"https?://([a-zA-Z0-9\-]+\.){4,}[a-zA-Z]{2,}"},

    {"rule_id": "URL_009", "name": "Hexadecimal IP address in URL",
     "category": "url_analysis", "weight": 3.0, "is_enabled": True, "is_custom": False,
     "description": "A hexadecimal representation of an IP address evades IP-based filters.",
     "pattern": r"https?://0x[a-fA-F0-9]{2,}"},

    {"rule_id": "URL_010", "name": "Heavy percent-encoding in URL",
     "category": "url_analysis", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "Five or more consecutive percent-encoded characters indicates "
                    "deliberate obfuscation to hide a malicious URL.",
     "pattern": r"(%[0-9A-Fa-f]{2}){5,}"},

    {"rule_id": "URL_011", "name": "Punycode domain (homograph attack)",
     "category": "url_analysis", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "xn-- punycode encoding disguises characters from other alphabets "
                    "as ASCII, making a fake domain look identical to a real one.",
     "pattern": r"xn--[a-z0-9\-]+"},

    {"rule_id": "URL_012", "name": "Auth/session parameters in URL",
     "category": "url_analysis", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "Authentication-related parameters pointing to another URL "
                    "are used to steal session credentials via open redirect.",
     "pattern": r"[?&](token|session|auth|credential|key|apikey)=https?"},

    {"rule_id": "URL_013", "name": "Data URI in HTML (embedded page)",
     "category": "url_analysis", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "A data:text/html;base64 URI embeds an entire HTML page inline, "
                    "completely bypassing URL-based phishing filters.",
     "pattern": r"data:text/html;base64"},

    {"rule_id": "URL_014", "name": "JavaScript URI scheme",
     "category": "url_analysis", "weight": 3.0, "is_enabled": True, "is_custom": False,
     "description": "A javascript: URI executes code when clicked — never legitimate in email.",
     "pattern": r"javascript\s*:"},

    {"rule_id": "URL_015", "name": "Login/verify/reset path on URL",
     "category": "url_analysis", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "URL path contains login, verify, secure, reset or account keywords. "
                    "Phishing pages mimic bank portals by using these path keywords.",
     "pattern": r"https?://[^\s/]+/(?:login|verify|secure|account|signin|webscr|update|reset|confirm)[/?\s]"},

    {"rule_id": "URL_016", "name": "Security/auth keywords in domain name",
     "category": "url_analysis", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "The URL's domain name contains words like 'security', 'verify', "
                    "'login', 'reset', or 'secure' that are commonly used by phishers "
                    "to make fake domains look trustworthy. Excludes known major brands.",
     "pattern": r"https?://(?!(?:www\.)?(?:google|microsoft|amazon|apple|facebook|twitter|linkedin)\.[a-z])[a-z0-9\-]*(?:security|secure|verify|login|reset|confirm|update|bank|account)[a-z0-9\-]*\.[a-z]{2,}"},

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 2: CONTENT & KEYWORDS  (multiplier × 0.9)
    # Low multiplier keeps content signals from dominating alone; they must
    # accumulate or be corroborated before crossing the phishing threshold.
    # ═══════════════════════════════════════════════════════════════════

    {"rule_id": "KW_001", "name": "Urgency and threat language",
     "category": "content_keyword", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "Urgency or threat language pressures the recipient into acting without "
                    "thinking. Includes account-threat lures ('account suspended', 'unusual activity') "
                    "and job-scam pressure ('positions limited', 'interviews close today'). "
                    "Weight MODERATE — many legitimate automated emails also use urgency language.",
     "pattern": r"\b(urgent|immediately|account.{0,10}(suspended|closed|blocked|locked|terminated|deactivated)|"
                r"verify.{0,10}(now|immediately)|limited.{0,5}time|act.{0,5}now|"
                r"deadline.{0,10}(today|tomorrow)|final.{0,5}notice|last.{0,5}(chance|warning)|"
                r"unusual.{0,10}(activity|login|attempt|access|transaction)|"
                r"suspicious.{0,10}(activity|login|transaction)|"
                r"access.{0,10}(revoked|terminated|suspended)|"
                r"temporarily.{0,10}(limited|suspended|restricted)|"
                r"(position|seat|slot|opening)s?.{0,10}(are.{0,5})?limited|"
                r"(position|seat|slot|opening)s?.{0,10}fill(ing|ed).{0,10}fast|"
                r"interviews?.{0,10}close.{0,10}today|"
                r"closing.{0,10}(today|soon|shortly|immediately)|"
                r"limited.{0,10}(position|seat|slot|opening)s?)\b"},

    {"rule_id": "URGENCY_002", "name": "Short time-window access pressure",
     "category": "content_keyword", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "A link or access window that expires within hours or minutes creates "
                    "panic pressure. Phishing emails use 1–24 hours; legitimate notifications "
                    "use days-long windows. Also catches 'expires today' / 'within 30 minutes'.",
     "pattern": r"expir\w+\s+in\s+\d+\s*(?:hour|minute|min)s?\b|"
                r"link\s+expir\w*|"
                r"within.{0,10}\d+.{0,10}(?:minute|hour)s?\b|"
                r"in.{0,5}the.{0,5}next.{0,5}\d+.{0,10}(?:minute|hour)s?\b|"
                r"expir\w+\s+(?:today|now|immediately|soon)\b"},

    {"rule_id": "KW_002", "name": "Explicit credential or personal data request",
     "category": "content_keyword", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "The email explicitly requests sensitive information: PIN, password, "
                    "account number, ATM PIN, CVV, OTP, credit card, or date of birth. "
                    "Legitimate organisations NEVER ask for these via email. This is one "
                    "of the strongest phishing signals. Patterns cover both formal "
                    "('please provide') and casual ('send us your', 'reply with') phrasing.",
     "pattern": r"\b(enter.{0,15}(pin|password|passcode|account.number)|"
                r"provide.{0,15}(pin|password|ssn|account.number|bank.details|card.details)|"
                r"confirm.{0,15}(pin|password|account)|"
                r"send.{0,20}(your|the|us).{0,20}(pin|password|account.number|bank.details|card.details|atm.pin)|"
                r"share.{0,15}(pin|password|account|card|bank).{0,10}(number|detail|information)|"
                r"your.{0,10}pin.{0,10}(is|below)|"
                r"reply.{0,20}(with|using).{0,40}(pin|password|account.number|atm.pin|credit.card|bank.detail)|"
                r"\bcvv\b|one.time.password|one.time.pin|security.code.{0,10}(is|below|:)|"
                r"enter.{0,10}otp|submit.{0,10}password|"
                r"atm.{0,5}pin|account.{0,5}number.{0,20}(and|plus|with).{0,10}pin)\b"},

    {"rule_id": "KW_003", "name": "Prize / lottery / inheritance lure",
     "category": "content_keyword", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "Prize, lottery or unexpected inheritance claims are used in advance-fee "
                    "fraud. Nobody wins a lottery they did not enter.",
     "pattern": r"\b(you.{0,10}(won|have won|are a winner)|lottery.{0,10}(winner|prize|fund)|"
                r"inheritance.{0,10}(claim|fund|million)|unclaimed.{0,10}(fund|prize)|jackpot|"
                r"lucky.{0,10}winner|prize.{0,10}(notification|claim)|selected.{0,10}(winner|lucky)|"
                r"international.{0,15}(promotion|draw|lottery))\b"},

    {"rule_id": "KW_004", "name": "Unsolicited wire transfer / financial request",
     "category": "content_keyword", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "Wire transfer or payment requests out of context indicate BEC fraud. "
                    "Legitimate invoices are expected; unexpected payment demands are not.",
     "pattern": r"\b(wire.{0,5}transfer|send.{0,10}(money|funds|payment)|transfer.{0,10}(funds|amount)|"
                r"western.{0,5}union|moneygram|mobile.{0,5}money.{0,5}(send|transfer))\b"},

    {"rule_id": "KW_005", "name": "Generic impersonal greeting",
     "category": "content_keyword", "weight": 0.8, "is_enabled": True, "is_custom": False,
     "description": "A generic greeting ('Dear Customer', 'Dear Candidate', 'Dear Winner') "
                    "indicates a mass phishing campaign unable to personalise. Weight LOW — "
                    "many legitimate bulk emails also use generic greetings.",
     "pattern": r"^.{0,50}\bDear\s+(Customer|User|Account.Holder|Valued.Client|Member|"
                r"Subscriber|Sir/Madam|Client|Beneficiary|Winner|Employee|"
                r"Candidate|Applicant|Investor|Recipient)\b"},

    {"rule_id": "KW_006", "name": "Authority impersonation (government/tax)",
     "category": "content_keyword", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "The email impersonates a government or tax authority. IRS, FBI, "
                    "TRA (Tanzania), customs, police threats are classic phishing tactics.",
     "pattern": r"\b(internal.revenue.service|irs\b|fbi\b|interpol|court.order|legal.action|"
                r"subpoena|arrest.warrant|tanzania.revenue|tra.refund|customs.officer|police.warrant)\b"},

    {"rule_id": "KW_007", "name": "Click-link-to-verify phishing lure",
     "category": "content_keyword", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "The email instructs the recipient to click a link to verify, confirm, "
                    "or restore account access — the core action-hook of phishing emails. "
                    "By itself weak; combined with urgency or credential request: strong signal.",
     "pattern": r"\b(click.{0,20}(link|here|below|button).{0,40}(verify|confirm|reset|secure|access|restore|update)|"
                r"verify.{0,20}(by|via).{0,20}click|"
                r"click.{0,20}to.{0,10}(verify|confirm|reset|secure|restore|update).{0,20}(account|password|access|identity)|"
                r"follow.{0,10}(the|this).{0,10}link.{0,30}(verify|confirm|reset|access))\b"},

    {"rule_id": "KW_008", "name": "Request to reply with personal information",
     "category": "content_keyword", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "The email asks the recipient to REPLY with personal or financial "
                    "information (full name, ID number, bank details, address, phone). "
                    "Legitimate organisations never collect sensitive data by email reply.",
     "pattern": r"\b(reply.{0,20}(with|using|to.{0,10}this.{0,5}email).{0,60}(full.name|id.number|account|bank|credit.card|address|phone|details)|"
                r"send.{0,20}(the.{0,10}following|your).{0,60}(full.name|id.number|account|bank.detail|credit.card|address|date.of.birth)|"
                r"provide.{0,20}(the.{0,10}following|your).{0,60}(full.name|id.number|account|bank.detail|credit.card))\b"},

    {"rule_id": "SOC_001", "name": "Fear-based threat language",
     "category": "content_keyword", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "Explicit threats of arrest, lawsuit, account breach, or termination "
                    "are designed to create panic and override rational decision-making.",
     "pattern": r"\b(will.be.arrested|face.legal.action|breach.of.account|account.breached|"
                r"immediately.terminated|criminal.charges|law.enforcement.will|your.data.will.be.deleted)\b"},

    {"rule_id": "SOC_002", "name": "Secrecy / confidentiality demand",
     "category": "content_keyword", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "Requests for secrecy prevent the victim from verifying the request "
                    "with colleagues or IT — a classic BEC social engineering tactic.",
     "pattern": r"\b(keep.{0,10}(confidential|secret|private)|do.not.tell|do.not.discuss|"
                r"between.us.only|do.not.forward|speak.to.no.one)\b"},

    {"rule_id": "SOC_003", "name": "Gift card payment demand",
     "category": "content_keyword", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "Gift card payment requests are exclusively used in scams. No legitimate "
                    "organisation ever accepts payment via iTunes/Steam/Google Play cards.",
     "pattern": r"\b(gift.card|itunes.card|steam.card|google.play.card|amazon.gift.card|"
                r"buy.{0,10}gift.card|gift.card.code|e-gift.card)\b"},

    {"rule_id": "SOC_004", "name": "Cryptocurrency payment request",
     "category": "content_keyword", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "Cryptocurrency payment demands via email are a hallmark of ransomware "
                    "and extortion scams. Legitimate payroll and billing never use crypto.",
     "pattern": r"\b(bitcoin.address|send.{0,10}bitcoin|ethereum.wallet|usdt.address|"
                r"crypto.wallet.address|pay.{0,10}in.bitcoin|tether.address|send.{0,10}crypto)\b"},

    {"rule_id": "SOC_005", "name": "Fake work-from-home / easy money offer",
     "category": "content_keyword", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "Unsolicited work-from-home or easy income offers recruit money mules "
                    "or harvest personal/banking credentials. Includes generic 'remote position "
                    "with salary' job-scam lures and 'download the employment form' hooks.",
     "pattern": r"\b(work.from.home.{0,20}(earn|income|salary)|easy.{0,10}income|"
                r"no.experience.needed.{0,20}earn|earn.{0,15}per.week.{0,20}from.home|"
                r"remote.{0,15}(position|role|job|work|opportunity).{0,50}(salary|\$[\d,]+|per.month|per.week)|"
                r"starting.{0,10}salary.{0,30}(\$[\d,]+|\d{3,}).{0,10}(month|week|year)|"
                r"download.{0,20}(employment|job|application|onboarding).{0,15}form|"
                r"complete.{0,15}(employment|onboarding|application).{0,10}form)\b"},

    {"rule_id": "KW_009", "name": "Unsolicited employment offer scam",
     "category": "content_keyword", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "Unsolicited job offers citing a profile review, a specific salary, and a "
                    "form to complete are classic recruitment scams that harvest personal data "
                    "or recruit money mules. 'We reviewed your profile and are pleased to offer' "
                    "is the signature phrase of this attack type.",
     "pattern": r"\b((reviewed|selected).{0,20}(your|their).{0,15}(profile|resume|cv|application)|"
                r"pleased.{0,15}(to.{0,5})?(offer|hire|recruit).{0,20}(you.{0,10})?(remote|position|role)|"
                r"remote.{0,15}position.{0,30}starting.{0,10}salary|"
                r"employment.{0,10}(form|application).{0,20}(download|complete|fill))\b"},

    {"rule_id": "SOC_006", "name": "Credential verification or account restoration pressure",
     "category": "content_keyword", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "Pressure to re-verify credentials or restore access immediately. "
                    "Covers 'confirm your login', 'reset your password now', 'verify your "
                    "identity', 'restore access', 'update banking details'. Legitimate "
                    "password resets are USER-initiated, not sent unsolicited.",
     "pattern": r"\b(re.?verify.{0,15}account|confirm.{0,10}your.{0,10}(login|credentials|password)|"
                r"update.{0,15}banking.details|confirm.{0,10}bank.{0,10}details|"
                r"re.?enter.{0,15}(password|pin|credentials)|"
                r"verify.{0,15}your.{0,15}(identity|account.information|information)|"
                r"restore.{0,15}(your.{0,10})?(access|account)|"
                r"reset.{0,15}your.{0,15}password|"
                r"permanent.{0,15}account.{0,15}(deactivation|suspension|termination))\b"},

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 3: SENDER VERIFICATION  (multiplier × 1.3)
    # ═══════════════════════════════════════════════════════════════════

    {"rule_id": "SND_001", "name": "Display name brand mismatch with domain",
     "category": "sender_verification", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "The sender display name contains a well-known brand but the actual "
                    "email domain is unrelated. Evaluated programmatically.",
     "pattern": "DISPLAY_DOMAIN_MISMATCH"},

    {"rule_id": "SND_002", "name": "Free email provider for official context",
     "category": "sender_verification", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "A free consumer email provider (Gmail, Yahoo, Hotmail) is used by a "
                    "sender claiming to be a bank, government, or corporation. "
                    "Weight MODERATE — small businesses legitimately use Gmail.",
     "pattern": r"@(gmail|yahoo|hotmail|outlook|live|aol|icloud|protonmail|yandex|mail|gmx)\.(com|co\.tz|net|org|ke|ug)"},

    {"rule_id": "SND_003", "name": "Typosquatting / lookalike domain",
     "category": "sender_verification", "weight": 3.0, "is_enabled": True, "is_custom": False,
     "description": "The sender domain is visually similar to a known brand domain. "
                    "Evaluated with edit-distance algorithm — strongest sender signal.",
     "pattern": "TYPOSQUATTING_CHECK"},

    {"rule_id": "SND_004", "name": "Reply-To domain differs from From domain",
     "category": "sender_verification", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "Reply-To points to a different domain than From, routing all victim "
                    "replies to an attacker-controlled inbox.",
     "pattern": "REPLY_TO_MISMATCH"},

    {"rule_id": "SND_005", "name": "Randomised local-part in sender address",
     "category": "sender_verification", "weight": 0.5, "is_enabled": True, "is_custom": False,
     "description": "The sender's local-part is a long purely-alphanumeric string, "
                    "indicating automated phishing infrastructure. Weight VERY LOW.",
     "pattern": r"^[a-z0-9]{14,}@"},

    {"rule_id": "SND_006", "name": "Sender domain uses high-abuse TLD",
     "category": "sender_verification", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "The sender's email domain uses a TLD with extremely high phishing "
                    "abuse rates. Legitimate banks and corporations never send from .tk/.ml etc.",
     "pattern": r"@[a-z0-9\-]+\.(tk|ml|ga|cf|gq|xyz|top|click|pw|loan|win|bid|download|work|icu)\b"},

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 4: HEADER AUTHENTICATION  (multiplier × 1.3)
    # ═══════════════════════════════════════════════════════════════════

    {"rule_id": "HDR_003", "name": "DMARC policy fail in auth-results",
     "category": "header_authentication", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "Authentication-Results header shows dmarc=fail — likely spoofing.",
     "pattern": "DMARC_NOT_ENFORCED"},

    {"rule_id": "HDR_004", "name": "Known spam/bulk mail tool in X-Mailer",
     "category": "header_authentication", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "The X-Mailer header identifies a bulk or spam mailing tool.",
     "pattern": r"X-Mailer:\s*(PHPMailer|Mass.Mailer|Bulk.Mail|DreamMail|SendBlaster|Gammadyne)"},

    {"rule_id": "HDR_005", "name": "Missing Message-ID header",
     "category": "header_authentication", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "All legitimate mail servers inject a unique Message-ID. "
                    "Absence indicates a manually crafted or spam-tool-generated email.",
     "pattern": "MISSING_MESSAGE_ID"},

    {"rule_id": "HDR_006", "name": "Malformed Message-ID",
     "category": "header_authentication", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "Message-ID header is not properly formatted (<unique@domain>). "
                    "Malformed IDs indicate a low-quality phishing tool.",
     "pattern": r"Message-ID:\s*[^<\s]"},

    {"rule_id": "HDR_007", "name": "X-Priority set to Highest (1)",
     "category": "header_authentication", "weight": 1.0, "is_enabled": True, "is_custom": False,
     "description": "X-Priority: 1 (Highest) artificially elevates urgency perception.",
     "pattern": r"X-Priority:\s*1\b"},

    {"rule_id": "HDR_008", "name": "SPF hard fail in Received-SPF",
     "category": "header_authentication", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "Received-SPF header explicitly shows 'fail' — the sending server is "
                    "NOT authorised to send for this domain. Hard evidence of sender spoofing.",
     "pattern": r"Received-SPF:\s*fail\b"},

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 5: HTML OBFUSCATION  (multiplier × 1.2)
    # ═══════════════════════════════════════════════════════════════════

    {"rule_id": "HTML_001", "name": "Visible link text domain differs from href",
     "category": "html_obfuscation", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "An anchor tag shows one domain as text but href points elsewhere. "
                    "Classic visual deception.",
     "pattern": "LINK_TEXT_HREF_MISMATCH"},

    {"rule_id": "HTML_002", "name": "HTML entity obfuscation of keywords",
     "category": "html_obfuscation", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "4+ consecutive HTML entities (&#NNN;) encode text to evade keyword filters.",
     "pattern": r"(&#\d{2,4};){4,}"},

    {"rule_id": "HTML_003", "name": "Hidden/invisible text in HTML",
     "category": "html_obfuscation", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "display:none, visibility:hidden, or font-size:0 hides content from "
                    "human viewers but may deceive spam filters.",
     "pattern": r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0)"},

    {"rule_id": "HTML_004", "name": "Excessive inline CSS (>20 style attributes)",
     "category": "html_obfuscation", "weight": 1.0, "is_enabled": True, "is_custom": False,
     "description": "Auto-generated phishing kit HTML typically contains dense inline styling.",
     "pattern": "HTML_INLINE_STYLE_DENSITY"},

    {"rule_id": "HTML_005", "name": "Script tag in email body",
     "category": "html_obfuscation", "weight": 3.0, "is_enabled": True, "is_custom": False,
     "description": "A <script> tag in email HTML indicates a malicious phishing kit "
                    "attempting code execution — never legitimate in email HTML.",
     "pattern": r"<\s*script[\s>]"},

    {"rule_id": "HTML_006", "name": "Iframe in email body",
     "category": "html_obfuscation", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "An <iframe> loads an external phishing page invisibly inside the email. "
                    "Legitimate HTML emails never use iframes.",
     "pattern": r"<\s*iframe[\s>]"},

    {"rule_id": "HTML_007", "name": "Meta-refresh redirect",
     "category": "html_obfuscation", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "A meta http-equiv=refresh auto-redirects after a short delay.",
     "pattern": r"http-equiv\s*=\s*['\"]refresh"},

    {"rule_id": "HTML_008", "name": "Base64-encoded images",
     "category": "html_obfuscation", "weight": 1.0, "is_enabled": True, "is_custom": False,
     "description": "Base64 inline images are used to evade image-hosting-based spam scanners. "
                    "Weight LOW because legitimate HTML emails also use inline images.",
     "pattern": r"data:image/[a-z]{2,5};base64"},

    {"rule_id": "HTML_009", "name": "Large obfuscating HTML comments",
     "category": "html_obfuscation", "weight": 1.0, "is_enabled": True, "is_custom": False,
     "description": "HTML comment blocks longer than 200 characters pad content "
                    "to confuse Bayesian spam filters.",
     "pattern": r"<!--.{200,}-->"},

    {"rule_id": "HTML_010", "name": "External form submission (credential harvesting)",
     "category": "html_obfuscation", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "An HTML form with action= pointing to an external URL "
                    "harvests credentials typed by the victim.",
     "pattern": r"<form[^>]+action\s*=\s*['\"]https?://"},

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 6: BEHAVIORAL  (multiplier × 1.1)
    # ═══════════════════════════════════════════════════════════════════

    {"rule_id": "BEH_001", "name": "Dangerous executable attachment",
     "category": "behavioral", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "Attachment with executable extension (.exe, .js, .vbs, .bat, .scr, .ps1) "
                    "can run malware when opened.",
     "pattern": r"\.(exe|js|vbs|bat|cmd|scr|ps1|jar|msi|dmg|app)\b"},

    {"rule_id": "BEH_002", "name": "Macro-enabled Office attachment",
     "category": "behavioral", "weight": 3.0, "is_enabled": True, "is_custom": False,
     "description": "Macro-enabled Office files (.docm, .xlsm, .pptm) are the primary "
                    "delivery vehicle for RAT and ransomware payloads.",
     "pattern": r"\.(docm|xlsm|pptm|dotm|xlam)\b"},

    {"rule_id": "BEH_003", "name": "Double-extension disguised executable",
     "category": "behavioral", "weight": 3.0, "is_enabled": True, "is_custom": False,
     "description": "invoice.pdf.exe disguises a malicious executable as a harmless document.",
     "pattern": r"\.(pdf|doc|jpg|png|txt)\.(exe|scr|js|bat|cmd|vbs)"},

    {"rule_id": "BEH_004", "name": "ISO / IMG disk image attachment",
     "category": "behavioral", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "ISO disk images bypass email attachment scanners. Used to deliver malware.",
     "pattern": r"\.(iso|img)\b"},

    {"rule_id": "BEH_005", "name": "Windows shortcut (.lnk) attachment",
     "category": "behavioral", "weight": 3.0, "is_enabled": True, "is_custom": False,
     "description": "Windows .lnk shortcuts can execute arbitrary commands when opened. "
                    "Widely used in APT spear-phishing campaigns.",
     "pattern": r"\.lnk\b"},

    {"rule_id": "BEH_006", "name": "HTML attachment (embedded phishing page)",
     "category": "behavioral", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "An HTML attachment renders a self-contained phishing page locally, "
                    "completely bypassing URL reputation checks.",
     "pattern": r"\.(html?)\b"},

    {"rule_id": "BEH_007", "name": "Password-protected archive",
     "category": "behavioral", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "Password-protected zip/rar files bypass antivirus attachment scanning.",
     "pattern": r"password.{0,30}\.(zip|rar|7z)"},

    {"rule_id": "BEH_008", "name": "Midnight-5AM send time",
     "category": "behavioral", "weight": 0.8, "is_enabled": True, "is_custom": False,
     "description": "Email sent between midnight and 5AM UTC. Phishing automation often runs "
                    "at off-hours. Weight LOW — timezone differences make this weak alone.",
     "pattern": "SENDING_HOUR_CHECK"},

    {"rule_id": "BEH_009", "name": "Multiple external tracking images (3+ domains)",
     "category": "behavioral", "weight": 1.0, "is_enabled": True, "is_custom": False,
     "description": "Images from 3+ distinct external domains are used as tracking pixels.",
     "pattern": "EXTERNAL_IMAGE_COUNT"},

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 7: LINGUISTIC ANALYSIS  (multiplier × 0.7)
    # ═══════════════════════════════════════════════════════════════════

    {"rule_id": "LING_001", "name": "Excessive ALL-CAPS words",
     "category": "linguistic_analysis", "weight": 0.8, "is_enabled": True, "is_custom": False,
     "description": "Three or more ALL-CAPS words (5+ letters each) indicate "
                    "aggressive social engineering pressure (e.g. URGENT ACCOUNT SUSPENDED). "
                    "Evaluated by a case-sensitive programmatic handler (EXCESSIVE_CAPS_CHECK) "
                    "to avoid false matches from normal title-case words.",
     "pattern": "EXCESSIVE_CAPS_CHECK"},

    {"rule_id": "LING_002", "name": "Multiple consecutive exclamation marks",
     "category": "linguistic_analysis", "weight": 0.5, "is_enabled": True, "is_custom": False,
     "description": "Three or more exclamation marks in a row (!!!) are characteristic "
                    "of low-quality phishing. Weight VERY LOW — alone this means nothing.",
     "pattern": r"!{3,}"},

    {"rule_id": "LING_003", "name": "Unicode invisible character obfuscation",
     "category": "linguistic_analysis", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "Zero-width spaces (U+200B–200F) or BOM (U+FEFF) are inserted between "
                    "characters to break up keywords and evade text-based spam filters.",
     "pattern": "[​‌‍‎‏﻿]"},

    {"rule_id": "LING_004", "name": "Repeated urgency phrases",
     "category": "linguistic_analysis", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "The same urgency word appears multiple times — an extreme pressure tactic.",
     "pattern": r"(urgent.{0,100}urgent|immediately.{0,100}immediately|verify.{0,100}verify)"},

    {"rule_id": "LING_005", "name": "Broken English grammar pattern",
     "category": "linguistic_analysis", "weight": 1.0, "is_enabled": True, "is_custom": False,
     "description": "Common broken-English phrases associated with phishing emails from "
                    "non-native English speakers impersonating Western institutions.",
     "pattern": r"\b(kindly do the needful|revert back to us|do the needful|"
                r"your good self|at the earliest possible|with immediate effect)\b"},
]
