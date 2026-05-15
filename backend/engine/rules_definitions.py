"""
backend/engine/rules_definitions.py
=====================================
Complete detection rule seed data for PhishGuard v2.

DESIGN PHILOSOPHY:
  Every rule here is an ISOLATED signal — one pattern, one evidence type.
  Rules are NOT decisions. They are EVIDENCE.
  The CORRELATION ENGINE (scoring) turns corroborated evidence into decisions.

  A single "urgent" keyword should never classify email as phishing.
  BUT: urgent + credential request + suspicious URL + free-email sender = phishing.

RULE WEIGHT GUIDE:
  3.0  = Near-certain phishing indicator (IP as URL, .exe attachment, script tag)
  2.5  = Very strong indicator (@ in URL, typosquatting, gift card request)
  2.0  = Strong indicator (URL shortener, urgency language, missing DKIM)
  1.5  = Moderate indicator (free email sender, excessive caps, suspicious TLD)
  1.0  = Weak indicator (generic greeting, off-hours send, missing Message-ID)
  0.5  = Very weak / only relevant in combination (exclamation marks)

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
    # CATEGORY 1: URL ANALYSIS
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
     "pattern": r"https?://(bit\.ly|tinyurl\.com|goo\.gl|ow\.ly|t\.co|buff\.ly|is\.gd|rb\.gy|short\.link)/"},

    {"rule_id": "URL_003", "name": "High-abuse TLD in URL",
     "category": "url_analysis", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "The URL uses a top-level domain with extremely high phishing abuse rates.",
     "pattern": r"https?://[^\s/]+\.(xyz|top|click|tk|ml|ga|cf|gq|pw|loan|win|bid|download|work)(/|$)"},

    {"rule_id": "URL_004", "name": "Brand name in subdomain of unrelated domain",
     "category": "url_analysis", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "A well-known brand appears as a subdomain of an unrelated domain. "
                    "e.g. paypal.evil-site.com — the real domain is evil-site.com.",
     "pattern": r"https?://(paypal|amazon|google|microsoft|apple|facebook|netflix|crdb|nmb|equity)\.[a-z0-9\-]+\.[a-z]{2,}/"},

    {"rule_id": "URL_005", "name": "Excessively long URL (>120 chars)",
     "category": "url_analysis", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "URLs longer than 120 characters obscure the real destination and "
                    "are a common characteristic of phishing redirectors.",
     "pattern": r"https?://\S{121,}"},

    {"rule_id": "URL_006", "name": "Redirect chain in URL parameters",
     "category": "url_analysis", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "An embedded URL parameter (url=, redirect=, next=) indicates a redirect "
                    "chain used to bypass URL-based link scanners.",
     "pattern": r"[?&](url|redirect|next|goto|target|link|return_url)=https?://"},

    {"rule_id": "URL_007", "name": "@ symbol in URL (destination masking)",
     "category": "url_analysis", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "An @ symbol in a URL causes browsers to ignore everything before it. "
                    "http://legitimate.com@evil.com/phish goes to evil.com.",
     "pattern": r"https?://[^\s@]+@[^\s@]+"},

    {"rule_id": "URL_008", "name": "Too many subdomains (≥4 levels)",
     "category": "url_analysis", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "Excessive subdomains (e.g. secure.login.verify.bank.evil.com) simulate "
                    "legitimate-looking URL structure while routing to a malicious domain.",
     "pattern": r"https?://([a-zA-Z0-9\-]+\.){4,}[a-zA-Z]{2,}"},

    {"rule_id": "URL_009", "name": "Hexadecimal IP address in URL",
     "category": "url_analysis", "weight": 3.0, "is_enabled": True, "is_custom": False,
     "description": "A hexadecimal representation of an IP address is used to evade IP-based "
                    "detection filters. e.g. http://0xC0A80001 = http://192.168.0.1",
     "pattern": r"https?://0x[a-fA-F0-9]{2,}"},

    {"rule_id": "URL_010", "name": "Heavy percent-encoding in URL",
     "category": "url_analysis", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "Five or more consecutive percent-encoded characters indicates obfuscation "
                    "of a malicious URL to hide it from content scanners.",
     "pattern": r"(%[0-9A-Fa-f]{2}){5,}"},

    {"rule_id": "URL_011", "name": "Punycode domain (homograph attack)",
     "category": "url_analysis", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "xn-- punycode encoding is used to disguise characters from other "
                    "alphabets as ASCII, making a fake domain look identical to a real one.",
     "pattern": r"xn--[a-z0-9\-]+"},

    {"rule_id": "URL_012", "name": "Auth/session parameters in URL",
     "category": "url_analysis", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "Authentication-related parameters (token=, session=, auth=) pointing "
                    "to another URL are used to steal session credentials via redirect.",
     "pattern": r"[?&](token|session|auth|credential)=https?"},

    {"rule_id": "URL_013", "name": "Data URI in HTML (embedded page)",
     "category": "url_analysis", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "A data:text/html;base64 URI embeds an entire HTML page inline, "
                    "completely bypassing URL-based phishing filters.",
     "pattern": r"data:text/html;base64"},

    {"rule_id": "URL_014", "name": "JavaScript URI scheme",
     "category": "url_analysis", "weight": 3.0, "is_enabled": True, "is_custom": False,
     "description": "A javascript: URI executes code when clicked. This is never legitimate "
                    "in an email link and indicates code injection.",
     "pattern": r"javascript\s*:"},

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 2: CONTENT & KEYWORDS
    # ═══════════════════════════════════════════════════════════════════

    {"rule_id": "KW_001", "name": "Urgency and threat language",
     "category": "content_keyword", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "Urgency or threat language ('URGENT', 'account suspended', 'verify now') "
                    "is used to pressure the recipient into acting without thinking. "
                    "Weight MODERATE — many legitimate automated emails (password expiry, "
                    "overdue invoices) also use urgency language.",
     "pattern": r"\b(urgent|immediately|account.{0,10}(suspended|closed|blocked|locked|terminated)|"
                r"verify.{0,10}(now|immediately)|limited.{0,5}time|act.{0,5}now|"
                r"deadline.{0,10}(today|tomorrow)|final.{0,5}notice|last.{0,5}(chance|warning))\b"},

    # Separate rule for short-window time pressure — common in phishing document-sharing,
    # credential-reset, and invoice-fraud lures.  Uses a PLAIN PATTERN (no trailing \b)
    # because the match ends mid-word ("expir" inside "expires"), which breaks word-boundary.
    {"rule_id": "URGENCY_002", "name": "Short time-window access pressure",
     "category": "content_keyword", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "A link or access window that expires within hours or minutes creates "
                    "panic pressure to act before thinking. Legitimate notifications use "
                    "days-long windows; phishing/scam emails use 1–24 hours.",
     "pattern": r"expir\w+\s+in\s+\d+\s*(?:hour|minute|min)s?\b|link\s+expir\w*"},

    {"rule_id": "KW_002", "name": "Explicit credential harvesting",
     "category": "content_keyword", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "The email explicitly requests sensitive credentials: PIN, password, SSN, "
                    "CVV, OTP. Legitimate organisations NEVER ask for these via email. "
                    "This is one of the strongest phishing content signals.",
     "pattern": r"\b(enter.{0,15}(pin|password|passcode)|provide.{0,15}(pin|password|ssn)|"
                r"confirm.{0,15}(pin|password)|your.{0,10}pin.{0,10}(is|below)|"
                r"\bcvv\b|one.time.password|security.code.{0,10}(is|below|:))\b"},

    {"rule_id": "KW_003", "name": "Prize / lottery / inheritance lure",
     "category": "content_keyword", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "Prize, lottery or unexpected inheritance claims are used in advance-fee "
                    "fraud. Nobody wins a lottery they did not enter.",
     "pattern": r"\b(you.{0,10}(won|have won|are a winner)|lottery.{0,10}(winner|prize|fund)|"
                r"inheritance.{0,10}(claim|fund|million)|unclaimed.{0,10}(fund|prize)|jackpot)\b"},

    {"rule_id": "KW_004", "name": "Unsolicited wire transfer / financial request",
     "category": "content_keyword", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "Wire transfer or payment requests out of context indicate BEC (Business "
                    "Email Compromise). Legitimate invoices are expected; unexpected ones are not.",
     "pattern": r"\b(wire.{0,5}transfer|send.{0,10}(money|funds|payment)|transfer.{0,10}(funds|amount)|"
                r"western.{0,5}union|moneygram)\b"},

    {"rule_id": "KW_005", "name": "Generic impersonal greeting",
     "category": "content_keyword", "weight": 0.8, "is_enabled": True, "is_custom": False,
     "description": "A generic greeting ('Dear Customer', 'Dear User') indicates a mass "
                    "phishing campaign that cannot personalise. Weight kept LOW because "
                    "many legitimate bulk emails also use generic greetings.",
     "pattern": r"^.{0,50}\bDear\s+(Customer|User|Account.Holder|Valued.Client|Member|Subscriber|Sir/Madam)\b"},

    {"rule_id": "KW_006", "name": "Authority impersonation (government/tax)",
     "category": "content_keyword", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "The email impersonates a government or tax authority. IRS, FBI, "
                    "TRA (Tanzania), customs, police threats are classic phishing tactics.",
     "pattern": r"\b(internal.revenue.service|irs\b|fbi\b|interpol|court.order|legal.action|"
                r"subpoena|arrest.warrant|tanzania.revenue|tra.refund|customs.officer)\b"},

    {"rule_id": "SOC_001", "name": "Fear-based threat language",
     "category": "content_keyword", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "Explicit threats of arrest, lawsuit, account breach, or termination "
                    "are designed to create panic and override rational thinking.",
     "pattern": r"\b(will.be.arrested|face.legal.action|breach.of.account|account.breached|"
                r"immediately.terminated|criminal.charges|law.enforcement.will)\b"},

    {"rule_id": "SOC_002", "name": "Secrecy / confidentiality demand",
     "category": "content_keyword", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "Requests for secrecy prevent the victim from verifying the request "
                    "with colleagues or IT — a classic BEC social engineering tactic.",
     "pattern": r"\b(keep.{0,10}(confidential|secret|private)|do.not.tell|do.not.discuss|"
                r"between.us.only|do.not.forward)\b"},

    {"rule_id": "SOC_003", "name": "Gift card payment demand",
     "category": "content_keyword", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "Gift card payment requests are exclusively used in scams. "
                    "No legitimate organisation ever accepts payment via iTunes/Steam/Google Play cards.",
     "pattern": r"\b(gift.card|itunes.card|steam.card|google.play.card|amazon.gift.card|"
                r"buy.{0,10}gift.card|gift.card.code)\b"},

    {"rule_id": "SOC_004", "name": "Cryptocurrency payment request",
     "category": "content_keyword", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "Cryptocurrency payment demands via email are a hallmark of ransomware "
                    "and extortion scams. Legitimate payroll and billing never uses crypto.",
     "pattern": r"\b(bitcoin.address|send.{0,10}bitcoin|ethereum.wallet|usdt.address|"
                r"crypto.wallet.address|pay.{0,10}in.bitcoin)\b"},

    {"rule_id": "SOC_005", "name": "Fake work-from-home / easy money offer",
     "category": "content_keyword", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "Unsolicited work-from-home or easy income offers recruit money mules "
                    "or harvest personal/banking credentials.",
     "pattern": r"\b(work.from.home.{0,20}(earn|income|salary)|easy.{0,10}income|"
                r"no.experience.needed.{0,20}earn|earn.{0,15}per.week.{0,20}from.home)\b"},

    {"rule_id": "SOC_006", "name": "Credential verification pressure",
     "category": "content_keyword", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "Pressure to re-verify or re-enter credentials immediately. "
                    "Legitimate password resets are initiated by the USER, not sent unsolicited.",
     "pattern": r"\b(re.?verify.{0,15}account|confirm.{0,10}your.{0,10}(login|credentials|password)|"
                r"update.{0,15}banking.details|confirm.{0,10}bank.{0,10}details)\b"},

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 3: SENDER VERIFICATION
    # ═══════════════════════════════════════════════════════════════════

    {"rule_id": "SND_001", "name": "Display name brand mismatch with domain",
     "category": "sender_verification", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "The sender display name contains a well-known brand but the actual "
                    "email domain is unrelated. e.g. PayPal <support@random-site.com>. "
                    "This is spoofing — evaluated programmatically.",
     "pattern": "DISPLAY_DOMAIN_MISMATCH"},

    {"rule_id": "SND_002", "name": "Free email provider for official context",
     "category": "sender_verification", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "A free consumer email provider (Gmail, Yahoo, Hotmail) is used by a "
                    "sender claiming to be a bank, government, or corporation. "
                    "Weight is MODERATE because small businesses legitimately use Gmail.",
     "pattern": r"@(gmail|yahoo|hotmail|outlook|live|aol|icloud|protonmail|yandex)\.(com|co\.tz|net|org)"},

    {"rule_id": "SND_003", "name": "Typosquatting / lookalike domain",
     "category": "sender_verification", "weight": 3.0, "is_enabled": True, "is_custom": False,
     "description": "The sender domain is visually similar to a known brand domain with "
                    "subtle character substitutions (paypa1.com, arnazon.com, crdb-bank.com). "
                    "Evaluated with edit-distance algorithm — strongest sender signal.",
     "pattern": "TYPOSQUATTING_CHECK"},

    {"rule_id": "SND_004", "name": "Reply-To domain differs from From domain",
     "category": "sender_verification", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "Reply-To points to a different domain than From. This routes all "
                    "victim replies to an attacker-controlled inbox while From looks legitimate.",
     "pattern": "REPLY_TO_MISMATCH"},

    {"rule_id": "SND_005", "name": "Randomised local-part in sender address",
     "category": "sender_verification", "weight": 0.5, "is_enabled": True, "is_custom": False,
     "description": "The sender's local-part (before @) is a long purely-alphanumeric string "
                    "with no separators, which can indicate automated phishing infrastructure. "
                    "Weight is VERY LOW (0.5) because many legitimate systems (notification bots, "
                    "automated alerts) also use long alphanumeric local parts. "
                    "This rule should never classify an email alone — it is a supporting signal only.",
     "pattern": r"^[a-z0-9]{14,}@"},

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 4: HEADER AUTHENTICATION
    # ═══════════════════════════════════════════════════════════════════

    # {"rule_id": "HDR_001", "name": "SPF authentication failure",
    #  "category": "header_authentication", "weight": 2.5, "is_enabled": True, "is_custom": False,
    #  "description": "Received-SPF header shows FAIL or SOFTFAIL — the sending server is "
    #                 "NOT authorised to send email for this domain. Strong phishing signal.",
    #  "pattern": r"Received-SPF:\s*(fail|softfail)\b"},

    # {"rule_id": "HDR_002", "name": "DKIM signature absent",
    #  "category": "header_authentication", "weight": 1.5, "is_enabled": True, "is_custom": False,
    #  "description": "No DKIM-Signature header is present. All major legitimate mail providers "
    #                 "sign outgoing email. Weight MODERATE (not HIGH) because many small "
    #                 "mail servers and self-hosted setups do not configure DKIM.",
    #  "pattern": "DKIM_MISSING_OR_FAIL"},

    {"rule_id": "HDR_003", "name": "DMARC policy fail in auth-results",
     "category": "header_authentication", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "Authentication-Results header shows dmarc=fail. The email failed "
                    "DMARC policy alignment, indicating likely spoofing.",
     "pattern": "DMARC_NOT_ENFORCED"},

    {"rule_id": "HDR_004", "name": "Known spam/bulk mail tool in X-Mailer",
     "category": "header_authentication", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "The X-Mailer header identifies a bulk or spam mailing tool.",
     "pattern": r"X-Mailer:\s*(PHPMailer|Mass.Mailer|Bulk.Mail|DreamMail|SendBlaster|Gammadyne)"},

    {"rule_id": "HDR_005", "name": "Missing Message-ID header",
     "category": "header_authentication", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "All legitimate mail servers inject a unique Message-ID. Absence "
                    "indicates a manually crafted or spam-tool-generated email.",
     "pattern": "MISSING_MESSAGE_ID"},

    {"rule_id": "HDR_006", "name": "Malformed Message-ID",
     "category": "header_authentication", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "Message-ID header is not properly formatted (should be <unique@domain>). "
                    "Malformed IDs indicate a low-quality phishing tool.",
     "pattern": r"Message-ID:\s*[^<\s]"},

    {"rule_id": "HDR_007", "name": "X-Priority set to Highest (1)",
     "category": "header_authentication", "weight": 1.0, "is_enabled": True, "is_custom": False,
     "description": "X-Priority: 1 (Highest) artificially elevates urgency perception.",
     "pattern": r"X-Priority:\s*1\b"},

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 5: HTML OBFUSCATION
    # ═══════════════════════════════════════════════════════════════════

    {"rule_id": "HTML_001", "name": "Visible link text domain differs from href",
     "category": "html_obfuscation", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "An anchor tag shows one domain as visible text but the href "
                    "points to a completely different domain. Classic visual deception.",
     "pattern": "LINK_TEXT_HREF_MISMATCH"},

    {"rule_id": "HTML_002", "name": "HTML entity obfuscation of keywords",
     "category": "html_obfuscation", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "4+ consecutive HTML entities (&#NNN;) encode text to evade keyword filters. "
                    "e.g. &#112;&#97;&#115;&#115;&#119;&#111;&#114;&#100; = password",
     "pattern": r"(&#\d{2,4};){4,}"},

    {"rule_id": "HTML_003", "name": "Hidden/invisible text in HTML",
     "category": "html_obfuscation", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "display:none, visibility:hidden, or white-text-on-white-background "
                    "hides content from human viewers but may deceive spam filters into "
                    "seeing benign invisible content.",
     "pattern": r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0)"},

    {"rule_id": "HTML_004", "name": "Excessive inline CSS (>20 style attributes)",
     "category": "html_obfuscation", "weight": 1.0, "is_enabled": True, "is_custom": False,
     "description": "Auto-generated phishing kit HTML typically contains dense inline styling.",
     "pattern": "HTML_INLINE_STYLE_DENSITY"},

    {"rule_id": "HTML_005", "name": "Script tag in email body",
     "category": "html_obfuscation", "weight": 3.0, "is_enabled": True, "is_custom": False,
     "description": "A <script> tag in email HTML is blocked by all modern email clients "
                    "but indicates a malicious phishing kit attempting code execution.",
     "pattern": r"<\s*script[\s>]"},

    {"rule_id": "HTML_006", "name": "Iframe in email body",
     "category": "html_obfuscation", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "An <iframe> loads an external phishing page invisibly inside the email. "
                    "Legitimate HTML emails never use iframes.",
     "pattern": r"<\s*iframe[\s>]"},

    {"rule_id": "HTML_007", "name": "Meta-refresh redirect",
     "category": "html_obfuscation", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "A meta http-equiv=refresh auto-redirects after a short delay, "
                    "sending the reader to a phishing page before they can react.",
     "pattern": r"http-equiv\s*=\s*['\"]refresh"},

    {"rule_id": "HTML_008", "name": "Base64-encoded images",
     "category": "html_obfuscation", "weight": 1.0, "is_enabled": True, "is_custom": False,
     "description": "Base64 inline images are used to evade image-hosting-based spam scanners. "
                    "Weight LOW because legitimate HTML emails also use inline images.",
     "pattern": r"data:image/[a-z]{2,5};base64"},

    {"rule_id": "HTML_009", "name": "Large obfuscating HTML comments",
     "category": "html_obfuscation", "weight": 1.0, "is_enabled": True, "is_custom": False,
     "description": "HTML comment blocks longer than 200 characters pad content "
                    "to confuse statistical Bayesian spam filters.",
     "pattern": r"<!--.{200,}-->"},

    {"rule_id": "HTML_010", "name": "External form submission (credential harvesting)",
     "category": "html_obfuscation", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "An HTML form with action= pointing to an external URL "
                    "harvests credentials typed by the victim.",
     "pattern": r"<form[^>]+action\s*=\s*['\"]https?://"},

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 6: BEHAVIORAL (ATTACHMENTS + TIMING + TRACKING)
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
     "description": "invoice.pdf.exe disguises a malicious executable as a harmless "
                    "document. The OS hides the final extension by default.",
     "pattern": r"\.(pdf|doc|jpg|png|txt)\.(exe|scr|js|bat|cmd|vbs)"},

    {"rule_id": "BEH_004", "name": "ISO / IMG disk image attachment",
     "category": "behavioral", "weight": 2.5, "is_enabled": True, "is_custom": False,
     "description": "ISO disk images bypass email attachment scanners because most "
                    "do not inspect ISO contents. Used to deliver malware.",
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
     "description": "Email sent between midnight and 5AM UTC. Phishing automation "
                    "often runs at off-hours. Weight LOW — timezone differences make "
                    "this weak alone but relevant in combination.",
     "pattern": "SENDING_HOUR_CHECK"},

    {"rule_id": "BEH_009", "name": "Multiple external tracking images (3+ domains)",
     "category": "behavioral", "weight": 1.0, "is_enabled": True, "is_custom": False,
     "description": "Images from 3+ distinct external domains are used as tracking pixels.",
     "pattern": "EXTERNAL_IMAGE_COUNT"},

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 7: LINGUISTIC ANALYSIS
    # ═══════════════════════════════════════════════════════════════════

    # IMPORTANT: LING_001 uses a PROGRAMMATIC handler ("EXCESSIVE_CAPS_CHECK"),
    # NOT a regex pattern.  The rule engine compiles all regex patterns with
    # re.IGNORECASE, which makes [A-Z]{5,} match any 5-letter word (including
    # lowercase ones like "Customer", "prepared", "attached").  The programmatic
    # handler in rule_engine.py uses re.findall WITHOUT IGNORECASE so it
    # correctly detects only genuinely uppercase words like URGENT, SUSPENDED.
    {"rule_id": "LING_001", "name": "Excessive ALL-CAPS words",
     "category": "linguistic_analysis", "weight": 0.8, "is_enabled": True, "is_custom": False,
     "description": "Three or more ALL-CAPS words (5+ letters each) indicate "
                    "aggressive social engineering pressure (e.g. URGENT ACCOUNT SUSPENDED). "
                    "Evaluated by a case-sensitive programmatic handler to avoid "
                    "false matches from normal title-case words.",
     "pattern": "EXCESSIVE_CAPS_CHECK"},

    {"rule_id": "LING_002", "name": "Multiple consecutive exclamation marks",
     "category": "linguistic_analysis", "weight": 0.5, "is_enabled": True, "is_custom": False,
     "description": "Three or more exclamation marks in a row (!!!) are characteristic "
                    "of low-quality phishing. Weight VERY LOW — alone this means nothing.",
     "pattern": r"!{3,}"},

    {"rule_id": "LING_003", "name": "Unicode invisible character obfuscation",
     "category": "linguistic_analysis", "weight": 2.0, "is_enabled": True, "is_custom": False,
     "description": "Zero-width spaces (U+200B–200F) or BOM (U+FEFF) are inserted between "
                    "characters to break up keywords and evade text-based spam filters. "
                    "This is deliberate obfuscation and rarely appears in legitimate email.",
     "pattern": "[\u200B\u200C\u200D\u200E\u200F\uFEFF]"},

    {"rule_id": "LING_004", "name": "Repeated urgency phrases",
     "category": "linguistic_analysis", "weight": 1.5, "is_enabled": True, "is_custom": False,
     "description": "The same urgency word appears multiple times in the same email, "
                    "an extreme pressure tactic targeting less tech-savvy recipients.",
     "pattern": r"(urgent.{0,100}urgent|immediately.{0,100}immediately|verify.{0,100}verify)"},

    {"rule_id": "LING_005", "name": "Broken English grammar pattern",
     "category": "linguistic_analysis", "weight": 1.0, "is_enabled": True, "is_custom": False,
     "description": "Common broken-English phrases associated with phishing emails from "
                    "non-native English speakers.",
     "pattern": r"\b(kindly do the needful|revert back to us|do the needful|"
                r"your good self|at the earliest possible)\b"},
]
