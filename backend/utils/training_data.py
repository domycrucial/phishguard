"""
============================================================
backend/utils/training_data.py
Training Mode Sample Email Dataset for PhishGuard.
Provides curated phishing and legitimate email samples for
the Training Mode feature. Used in the GET /api/training endpoint.
Includes Tanzanian-context examples for local relevance.
============================================================
"""

# TRAINING_EMAILS is a list of sample email dicts for educational use.
# Each entry contains:
#   - id:            Unique identifier for the sample
#   - title:         Short descriptive name for the training card
#   - expected_type: "phishing" | "legitimate"
#   - difficulty:    "easy" | "medium" | "hard"
#   - sender:        From: header value
#   - subject:       Subject line
#   - body_text:     Plain text body
#   - hint:          Teaching hint shown after submission (for learning)
#   - key_indicators: List of things to look for

TRAINING_EMAILS: list[dict] = [

    # ── PHISHING EXAMPLES ────────────────────────────────────────────────

    {
        "id":            "train_001",
        "title":         "Classic Bank Account Suspension",
        "expected_type": "phishing",
        "difficulty":    "easy",
        "sender":        "CRDB Bank Security <security@crdb-verify.xyz>",
        "subject":       "URGENT: Your CRDB account has been suspended",
        "body_text": (
            "Dear Customer,\n\n"
            "Your CRDB Bank account has been SUSPENDED due to suspicious activity. "
            "You must verify your account immediately or it will be permanently closed.\n\n"
            "Click here to verify: http://crdb-secure-login.tk/verify?token=abc123\n\n"
            "Please provide your:\n"
            "- Account number\n"
            "- PIN number\n"
            "- Date of birth\n\n"
            "You have 24 hours to act or your account will be deleted.\n\n"
            "CRDB Bank Security Team"
        ),
        "hint": (
            "Key red flags: (1) Suspicious TLD '.tk' — free domains used by phishers. "
            "(2) Bank domain mismatch — real CRDB emails come from @crdbbank.com. "
            "(3) Urgency language ('URGENT', 'immediately', '24 hours'). "
            "(4) Requesting PIN — banks NEVER ask for PINs via email. "
            "(5) Generic 'Dear Customer' greeting."
        ),
        "key_indicators": [
            "Sender domain '.xyz' doesn't match real CRDB domain",
            "Suspicious link uses '.tk' TLD",
            "Urgency language to pressure victim",
            "Requests PIN number (credential harvesting)",
            "Generic greeting without recipient name",
        ]
    },

    {
        "id":            "train_002",
        "title":         "Prize Winner Lottery Scam",
        "expected_type": "phishing",
        "difficulty":    "easy",
        "sender":        "International Lottery Foundation <winner@lottery-prize.ml>",
        "subject":       "CONGRATULATIONS! You have won $1,500,000",
        "body_text": (
            "Dear Winner,\n\n"
            "Congratulations! You have been selected as the winner of our "
            "International Online Lottery for this week. Your email address was "
            "randomly selected from 50,000 entries.\n\n"
            "Your prize: $1,500,000 USD (One Million Five Hundred Thousand US Dollars)\n\n"
            "To claim your prize, send the following:\n"
            "- Full name\n"
            "- Bank account number\n"
            "- Routing number\n"
            "- Copy of your national ID\n\n"
            "Contact our claims officer: agent@gmail.com\n"
            "This offer expires in 48 hours. Act now!\n\n"
            "Mr. James Williams\n"
            "International Lottery Foundation"
        ),
        "hint": (
            "This is a classic advance-fee fraud (419 scam). "
            "Indicators: (1) '.ml' TLD — free domain used by scammers. "
            "(2) Lottery you never entered. (3) Requests bank account details. "
            "(4) Uses @gmail.com for 'official' contact. "
            "(5) Urgency ('48 hours'). Real lotteries don't contact winners by random email."
        ),
        "key_indicators": [
            "Sender uses free .ml domain",
            "Claims you won a lottery you never entered",
            "Requests bank account and routing numbers",
            "Official contact is a Gmail address",
            "Prize/lottery keyword triggers",
        ]
    },

    {
        "id":            "train_003",
        "title":         "CEO Wire Transfer (BEC) Attack",
        "expected_type": "phishing",
        "difficulty":    "hard",
        "sender":        "Dr. Hassan Mwamba <hassan.mwamba@company-group.net>",
        "subject":       "Confidential - Urgent Wire Transfer Needed",
        "body_text": (
            "Hi Sarah,\n\n"
            "I need you to process an urgent wire transfer today. I'm in a meeting and "
            "can't talk. Please keep this confidential as it's for a sensitive acquisition.\n\n"
            "Transfer Details:\n"
            "Amount: $47,500\n"
            "Bank: First National Bank\n"
            "Account: 8834521987\n"
            "Routing: 021000021\n"
            "Reference: Acquisition-Q4\n\n"
            "Please confirm once done. Do NOT discuss this with anyone else.\n\n"
            "Dr. Hassan Mwamba\n"
            "CEO, Mwamba Group"
        ),
        "hint": (
            "This is a Business Email Compromise (BEC) attack — hard to detect because "
            "it avoids URLs and malware. Red flags: (1) Domain 'company-group.net' is NOT "
            "the real company domain. (2) Extreme secrecy ('keep confidential', 'don't discuss'). "
            "(3) Urgent financial request from CEO. (4) Sending hour may be unusual. "
            "Always verify wire transfers via phone using a known number, not from this email."
        ),
        "key_indicators": [
            "Sender domain doesn't match the real company",
            "Requests urgent wire transfer",
            "Instructs recipient to keep secret",
            "No links or attachments (pure social engineering)",
            "Financial/payment request keywords",
        ]
    },

    {
        "id":            "train_004",
        "title":         "Microsoft Password Expiry Phish",
        "expected_type": "phishing",
        "difficulty":    "medium",
        "sender":        "Microsoft Account Team <no-reply@microsoft-security.top>",
        "subject":       "Your password will expire in 24 hours",
        "body_text": (
            "Dear Microsoft User,\n\n"
            "Your Microsoft account password will expire in 24 hours. "
            "To keep your account active, please update your password immediately.\n\n"
            "Update Password: http://192.168.50.1/microsoft/reset?user=you@email.com\n\n"
            "If you do not update your password, your account will be permanently deactivated.\n\n"
            "Microsoft Account Team"
        ),
        "hint": (
            "Red flags: (1) Sender domain 'microsoft-security.top' — '.top' is suspicious TLD; "
            "real Microsoft emails come from @microsoft.com. (2) Link uses IP address instead of domain. "
            "(3) Brand name in sender domain that doesn't match Microsoft's real domain. "
            "(4) Generic 'Dear Microsoft User' greeting. (5) Urgency language."
        ),
        "key_indicators": [
            "Suspicious .top TLD in sender domain",
            "Link uses bare IP address (no domain)",
            "Brand name in non-matching domain (spoofing)",
            "Generic greeting",
            "Urgency language (24 hours)",
        ]
    },

    {
        "id":            "train_005",
        "title":         "Tanzania Revenue Authority Tax Refund Scam",
        "expected_type": "phishing",
        "difficulty":    "medium",
        "sender":        "Tanzania Revenue Authority <tra-refund@tanzara-online.ga>",
        "subject":       "Tax Refund Notification - TZS 450,000",
        "body_text": (
            "Dear Taxpayer,\n\n"
            "Our records show that you are eligible for a tax refund of TZS 450,000 "
            "from Tanzania Revenue Authority (TRA) for the fiscal year 2023/2024.\n\n"
            "To receive your refund, please click the link below and provide your "
            "bank account details:\n"
            "http://tra-tanzania.ga/refund-claim\n\n"
            "You must claim within 7 days or forfeit your refund.\n\n"
            "Tax Authority\n"
            "Tanzania Revenue Authority"
        ),
        "hint": (
            "This is a Tanzanian-context phishing attack. Red flags: "
            "(1) Domain '.ga' is a free domain commonly used by scammers. "
            "(2) Real TRA emails come from @tra.go.tz. "
            "(3) Tax authorities do NOT process refunds via email links. "
            "(4) Requests bank account details. (5) Urgency (7 days)."
        ),
        "key_indicators": [
            "Sender uses .ga domain (not tra.go.tz)",
            "Requests bank account details",
            "Tax authority impersonation",
            "Suspicious .ga TLD in link",
            "Urgency (7 days to claim)",
        ]
    },

    {
        "id":            "train_006",
        "title":         "Money Mule / Fake Job Offer",
        "expected_type": "phishing",
        "difficulty":    "medium",
        "sender":        "recruitment@jobs-africa-careers.com",
        "subject":       "Exciting Job Opportunity - Earn $5,000/month Working From Home",
        "body_text": (
            "Hello,\n\n"
            "We found your profile online and believe you are a great candidate "
            "for our data entry position. Earn $5,000 per month working from home, "
            "no experience required!\n\n"
            "Requirements:\n"
            "- Must have a bank account\n"
            "- Available 2 hours per day\n\n"
            "To apply, visit: http://bit.ly/afr-jobs-2024\n\n"
            "Reply to this email with your details.\n\n"
            "HR Department"
        ),
        "hint": (
            "This is a phishing / money mule recruitment email. "
            "Red flags: (1) URL shortener (bit.ly) hides the real phishing landing page. "
            "(2) Unrealistically high pay ($5,000/month) for 2 hours of work — classic lure. "
            "(3) Unsolicited job offer requesting bank account details. "
            "(4) No company name, phone number, or verifiable identity. "
            "The goal is to recruit money mules or harvest banking credentials."
        ),
        "key_indicators": [
            "URL shortener conceals phishing destination",
            "Unrealistic financial promise (lure)",
            "Requests bank account details",
            "No verifiable sender identity",
        ]
    },

    # ── LEGITIMATE EXAMPLES ──────────────────────────────────────────────

    {
        "id":            "train_007",
        "title":         "University Course Registration Confirmation",
        "expected_type": "legitimate",
        "difficulty":    "easy",
        "sender":        "registrar@udsm.ac.tz",
        "subject":       "Course Registration Confirmation - Semester 1 2024/2025",
        "body_text": (
            "Dear John Msangi,\n\n"
            "Your course registration for Semester 1, 2024/2025 academic year has been "
            "successfully processed. Below are your registered courses:\n\n"
            "1. CS 401 - Software Engineering (3 Credits)\n"
            "2. CS 405 - Database Systems (3 Credits)\n"
            "3. CS 412 - Computer Networks (3 Credits)\n\n"
            "Your student portal is available at: https://portal.udsm.ac.tz\n\n"
            "If you have any questions, contact the Registrar's Office:\n"
            "Email: registrar@udsm.ac.tz\n"
            "Phone: +255 22 241 0500\n\n"
            "Best regards,\n"
            "University of Dar es Salaam\n"
            "Registrar's Office"
        ),
        "hint": (
            "This is a legitimate email. Positive indicators: "
            "(1) Sender uses the official .ac.tz domain for a university. "
            "(2) Personalised greeting with student name. "
            "(3) Specific, accurate course information. "
            "(4) Link goes to the university's own domain. "
            "(5) Provides verifiable contact information. "
            "(6) No urgency, no credential requests."
        ),
        "key_indicators": [
            "Official .ac.tz domain matches institution",
            "Personalised with recipient's name",
            "No credential requests",
            "Links go to the same official domain",
            "Provides real contact information",
        ]
    },

    {
        "id":            "train_008",
        "title":         "NMB Bank Transaction Alert (Legitimate)",
        "expected_type": "legitimate",
        "difficulty":    "easy",
        "sender":        "alerts@nmbbank.co.tz",
        "subject":       "Transaction Alert: Debit of TZS 25,000 on your account",
        "body_text": (
            "Dear Amina Juma,\n\n"
            "A transaction has been processed on your account:\n\n"
            "Type:        Debit\n"
            "Amount:      TZS 25,000\n"
            "Description: AIRTEL MONEY TRANSFER\n"
            "Date/Time:   2024-11-15 14:32:05\n"
            "Balance:     TZS 342,150\n\n"
            "If you did not authorise this transaction, contact us immediately:\n"
            "- Call: 0800 750 002 (toll free)\n"
            "- Visit: https://www.nmbbank.co.tz\n"
            "- Branch: Your nearest NMB branch\n\n"
            "NMB Bank PLC\n"
            "This is an automated alert. Please do not reply to this email."
        ),
        "hint": (
            "This is a legitimate bank transaction alert. Positive signs: "
            "(1) Sender domain '@nmbbank.co.tz' matches the real NMB Bank Tanzania domain. "
            "(2) Personalised with customer name 'Amina Juma'. "
            "(3) Specific transaction details. "
            "(4) No links asking for credentials — only a link to the bank's own website. "
            "(5) Toll-free number provided for verification."
        ),
        "key_indicators": [
            "Official nmbbank.co.tz domain",
            "Personalised with account holder name",
            "Specific transaction details",
            "No credential requests",
            "Provides toll-free verification number",
        ]
    },
]
