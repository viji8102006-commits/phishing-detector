"""
Phishing Detection System (URL & Email Analysis) — Flask backend
Task 04: Analyzes URLs and email text for phishing indicators and
classifies input as SAFE or SUSPICIOUS with detailed reasoning.
"""

import re
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# -----------------------------------------------------------------------
# Indicator libraries
# -----------------------------------------------------------------------

PHISHING_KEYWORDS = [
    "verify your account", "confirm your identity", "update your information",
    "click here immediately", "your account has been suspended",
    "unusual activity", "unauthorized access", "limited time offer",
    "act now", "urgent action required", "your account will be closed",
    "bank account", "social security", "credit card number",
    "enter your password", "reset your password immediately",
    "won a prize", "you have been selected", "free gift",
    "click the link below", "login to verify", "validate your account",
    "account verification required", "security alert",
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
    ".loan", ".work", ".date", ".faith", ".review", ".stream",
    ".download", ".win", ".accountant",
]

LEGITIMATE_DOMAINS = {
    "google.com", "gmail.com", "youtube.com", "microsoft.com",
    "outlook.com", "apple.com", "icloud.com", "amazon.com",
    "paypal.com", "facebook.com", "instagram.com", "twitter.com",
    "x.com", "linkedin.com", "github.com", "wikipedia.org",
    "netflix.com", "spotify.com", "adobe.com", "dropbox.com",
}

# Brands commonly impersonated in phishing
BRAND_NAMES = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "facebook", "instagram", "whatsapp", "dhl", "fedex", "ups",
    "bank of america", "chase", "wells fargo", "citibank", "hsbc",
]

# -----------------------------------------------------------------------
# URL analysis
# -----------------------------------------------------------------------

def analyze_url(url: str) -> dict:
    flags = []
    score = 0

    # Ensure parseable
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full = url.lower()
    except Exception:
        return {"score": 10, "flags": ["Could not parse the URL."], "verdict": "suspicious"}

    # 1. HTTP instead of HTTPS
    if parsed.scheme == "http":
        flags.append("Uses HTTP (not HTTPS) — connection is not encrypted.")
        score += 2

    # 2. IP address instead of domain name
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}", domain):
        flags.append("URL uses a raw IP address instead of a domain name — common in phishing.")
        score += 4

    # 3. Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            flags.append(f"Uses a high-risk top-level domain ({tld}).")
            score += 3
            break

    # 4. Excessive subdomains (e.g. paypal.secure.login.evil.com)
    parts = domain.split(".")
    if len(parts) > 4:
        flags.append(f"Unusually many subdomains ({len(parts) - 2}) — may be hiding the real domain.")
        score += 2

    # 5. Brand name in subdomain but not in root domain
    root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
    for brand in BRAND_NAMES:
        if brand in subdomain and brand not in root_domain and brand + "." not in root_domain:
            flags.append(f"Brand name '{brand}' appears in subdomain but NOT in the actual domain — classic impersonation trick.")
            score += 5
            break

    # 6. Legitimate domain check
    if root_domain in LEGITIMATE_DOMAINS and score == 0:
        flags.append(f"Domain '{root_domain}' is a known legitimate domain.")
        score = max(score - 2, 0)

    # 7. URL length
    if len(url) > 100:
        flags.append(f"URL is unusually long ({len(url)} characters) — long URLs are often used to obscure the real destination.")
        score += 1

    # 8. Suspicious words in path / query
    suspicious_path_words = ["login", "signin", "verify", "secure", "account", "update", "confirm", "password", "banking"]
    found = [w for w in suspicious_path_words if w in path or w in parsed.query.lower()]
    if found:
        flags.append(f"Suspicious words in URL path: {', '.join(found)}.")
        score += 2

    # 9. Multiple redirects hinted by URL
    if full.count("http") > 1:
        flags.append("URL contains multiple 'http' occurrences — may be a redirect chain to hide destination.")
        score += 3

    # 10. Hyphen overuse in domain
    if domain.count("-") >= 3:
        flags.append(f"Domain contains many hyphens ({domain.count('-')}) — often seen in fake domains (e.g. secure-paypal-login.com).")
        score += 2

    if not flags:
        flags.append("No obvious phishing indicators detected in this URL.")

    verdict = "suspicious" if score >= 4 else "safe"
    return {"score": score, "flags": flags, "verdict": verdict}


# -----------------------------------------------------------------------
# Email analysis
# -----------------------------------------------------------------------

def analyze_email(text: str) -> dict:
    flags = []
    score = 0
    lower = text.lower()

    # 1. Phishing keyword phrases
    found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in lower]
    if found_keywords:
        flags.append(f"Contains {len(found_keywords)} phishing phrase(s): \"{found_keywords[0]}\"" +
                     (f" and {len(found_keywords)-1} more." if len(found_keywords) > 1 else "."))
        score += min(len(found_keywords) * 2, 8)

    # 2. Urgency language
    urgency_words = ["immediately", "urgent", "asap", "right now", "today only",
                     "expires", "limited time", "final notice", "last chance"]
    found_urgency = [w for w in urgency_words if w in lower]
    if found_urgency:
        flags.append(f"Uses urgency language: {', '.join(found_urgency[:3])} — pressure tactics are a social engineering technique.")
        score += 2

    # 3. Requests sensitive info
    sensitive = ["password", "social security", "ssn", "credit card", "bank account",
                 "pin number", "mother's maiden name", "date of birth", "passport"]
    found_sensitive = [s for s in sensitive if s in lower]
    if found_sensitive:
        flags.append(f"Requests sensitive information: {', '.join(found_sensitive[:3])}. Legitimate organizations never ask for these via email.")
        score += 4

    # 4. Suspicious links embedded
    urls_in_text = re.findall(r'https?://\S+', text)
    if urls_in_text:
        for u in urls_in_text[:3]:
            url_result = analyze_url(u)
            if url_result["verdict"] == "suspicious":
                flags.append(f"Contains a suspicious link: {u[:60]}{'...' if len(u)>60 else ''}")
                score += 3
                break

    # 5. Mismatched sender hint (e.g. "From: PayPal" but domain not paypal)
    from_match = re.search(r'from[:\s]+(.+)', lower)
    if from_match:
        from_line = from_match.group(1)
        for brand in BRAND_NAMES:
            if brand in from_line:
                domain_in_from = re.search(r'@([\w.-]+)', from_line)
                if domain_in_from:
                    sender_domain = domain_in_from.group(1)
                    if brand not in sender_domain:
                        flags.append(f"Sender claims to be '{brand}' but email domain is '{sender_domain}' — likely spoofed sender.")
                        score += 5

    # 6. Generic greeting
    generic_greetings = ["dear customer", "dear user", "dear account holder",
                         "dear member", "hello user", "valued customer"]
    if any(g in lower for g in generic_greetings):
        flags.append("Uses a generic greeting (e.g. 'Dear Customer') instead of your name — mass phishing emails do this.")
        score += 1

    # 7. Spelling/grammar flags (simple heuristic)
    double_spaces = text.count("  ")
    if double_spaces > 3:
        flags.append("Unusually frequent double spaces — may indicate copy-paste from a foreign-language source.")
        score += 1

    if not flags:
        flags.append("No obvious phishing indicators detected in this email text.")

    verdict = "suspicious" if score >= 4 else "safe"
    return {"score": score, "flags": flags, "verdict": verdict}


# -----------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "url")        # "url" or "email"
    content = data.get("content", "").strip()

    if not content:
        return jsonify({"verdict": "safe", "score": 0, "flags": ["Nothing to analyze — enter a URL or email text."]})

    if mode == "url":
        result = analyze_url(content)
    else:
        result = analyze_email(content)

    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
