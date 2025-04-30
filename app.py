import re
import requests
from urllib.parse import urlparse
from flask import Flask, request, render_template

app = Flask(__name__)

IPQS_API_KEY = "j1Kn3vGWqMhjk60Wf7Sgs79GDTcpVvcl"
  # Replace with your real key

# List of suspicious top-level domains
SUSPICIOUS_TLDS = ['.win', '.tk', '.cn', '.gq', '.ml', '.cf', '.ga']

# Suspicious patterns often used in phishing
SUSPICIOUS_PATTERNS = ['login', 'secure', 'verify', 'update', 'billing', 'ezpass', 'paypal']

# Brand impersonation examples (expand this list based on targets)
KNOWN_BRANDS = ['ezpass', 'paypal', 'apple', 'amazon', 'microsoft', 'google']

def custom_phishing_rules(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()

    reasons = []

    # Rule 1: Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            reasons.append(f"Suspicious TLD: {tld}")

    # Rule 2: Brand impersonation (not exact match)
    for brand in KNOWN_BRANDS:
        if brand in domain and not domain.endswith(f"{brand}.com"):
            reasons.append(f"Potential brand impersonation: {brand}")

    # Rule 3: Hyphenated or numeric domains
    if re.search(r"\d", domain) or "-" in domain:
        reasons.append("Contains digits or hyphens (common in fake domains)")

    # Rule 4: Suspicious path words
    if any(keyword in parsed_url.path.lower() for keyword in SUSPICIOUS_PATTERNS):
        reasons.append("Suspicious keywords in URL path")

    return reasons

def check_with_ipqualityscore(url):
    api_url = f"https://ipqualityscore.com/api/json/url/{IPQS_API_KEY}/{url}"
    try:
        response = requests.get(api_url)
        data = response.json()
        return data
    except Exception as e:
        return {"success": False, "message": str(e)}

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    url = ""

    if request.method == 'POST':
        url = request.form['url'].strip()
        manual_flags = custom_phishing_rules(url)
        api_result = check_with_ipqualityscore(url)

        is_phishing = api_result.get("unsafe", False) or bool(manual_flags)

        result = {
            "input_url": url,
            "phishing_detected": is_phishing,
            "manual_reasons": manual_flags,
            "api_score": api_result.get("risk_score", "N/A"),
            "api_unsafe": api_result.get("unsafe", "N/A"),
            "api_domain": api_result.get("domain", "N/A")
        }

    return render_template('index.html', result=result)

if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)


