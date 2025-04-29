# Cybersecurity Coding Project – Phishing URL Detector (Phase 3 with Scoring System + Flask Web App + Real API Check)
# This version adds a web interface using Flask and checks reputation using the IPQualityScore API
# Renamed to app.py


 import re
import requests
from urllib.parse import urlparse
import whois
import datetime
import os
from flask import Flask, request, render_template

app = Flask(__name__)

IPQS_API_KEY = os.getenv("IPQS_API_KEY")  # Read API key from environment variable

SUSPICIOUS_TLDS = ['.win', '.top', '.xyz', '.click', '.link', '.club', '.info', '.icu']
KNOWN_BRANDS = ['ezpass', 'paypal', 'amazon', 'bankofamerica', 'chase', 'dhl']

def check_ipqs(url):
    response = requests.get(
        f"https://ipqualityscore.com/api/json/url/{IPQS_API_KEY}/{url}"
    )
    if response.ok:
        data = response.json()
        if data.get('unsafe'):
            return "Phishing Detected (IPQualityScore)"
    return None

def check_domain_age(url):
    try:
        domain = urlparse(url).netloc
        info = whois.whois(domain)
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if not creation_date:
            return None
        age_days = (datetime.datetime.now() - creation_date).days
        if age_days < 90:
            return "Suspicious: Domain is newly registered"
    except:
        return "Unable to verify domain age"
    return None

def check_suspicious_tld(url):
    parsed = urlparse(url)
    for tld in SUSPICIOUS_TLDS:
        if parsed.netloc.endswith(tld):
            return f"Suspicious TLD detected: {tld}"
    return None

def check_brand_mimic(url):
    domain = urlparse(url).netloc.lower()
    for brand in KNOWN_BRANDS:
        if brand in domain and not domain.startswith(brand):
            return f"Possible brand impersonation: {brand}"
    return None

def overall_check(url):
    reasons = []

    for check_func in [check_ipqs, check_domain_age, check_suspicious_tld, check_brand_mimic]:
        result = check_func(url)
        if result:
            reasons.append(result)

    if not reasons:
        return "Safe", []
    else:
        return "Suspicious / Phishing", reasons

@app.route("/", methods=["GET", "POST"])
def home():
    status = None
    details = []
    if request.method == "POST":
        url = request.form["url"]
        status, details = overall_check(url)
    return render_template("index.html", status=status, details=details)

if __name__ == "__main__":
    app.run(debug=True)


