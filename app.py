# Cybersecurity Coding Project – Phishing URL Detector (Phase 3 with Scoring System + Flask Web App + Real API Check)
# This version adds a web interface using Flask and checks reputation using the IPQualityScore API
# Renamed to app.py

import re
import requests
from urllib.parse import urlparse
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Replace with your actual API key from https://www.ipqualityscore.com/
IPQS_API_KEY = "j1Kn3vGWqMhjk60Wf7Sgs79GDTcpVvcl"

def is_ip_in_url(url):
    domain = urlparse(url).netloc
    return bool(re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", domain))

def has_suspicious_keywords(url):
    suspicious_keywords = ["login", "secure", "account", "update", "bank", "verify"]
    return any(keyword in url.lower() for keyword in suspicious_keywords)

def has_multiple_subdomains(url):
    domain = urlparse(url).netloc
    return domain.count('.') > 2

def check_ipqualityscore(url):
    try:
        response = requests.get(
            f"https://ipqualityscore.com/api/json/url/{IPQS_API_KEY}/{url}"
        )
        if response.status_code == 200:
            data = response.json()
            return data.get("suspicious", False)
    except:
        pass
    return False

def is_url_suspicious(url):
    checks = {
        "IP address in URL": is_ip_in_url(url),
        "Suspicious keywords": has_suspicious_keywords(url),
        "Too many subdomains": has_multiple_subdomains(url),
        "Listed on IPQualityScore": check_ipqualityscore(url),
    }
    return checks

def calculate_risk_score(results):
    score = sum(results.values())
    if score == 0:
        return "✅ Safe"
    elif score <= 2:
        return "⚠️ Suspicious"
    else:
        return "🔥 High Risk"

html_template = """
<!doctype html>
<html>
  <head>
    <title>Phishing URL Checker</title>
    <style>
      body { font-family: Arial; padding: 2em; background: #f4f4f4; }
      input[type=text] { width: 300px; padding: 8px; }
      button { padding: 8px 12px; }
      .result { margin-top: 1em; background: #fff; padding: 1em; border-radius: 5px; }
    </style>
  </head>
  <body>
    <h1>Phishing URL Checker</h1>
    <form method="post">
      <input type="text" name="url" placeholder="Enter a URL" required>
      <button type="submit">Check</button>
    </form>
    {% if results %}
    <div class="result">
      <h3>Results:</h3>
      <ul>
        {% for check, result in results.items() %}
          <li><strong>{{ check }}</strong>: {{ '⚠️ Yes' if result else '✅ No' }}</li>
        {% endfor %}
      </ul>
      <p><strong>Risk Level:</strong> {{ risk }}</p>
    </div>
    {% endif %}
  </body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    results = None
    risk = None
    if request.method == 'POST':
        url = request.form['url']
        results = is_url_suspicious(url)
        risk = calculate_risk_score(results)
    return render_template_string(html_template, results=results, risk=risk)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
