from flask import Flask, jsonify, request, render_template
import re
import json
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "alert@sentinel-x.com")
ALERT_EMAIL = os.environ.get("ALERT_EMAIL", "")

alerted_ips = set()

BLACKLIST_FILE = "blacklist.json"

def load_blacklist():
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, "r") as f:
            return json.load(f)
    return []

def save_blacklist(blacklist):
    with open(BLACKLIST_FILE, "w") as f:
        json.dump(blacklist, f)

blacklisted_ips = load_blacklist()

THREAT_PATTERNS = {
    "SQL Injection": [
        r"(?i)(union\s+select|drop\s+table|insert\s+into|delete\s+from|select\s+\*)",
        r"(?i)('|\"|;|--|\b(or|and)\b\s+\d+=\d+)",
    ],
    "XSS Attack": [
        r"(?i)(<script|javascript:|onerror=|onload=|alert\s*\()",
    ],
    "Path Traversal": [
        r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.%2e/|%2e\./)",
    ],
    "Command Injection": [
        r"(?i)(;|\||&&|\$\(|`)\s*(ls|cat|rm|wget|curl|bash|sh|python|perl|nc)\b",
    ],
    "Brute Force": [
        r"(?i)(password=|passwd=|pwd=).{0,20}(admin|root|123|test|pass)",
    ],
}

request_counts = {}

def detect_threats(ip, path, payload):
    threats = []
    full_text = f"{path} {payload}"

    for threat_name, patterns in THREAT_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, full_text):
                threats.append(threat_name)
                break

    return threats

def send_alert_email(ip, threat_type, count, severity):
    if not SENDGRID_API_KEY or not ALERT_EMAIL:
        print("[EMAIL] Skipped — missing API key or recipient email")
        return

    recipient = ALERT_EMAIL
    recipients = [{"email": e.strip()} for e in recipient.split(",")]

    subject = f"🚨 Sentinel-X Alert: {threat_type} from {ip}"
    body = f"""
    <h2>⚠️ Security Alert from Sentinel-X</h2>
    <p><b>Threat Type:</b> {threat_type}</p>
    <p><b>Source IP:</b> {ip}</p>
    <p><b>Severity:</b> {severity}</p>
    <p><b>Request Count:</b> {count}</p>
    <p><b>Time:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
    <br>
    <p>Login to your Sentinel-X dashboard for more details.</p>
    """

    import urllib.request
    import urllib.error

    data = json.dumps({
        "personalizations": [{"to": recipients}],
        "from": {"email": SENDER_EMAIL},
        "subject": subject,
        "content": [{"type": "text/html", "value": body}]
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.sendgrid.com/v3/mail/send",
        data=data,
        headers={
            "Authorization": f"Bearer {SENDGRID_API_KEY}",
            "Content-Type": "application/json"
        },
        method="POST"
    )

    try:
        urllib.request.urlopen(req)
        print(f"[EMAIL] Alert sent to: {ALERT_EMAIL}")
    except urllib.error.HTTPError as e:
        print(f"[EMAIL] Failed: {e.code} {e.read().decode()}")
    except Exception as e:
        print(f"[EMAIL] Error: {e}")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    ip = data.get("ip", "unknown")
    path = data.get("path", "/")
    payload = data.get("payload", "")

    if ip in blacklisted_ips:
        return jsonify({"status": "blocked", "ip": ip, "reason": "Blacklisted IP"})

    threats = detect_threats(ip, path, payload)

    if ip not in request_counts:
        request_counts[ip] = 0
    request_counts[ip] += 1

    count = request_counts[ip]
    severity = "LOW"

    if count >= 20:
        severity = "CRITICAL"
    elif count >= 10:
        severity = "HIGH"
    elif count >= 5:
        severity = "MEDIUM"

    if threats and ip not in alerted_ips:
        alerted_ips.add(ip)
        send_alert_email(ip, threats[0], count, severity)

    return jsonify({
        "status": "analyzed",
        "ip": ip,
        "threats": threats,
        "request_count": count,
        "severity": severity
    })


@app.route("/blacklist", methods=["POST"])
def blacklist():
    data = request.get_json()
    ip = data.get("ip")
    if ip and ip not in blacklisted_ips:
        blacklisted_ips.append(ip)
        save_blacklist(blacklisted_ips)
        return jsonify({"status": "blacklisted", "ip": ip})
    return jsonify({"status": "already blacklisted or invalid", "ip": ip})


@app.route("/blacklist", methods=["GET"])
def get_blacklist():
    return jsonify({"blacklisted_ips": blacklisted_ips})


@app.route("/stats", methods=["GET"])
def stats():
    return jsonify({
        "total_ips_tracked": len(request_counts),
        "alerted_ips": list(alerted_ips),
        "blacklisted_ips": blacklisted_ips,
        "request_counts": request_counts
    })


@app.route("/test-email")
def test_email():
    alerted_ips.clear()  # ✅ FIX: clears so test always fires
    send_alert_email("1.2.3.4", "SQL Injection", 14, "CRITICAL")
    return jsonify({"status": "Email sent! Check your inbox.", "to": ALERT_EMAIL})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)