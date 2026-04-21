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

BLACKLIST_FILE = "blacklist.json"
LOG_FILE       = "logs.txt"

# Email config from .env
SENDER_EMAIL    = os.getenv("SENDER_EMAIL", "")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD", "")
ALERT_EMAIL     = os.getenv("ALERT_EMAIL", "")

# Track which IPs we already emailed about (resets on restart — fine for demo)
alerted_ips = set()

# ── HELPERS ──────────────────────────────────────────────────────────────────

def load_blacklist():
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    return []

def save_to_blacklist(ip):
    blacklist = load_blacklist()
    if ip not in blacklist:
        blacklist.append(ip)
        with open(BLACKLIST_FILE, "w") as f:
            json.dump(blacklist, f, indent=2)

def get_threat_level(count):
    if count < 3:  return "LOW"
    if count < 6:  return "MEDIUM"
    if count < 10: return "HIGH"
    return "CRITICAL"

# ── EMAIL ALERT ───────────────────────────────────────────────────────────────

def send_alert_email(ip, attack_type, attempts, threat_level):
    api_key = os.environ.get("SENDGRID_API_KEY")
    sender = os.environ.get("SENDER_EMAIL")
    recipient = os.environ.get("ALERT_EMAIL")
    if not api_key or not sender or not recipient:
        print("[EMAIL] Skipped — SendGrid credentials not set")
        return
    if ip in alerted_ips:
        return
    alerted_ips.add(ip)

    now = datetime.now().strftime("%d-%b-%Y at %I:%M:%S %p")
    subject = f"🔴 CRITICAL THREAT DETECTED — {attack_type} | Sentinel-X"

    html_body = f"""
    <div style="font-family: 'Courier New', monospace; background: #020408; color: #cdd6f4;
                max-width: 600px; margin: 0 auto; border: 1px solid #00e5ff33; border-radius: 4px;">
      <div style="background: #060c14; padding: 24px 32px; border-bottom: 1px solid #00e5ff22;">
        <div style="color: #00e5ff; font-size: 20px; font-weight: bold; letter-spacing: 6px;">SENTINEL-X</div>
        <div style="color: #3a4a60; font-size: 11px; letter-spacing: 2px; margin-top: 4px;">E-COMMERCE THREAT MONITORING SYSTEM</div>
      </div>
      <div style="background: #ff2d5511; border-bottom: 1px solid #ff2d5522; padding: 12px 32px; color: #ff2d55; font-size: 12px; letter-spacing: 3px;">
        ⚠ AUTOMATED SECURITY ALERT — IMMEDIATE ATTENTION REQUIRED
      </div>
      <div style="padding: 32px;">
        <table style="width:100%; border-collapse: collapse;">
          <tr><td style="padding: 10px 0; color: #3a4a60; font-size: 11px; letter-spacing: 2px; width: 140px;">THREAT LEVEL</td><td style="padding: 10px 0; color: #ff2d55; font-weight: bold; font-size: 16px;">● {threat_level}</td></tr>
          <tr style="border-top: 1px solid #0a1520;"><td style="padding: 10px 0; color: #3a4a60; font-size: 11px; letter-spacing: 2px;">ATTACK TYPE</td><td style="padding: 10px 0; color: #cdd6f4;">{attack_type}</td></tr>
          <tr style="border-top: 1px solid #0a1520;"><td style="padding: 10px 0; color: #3a4a60; font-size: 11px; letter-spacing: 2px;">IP ADDRESS</td><td style="padding: 10px 0; color: #00e5ff;">{ip}</td></tr>
          <tr style="border-top: 1px solid #0a1520;"><td style="padding: 10px 0; color: #3a4a60; font-size: 11px; letter-spacing: 2px;">ATTEMPTS</td><td style="padding: 10px 0; color: #ff9f1c;">{attempts} attempts detected</td></tr>
          <tr style="border-top: 1px solid #0a1520;"><td style="padding: 10px 0; color: #3a4a60; font-size: 11px; letter-spacing: 2px;">DETECTED AT</td><td style="padding: 10px 0; color: #cdd6f4;">{now}</td></tr>
          <tr style="border-top: 1px solid #0a1520;"><td style="padding: 10px 0; color: #3a4a60; font-size: 11px; letter-spacing: 2px;">ACTION TAKEN</td><td style="padding: 10px 0; color: #00ff88;">✅ IP Auto-Banned from blacklist</td></tr>
        </table>
      </div>
      <div style="background: #060c14; padding: 16px 32px; border-top: 1px solid #0a1520; color: #3a4a60; font-size: 10px;">
        This is an automated alert from Sentinel-X Security Monitoring. Do not reply to this email.
      </div>
    </div>
    """

    try:
        import urllib.request, json
        body = json.dumps({
            "personalizations": [{"to": [{"email": recipient}]}],
            "from": {"email": sender, "name": "Sentinel-X Security"},
            "subject": subject,
            "content": [{"type": "text/html", "value": html_body}]
        }).encode()
        req = urllib.request.Request(
            "https://api.sendgrid.com/v3/mail/send",
            data=body,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        )
        urllib.request.urlopen(req)
        print(f"[EMAIL] Alert sent → {recipient}")
    except Exception as e:
        print(f"[EMAIL] Failed: {e}")

# ── ATTACK SIGNATURES ─────────────────────────────────────────────────────────

ATTACK_PATTERNS = {
    "SQL Injection":       r"('|\"|\b)(OR|AND)\s+\d+=\d+|SELECT\s+\*|UNION\s+SELECT|DROP\s+TABLE|--|;--|/\*",
    "XSS Attack":          r"<script[\s\S]*?>|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie",
    "Directory Traversal": r"\.\./|\.\.\\|%2e%2e|/etc/passwd|/etc/shadow",
    "Command Injection":   r";\s*(ls|cat|rm|wget|curl|bash|sh|nc|python|perl)\b|\|\s*(ls|cat|bash)",
    "Brute Force":         r"LOGIN_FAIL",
    "Credential Stuffing": r"CRED_STUFF|credential.stuff",
    "Port Scan":           r"PORT_SCAN|port.scan",
}

CRITICAL_ATTACKS = {"SQL Injection", "XSS Attack", "Directory Traversal", "Command Injection"}

SEVERITY_ORDER = [
    "Command Injection", "SQL Injection", "XSS Attack",
    "Directory Traversal", "Credential Stuffing", "Port Scan", "Brute Force"
]

# ── ROUTES ────────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/stats")
def stats():
    blacklist     = load_blacklist()
    fail_count    = 0
    success_count = 0
    ip_data       = {}
    honeypot_hits = 0

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                if "HONEYPOT" in line or "fake-admin" in line:
                    honeypot_hits += 1
                    continue

                if "LOGIN_SUCCESS" in line:
                    success_count += 1
                    continue

                is_attack = "LOGIN_FAIL" in line or any(
                    re.search(p, line, re.IGNORECASE)
                    for p in ATTACK_PATTERNS.values()
                )

                if not is_attack:
                    continue

                fail_count += 1

                # Extract IP
                ip = None
                m = re.search(r"ip=([0-9]{1,3}(?:\.[0-9]{1,3}){3})", line)
                if m:
                    ip = m.group(1)
                else:
                    m2 = re.search(r"\b([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b", line)
                    if m2:
                        ip = m2.group(1)

                if not ip:
                    continue

                if ip not in ip_data:
                    ip_data[ip] = {
                        "attempts":   0,
                        "type":       "Brute Force",
                        "threat":     "LOW",
                        "first_seen": datetime.now().strftime("%H:%M:%S"),
                    }

                ip_data[ip]["attempts"] += 1
                ip_data[ip]["threat"]    = get_threat_level(ip_data[ip]["attempts"])

                for attack_name in SEVERITY_ORDER:
                    if re.search(ATTACK_PATTERNS[attack_name], line, re.IGNORECASE):
                        ip_data[ip]["type"] = attack_name
                        if attack_name in CRITICAL_ATTACKS:
                            ip_data[ip]["threat"] = "CRITICAL"
                            save_to_blacklist(ip)
                            # 🔔 Send email alert for critical threats
                            send_alert_email(
                                ip, attack_name,
                                ip_data[ip]["attempts"], "CRITICAL"
                            )
                        break

    for ip in ip_data:
        ip_data[ip]["banned"] = ip in blacklist

    return jsonify({
        "total_success":  success_count,
        "total_fails":    fail_count,
        "banned_count":   len(blacklist),
        "blacklist":      blacklist,
        "suspicious_ips": ip_data,
        "honeypot_hits":  honeypot_hits,
        "health_score":   max(0, 100 - (fail_count * 2)),
    })


@app.route("/block-ip", methods=["POST"])
def block_ip():
    data = request.get_json()
    ip   = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "No IP provided"}), 400
    save_to_blacklist(ip)
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now().isoformat()} MANUAL_BLOCK ip={ip}\n")
    return jsonify({"status": "blocked", "ip": ip})


@app.route("/unblock-ip", methods=["POST"])
def unblock_ip():
    data      = request.get_json()
    ip        = data.get("ip", "").strip()
    blacklist = load_blacklist()
    if ip in blacklist:
        blacklist.remove(ip)
        with open(BLACKLIST_FILE, "w") as f:
            json.dump(blacklist, f, indent=2)
    alerted_ips.discard(ip)
    return jsonify({"status": "unblocked", "ip": ip})


@app.route("/simulate", methods=["POST"])
def simulate():
    data = request.get_json()
    line = data.get("line", "").strip()
    if not line:
        return jsonify({"error": "Empty payload"}), 400
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")
    return jsonify({"ok": True, "logged": line})


@app.route("/honeypot", methods=["GET", "POST"])
def honeypot():
    client_ip = request.remote_addr
    ts = datetime.now().isoformat()
    with open(LOG_FILE, "a") as f:
        f.write(f"{ts} HONEYPOT triggered ip={client_ip} path=/honeypot\n")
    return "<html><body><h2>Admin Login</h2></body></html>", 200


@app.route("/blacklist")
def get_blacklist():
    return jsonify({"blacklist": load_blacklist()})


@app.route("/test-email")
def test_email():
    """Route to test email setup — visit /test-email in browser."""
    send_alert_email("1.2.3.4", "SQL Injection", 14, "CRITICAL")
    return jsonify({"status": "Email sent! Check your inbox.", "to": ALERT_EMAIL})




# ── STARTUP ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            f.write("")
        print("✅ Created logs.txt")

    if not os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, "w") as f:
            json.dump([], f)
        print("✅ Created blacklist.json")

    port = int(os.environ.get("PORT", 5000))
    print(f"🛡  SENTINEL-X running → http://127.0.0.1:{port}")
    app.run(debug=False, host="0.0.0.0", port=port)