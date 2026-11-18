# -*- coding: utf-8 -*-
"""
IGYR Central Security Operations Centre (SOC) - Dedicated Standalone Server
Completely isolated from the main website server.
Hosted on an independent server/port/Render service.
Credentials:
  ID: igyr
  Password: cutiee
"""

import os
import sys
import time
import json
import secrets
import shutil
import platform
from collections import deque
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, make_response, redirect
from flask_cors import CORS
from pymongo import MongoClient
import urllib.request
import urllib.error

# Telemetry
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None
    PSUTIL_AVAILABLE = False

# Application Setup
app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

# Credentials & Configuration
SOC_USER = os.environ.get("SOC_USER", "igyr")
SOC_PASSWORD = os.environ.get("SOC_PASSWORD", "cutiee")
SOC_SECRET_KEY = os.environ.get("SOC_SECRET_KEY", secrets.token_hex(32))
MAIN_SERVER_URL = os.environ.get("MAIN_SERVER_URL", "https://igyr-india-get-your-result.onrender.com").rstrip('/')

# Connect to MongoDB cluster
MONGO_URI = os.environ.get("MONGO_URI", "mongodb+srv://auradispatch2026_db_user:611LdmEjTS7WeqKW@cluster0.z9xcllt.mongodb.net/?appName=Cluster0")

try:
    client = MongoClient(MONGO_URI)
    db = client['igyr_database']
    soc_control_col = db['soc_control']
    soc_logs_col = db['soc_security_logs']
    soc_firewall_col = db['soc_ip_firewall']
    print("✅ SOC Server connected to MongoDB cluster.")
except Exception as e:
    db = None
    soc_control_col = None
    soc_logs_col = None
    soc_firewall_col = None
    print("⚠️ SOC Server running in detached mode:", e)

SERVER_START_TIME = time.time()
active_sessions = set()
recent_security_logs = deque(maxlen=500)

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-SOC-Token') or request.cookies.get('soc_token')
        if not token:
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header.split('Bearer ', 1)[1].strip()

        if not token or token not in active_sessions:
            return jsonify({
                "success": False,
                "error": "UNAUTHORIZED",
                "message": "Valid SOC session required. Please log in."
            }), 401
        return f(*args, **kwargs)
    return decorated

def get_website_control_doc():
    if soc_control_col is not None:
        try:
            doc = soc_control_col.find_one({"id": "system_state"})
            if doc:
                return doc
        except Exception:
            pass
    return {
        "website_active": True,
        "maintenance_title": "Scheduled Platform Maintenance",
        "maintenance_message": "India Get Your Result (IGYR) is undergoing scheduled system updates and security enhancements. Normal operations will resume shortly.",
        "estimated_restoration": "In progress (Checking real-time)",
        "updated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    }

def collect_telemetry():
    now = time.time()
    uptime_sec = int(now - SERVER_START_TIME)
    days, rem = divmod(uptime_sec, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)
    uptime_str = f"{days}d {hours}h {minutes}m {seconds}s" if days > 0 else f"{hours}h {minutes}m {seconds}s"

    cpu_percent = 0.0
    mem_used_mb = 0
    mem_total_mb = 0
    mem_percent = 0.0

    if PSUTIL_AVAILABLE:
        try:
            cpu_percent = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            mem_total_mb = round(mem.total / (1024 * 1024), 1)
            mem_used_mb = round(mem.used / (1024 * 1024), 1)
            mem_percent = mem.percent
        except Exception:
            pass

    # MongoDB status & latency ping
    db_status = "Disconnected"
    db_latency_ms = -1
    collections_count = 0
    if db is not None:
        try:
            t0 = time.time()
            db.command('ping')
            db_latency_ms = round((time.time() - t0) * 1000, 2)
            db_status = "Connected"
            collections_count = len(db.list_collection_names())
        except Exception as e:
            db_status = f"Degraded ({str(e)[:25]})"

    # Main platform live ping
    main_site_ping = "Unknown"
    try:
        req = urllib.request.Request(f"{MAIN_SERVER_URL}/health", headers={'User-Agent': 'IGYR-SOC-Monitor/1.0'})
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status == 200:
                main_site_ping = "Online (200 OK)"
            else:
                main_site_ping = f"Status {resp.status}"
    except Exception as ping_err:
        main_site_ping = "Unreachable / Maintenance"

    return {
        "status": "healthy" if db_status == "Connected" else "degraded",
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "uptime_str": uptime_str,
        "uptime_seconds": uptime_sec,
        "cpu_percent": cpu_percent,
        "memory": {
            "total_mb": mem_total_mb,
            "used_mb": mem_used_mb,
            "percent": mem_percent
        },
        "database": {
            "status": db_status,
            "latency_ms": db_latency_ms,
            "collections_count": collections_count
        },
        "main_server": {
            "url": MAIN_SERVER_URL,
            "status": main_site_ping
        },
        "environment": {
            "python_version": platform.python_version(),
            "os": f"{platform.system()} {platform.release()}",
            "pid": os.getpid(),
            "render_service": os.environ.get("RENDER_SERVICE_NAME", "SOC-Standalone-Node")
        }
    }


# ==========================================
# ROUTES
# ==========================================

@app.route('/')
@app.route('/soc')
@app.route('/soc/')
def serve_soc_dashboard():
    """Serves the SOC Security Operations Centre Dashboard Web Page."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(base_dir, 'dashboard.html')
    if os.path.isfile(file_path):
        return send_from_directory(base_dir, 'dashboard.html')
    return jsonify({"error": "dashboard.html not found in SOC directory"}), 404

@app.route('/health')
@app.route('/soc/health')
@app.route('/api/health')
def health_probe():
    control = get_website_control_doc()
    return jsonify({
        "status": "healthy",
        "service": "IGYR Security Operations Centre (SOC)",
        "role": "cybersecurity_and_system_command",
        "website_master_switch": "ONLINE" if bool(control.get("website_active", True)) else "MAINTENANCE",
        "database": "Connected" if db is not None else "Local / Disconnected",
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    }), 200

@app.route('/api/login', methods=['POST'])
@app.route('/soc/api/login', methods=['POST'])
def login():
    """Authenticates SOC Operator using ID (igyr) and Password (cutiee)."""
    data = request.json or {}
    user_id = str(data.get('id', '')).strip()
    password = str(data.get('password', '')).strip()

    if user_id == SOC_USER and password == SOC_PASSWORD:
        token = secrets.token_hex(24)
        active_sessions.add(token)

        resp = jsonify({
            "success": True,
            "token": token,
            "user": user_id,
            "message": "Access granted to IGYR Security Operations Centre."
        })
        resp.set_cookie('soc_token', token, max_age=86400, httponly=False, samesite='Lax')
        return resp

    return jsonify({
        "success": False,
        "error": "INVALID_CREDENTIALS",
        "message": "Invalid SOC ID or Security Password. Access Denied."
    }), 401

@app.route('/api/logout', methods=['POST'])
@app.route('/soc/api/logout', methods=['POST'])
@require_auth
def logout():
    token = request.headers.get('X-SOC-Token') or request.cookies.get('soc_token')
    if token in active_sessions:
        active_sessions.remove(token)
    resp = jsonify({"success": True, "message": "Logged out successfully."})
    resp.delete_cookie('soc_token')
    return resp

@app.route('/api/status', methods=['GET'])
@app.route('/soc/api/status', methods=['GET'])
def get_public_status():
    doc = get_website_control_doc()
    return jsonify({
        "website_active": bool(doc.get("website_active", True)),
        "maintenance_title": doc.get("maintenance_title", "Scheduled Platform Maintenance"),
        "maintenance_message": doc.get("maintenance_message", "Under maintenance"),
        "estimated_restoration": doc.get("estimated_restoration", "In progress"),
        "server_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    })

@app.route('/api/overview', methods=['GET'])
@app.route('/soc/api/overview', methods=['GET'])
@require_auth
def get_overview():
    control_doc = get_website_control_doc()
    telemetry = collect_telemetry()

    banned_count = 0
    threats_count = 0
    if soc_firewall_col is not None:
        try:
            banned_count = soc_firewall_col.count_documents({})
        except Exception:
            pass
    if soc_logs_col is not None:
        try:
            threats_count = soc_logs_col.count_documents({"blocked": True})
        except Exception:
            pass

    return jsonify({
        "success": True,
        "website_control": {
            "website_active": bool(control_doc.get("website_active", True)),
            "maintenance_title": control_doc.get("maintenance_title", "Scheduled Platform Maintenance"),
            "maintenance_message": control_doc.get("maintenance_message", ""),
            "estimated_restoration": control_doc.get("estimated_restoration", ""),
            "updated_at": control_doc.get("updated_at", "")
        },
        "health": telemetry,
        "security": {
            "banned_ips_count": banned_count,
            "threats_blocked_total": threats_count
        }
    })

@app.route('/api/toggle-website', methods=['POST'])
@app.route('/soc/api/toggle-website', methods=['POST'])
@require_auth
def toggle_website():
    """Toggles main website traffic ON/OFF via MongoDB."""
    data = request.json or {}
    current = get_website_control_doc()
    current_state = bool(current.get("website_active", True))

    if "enabled" in data:
        new_status = bool(data["enabled"])
    else:
        new_status = not current_state

    if soc_control_col is not None:
        try:
            soc_control_col.update_one(
                {"id": "system_state"},
                {"$set": {
                    "website_active": new_status,
                    "updated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "updated_by": SOC_USER
                }},
                upsert=True
            )
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    # Log action
    if soc_logs_col is not None:
        try:
            soc_logs_col.insert_one({
                "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "epoch": int(time.time()),
                "ip": request.remote_addr,
                "threat_type": "WEBSITE_TOGGLE",
                "severity": "HIGH",
                "details": f"Main website toggled to {'ONLINE' if new_status else 'MAINTENANCE (OFF)'}",
                "path": "/api/toggle-website",
                "method": "POST",
                "user_agent": "SOC Dashboard",
                "blocked": False
            })
        except Exception:
            pass

    return jsonify({
        "success": True,
        "website_active": new_status,
        "status_label": "ONLINE" if new_status else "MAINTENANCE",
        "message": f"Website is now {'ONLINE (Public access active)' if new_status else 'OFFLINE (Under Maintenance)'}."
    })

@app.route('/api/set-maintenance-info', methods=['POST'])
@app.route('/soc/api/set-maintenance-info', methods=['POST'])
@require_auth
def update_maintenance_notice():
    data = request.json or {}
    title = data.get('title', 'Scheduled Platform Maintenance').strip()
    msg = data.get('message', '').strip()
    est = data.get('estimated_restoration', 'Estimated: 15-30 Minutes').strip()

    if soc_control_col is not None:
        try:
            soc_control_col.update_one(
                {"id": "system_state"},
                {"$set": {
                    "maintenance_title": title,
                    "maintenance_message": msg,
                    "estimated_restoration": est,
                    "updated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
                }},
                upsert=True
            )
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    return jsonify({"success": True, "message": "Notice updated successfully."})

@app.route('/api/security/logs', methods=['GET'])
@app.route('/soc/api/security/logs', methods=['GET'])
@require_auth
def get_security_logs():
    limit = min(int(request.args.get('limit', 100)), 500)
    logs = []
    if soc_logs_col is not None:
        try:
            logs = list(soc_logs_col.find({}, {"_id": 0}).sort("epoch", -1).limit(limit))
        except Exception:
            pass
    return jsonify({"success": True, "logs": logs})

@app.route('/api/security/clear-logs', methods=['POST'])
@app.route('/soc/api/security/clear-logs', methods=['POST'])
@require_auth
def clear_security_logs():
    if soc_logs_col is not None:
        try:
            soc_logs_col.delete_many({})
        except Exception:
            pass
    return jsonify({"success": True, "message": "Logs cleared."})

@app.route('/api/security/firewall', methods=['GET'])
@app.route('/soc/api/security/firewall', methods=['GET'])
@require_auth
def get_firewall():
    banned = []
    if soc_firewall_col is not None:
        try:
            banned = list(soc_firewall_col.find({}, {"_id": 0}).sort("epoch", -1))
        except Exception:
            pass
    return jsonify({"success": True, "banned_ips": banned})

@app.route('/api/security/firewall/ban', methods=['POST'])
@app.route('/soc/api/security/firewall/ban', methods=['POST'])
@require_auth
def ban_ip():
    data = request.json or {}
    ip = str(data.get('ip', '')).strip()
    reason = str(data.get('reason', 'Quarantined by SOC')).strip()
    if not ip:
        return jsonify({"success": False, "error": "IP is required"}), 400

    if soc_firewall_col is not None:
        try:
            soc_firewall_col.update_one(
                {"ip": ip},
                {"$set": {
                    "ip": ip,
                    "reason": reason,
                    "banned_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "epoch": int(time.time())
                }},
                upsert=True
            )
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    return jsonify({"success": True, "message": f"IP {ip} quarantined successfully."})

@app.route('/api/security/firewall/unban', methods=['POST'])
@app.route('/soc/api/security/firewall/unban', methods=['POST'])
@require_auth
def unban_ip():
    data = request.json or {}
    ip = str(data.get('ip', '')).strip()
    if not ip:
        return jsonify({"success": False, "error": "IP is required"}), 400

    if soc_firewall_col is not None:
        try:
            soc_firewall_col.delete_one({"ip": ip})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    return jsonify({"success": True, "message": f"IP {ip} unbanned."})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5006))
    print(f"🛡️ Independent SOC Server running on http://0.0.0.0:{port}/")
    app.run(host='0.0.0.0', port=port, debug=False)
