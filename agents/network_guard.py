import joblib
import psutil
import os
import time
import geoip2.database
from utils.network_features import extract_features
import warnings

warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=FutureWarning)

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'GeoLite2-City.mmdb')
HIGH_RISK_COUNTRIES = ["Russia", "China", "North Korea", "Iran","India","Unknown"]
SAFE_PORTS = [80, 443, 53, 8080]

ALLOWED_APPS = [
    "chrome.exe", "firefox.exe", "msedge.exe", "brave.exe", 
    "opera.exe", "spotify.exe", "Zoom.exe", "discord.exe", 
    "teams.exe", "slack.exe", "outlook.exe", "skype.exe", 
    "onedrive.exe", "dropbox.exe", "steam.exe", "epicgameslauncher.exe","StartMenuExperienceHost.exe"
]

RESTRICTED_TOOLS = [
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", 
    "notepad.exe", "calc.exe", "rundll32.exe", "regedit.exe"
]

CRITICAL_PROCESSES = [
    "svchost.exe", "System", "Registry", "smss.exe", "csrss.exe", 
    "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe", 
    "spoolsv.exe", "explorer.exe", "MsMpEng.exe", "taskhostw.exe","msedgewebview2.exe"
]

BLOCK_TRESHOLD = 70

process_start_times = {}


#************************* Static Analysis Functions *************************#

def get_country(ip_address):

    if ip_address.startswith(("192.168.", "10.", "127.", "172.16.")):
        return "Local"
    
    if not os.path.exists(DB_PATH):
        return "Unknown (DB Missing)"
    
    try:
        with geoip2.database.Reader(DB_PATH) as reader:
            response = reader.city(ip_address)
            return response.country.name
    except Exception:
        return "Unknown"
    

def get_process_category(proc_name):

    proc_name = proc_name.lower()

    if proc_name in [app.lower() for app in ALLOWED_APPS]:
        return "BROWSER"
    
    if proc_name in [tool.lower() for tool in RESTRICTED_TOOLS]:
        return "SYSTEM_TOOL"
    
    return "UNKNOWN_APP"


def check_traffic_anomalies(process):

    score = 0
    reasons = []

    try:
        io = process.io_counters()
        bytes_sent = io.write_bytes
        bytes_recv = io.read_bytes

        if bytes_sent > 5*1024*1024:
            if bytes_recv == 0 or (bytes_sent / bytes_recv > 10):
                score += 30
                reasons.append(f"High Upload Ratio (Exfiltration suspected): {bytes_sent/1024/1024:.2f}MB sent")

    except Exception:
        pass

    return score, reasons


def check_connection_duration(pid):

    score = 0
    reasons = []

    current_time = time.time()

    if pid not in process_start_times:
        process_start_times[pid] = current_time
        return score, reasons
    
    duration_mins = (current_time - process_start_times[pid]) / 60

    if duration_mins > 20:
        score += 20
        reasons.append(f"Long active connection ({int(duration_mins)}m) - possible C2 channel")

    return score, reasons


def calculate_connection_risk(proc_name, remote_port, country,traffic_score,traffic_reasons):

    score = 0
    reasons = []

    score += traffic_score
    reasons += traffic_reasons

    category = get_process_category(proc_name)

    if country in HIGH_RISK_COUNTRIES:
        score += 50
        reasons.append(f"Connection to high-risk country: {country}")
    elif country != "Local" and country != "Israel" and country != "United States":
        score += 10

    if category == "BROWSER":
        return 0, []

    if category == "SYSTEM_TOOL":
        if country != "Local":
            score += 80
            reasons.append(f"System tool '{proc_name}' connecting to internet")

    elif category == "UNKNOWN_APP":
        if country != "Local":
            score += 10

    if country == "Local":
        score -= 20

    if remote_port in SAFE_PORTS:
        score -= 10

    if remote_port not in SAFE_PORTS and country != "Local":
        score += 20
        reasons.append(f"Unusual destination port: {remote_port}")


        if remote_port in [4444,6667,1337,3389]:
            score += 30
            reasons.append(f"Blacklisted hacker port detected: {remote_port}")

    return score, reasons


#************************* Network Anomaly Detection Model *************************#
try:
    model = joblib.load("models/network_isolation_forest.pkl")
except Exception:
    model = None
    print(f"[NetworkGuard] Warning: Could not load network anomaly detection model from models/network_isolation_forest.pkl.")

def calc_model_score(process,conn):
    try:
        features = extract_features(process, conn)

        if features is None:
            return 0
        
        prediction = model.predict([features])[0]
        if prediction == -1:
            return 50  # Anomalous
        else:
            return 0   # Normal
        
    except Exception:
        return 10



def start_monitoring(alert_queue, stop_event):
    print("[NetworkGuard] Monitoring active connections with GeoIP...")

    if not os.path.exists(DB_PATH):
        alert_queue.put(("ERROR", f"[NetworkGuard] GeoIP DB not found at: {DB_PATH}\nGeo-blocking disabled."))

    reported_connections = set()

    while not stop_event.is_set():
        try:
            connections = psutil.net_connections(kind='inet')

            killed_pids_this_cycle = set()
            current_pids = set()

            for conn in connections:
                if conn.status not in ['ESTABLISHED', 'SYN_SENT']:
                    continue

                if not conn.raddr:
                    continue

                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                pid = conn.pid

                current_pids.add(pid)

                if pid in killed_pids_this_cycle:
                    continue

                conn_id = f"{pid}:{remote_ip}:{remote_port}"
                if conn_id in reported_connections:
                    continue

                try:
                    process = psutil.Process(pid)
                    proc_name = process.name()

                    traffic_score, traffic_reasons = check_traffic_anomalies(process)
                    duration_score, duration_reasons = check_connection_duration(pid)

                    total_traffic_score = traffic_score + duration_score
                    total_reasons = traffic_reasons + duration_reasons

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

                country = get_country(remote_ip)

                risk_score, reasons = calculate_connection_risk(proc_name, remote_port, country,total_traffic_score,total_reasons)

                model_score = calc_model_score(process, conn)
                risk_score += model_score
                reasons.append(f"Anomaly Detection Model Flaged Connection as Suspicious")

                if risk_score >= BLOCK_TRESHOLD:

                    if proc_name in CRITICAL_PROCESSES:
                        continue

                    msg = (f"NETWORK THREAT DETECTED!\n"
                           f"Process: {proc_name} (PID: {pid})\n"
                           f"Destination: {remote_ip} ({country})\n"
                           f"Port: {remote_port}\n"
                           f"Reasons: {', '.join(reasons)}")
                    
                    alert_queue.put(("THREAT", msg))

                    time.sleep(0.05)  # Small delay before taking action

                    try:
                        process.kill()
                        alert_queue.put(("INFO", f"AUTO-RESPONSE: Terminated {proc_name} to break connection."))
                        killed_pids_this_cycle.add(pid)
                    except:
                        alert_queue.put(("ERROR", f"RESPONSE FAILED: Could not kill {proc_name}"))

                    reported_connections.add(conn_id)

            for cached_pid in list(process_start_times.keys()):
                if cached_pid not in current_pids:
                    del process_start_times[cached_pid]

            if len(reported_connections) > 5000:
                reported_connections.clear()

            time.sleep(1)

        except Exception as e:
            print(f"[NetworkGuard] Error: {e}")
            time.sleep(1)
        
    