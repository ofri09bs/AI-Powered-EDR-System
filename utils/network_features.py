import psutil
import time
import os
import geoip2.database

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, 'data', 'GeoLite2-City.mmdb')

HIGH_RISK_COUNTRIES = ["Russia", "China", "North Korea", "Iran","India","Unknown"]

ALLOWED_APPS = [
    "chrome.exe", "firefox.exe", "msedge.exe", "brave.exe", 
    "opera.exe", "spotify.exe", "zoom.exe", "discord.exe", 
    "teams.exe", "slack.exe", "outlook.exe", "skype.exe", 
    "onedrive.exe", "dropbox.exe", "steam.exe", "epicgameslauncher.exe"
]


RESTRICTED_TOOLS = [
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", 
    "notepad.exe", "calc.exe", "rundll32.exe", "regedit.exe"
]

FEATURE_COLUMNS = [
    "RemotePort", "CountryRisk", "ProcType", "BytesRatio", 
    "Duration", "CPU", "SuspiciousParent", "ConnRate", 
    "NewPort", "SystemPath"
]

process_start_times = {}
process_port_history = {}
process_connection_times = {}

def get_country_risk(ip):
    if ip.startswith(("192.168.", "10.", "127.", "172.16.")):
        return 0  # Local IPs are safe

    if not os.path.exists(DB_PATH):
        return 3  # Unknown if DB is missing

    try:
        with geoip2.database.Reader(DB_PATH) as reader:
            response = reader.city(ip)
            country = response.country.name
            if country in HIGH_RISK_COUNTRIES:
                return 10  # High risk
            else:
                return 1  # Low risk
    except Exception:
        return 1  # Unknown on error
    

def get_process_type(proc_name):
    name = proc_name.lower()
    if name in ALLOWED_APPS:
        return 1  # Browser
    
    if name in RESTRICTED_TOOLS:
        return 5  # System tool
    
    return 3  # Unknown application


def get_behavioral_features(pid,proc_name,port):
    current_time = time.time()

    # Connection Rate (RPM)
    if pid not in process_start_times:
        process_connection_times[pid] = []

    process_connection_times[pid].append(current_time)
    process_connection_times[pid] = [t for t in process_connection_times[pid] if current_time - t <= 60]
    conn_rate = len(process_connection_times[pid])

    # New Port Usage
    is_new = 1
    if proc_name not in process_port_history:
        process_port_history[proc_name] = set()
    if port in process_port_history[proc_name]:
        is_new = 0
    
    else:
        process_port_history[proc_name].add(port)

    # Duration
    if pid not in process_start_times:
        process_start_times[pid] = current_time
        duration = 0
    else:
        duration = current_time - process_start_times[pid]

    return conn_rate, is_new, duration


def get_extended_info(process):
    try:
        # CPU Usage
        cpu = process.cpu_percent(interval=None)

        # Suspicious Parent Process
        try:
            ppid = process.ppid()
            parent = psutil.Process(ppid).name().lower()
            is_sus_parent = 1 if parent in RESTRICTED_TOOLS else 0
        except Exception:
            is_sus_parent = 0

        # System Path Check
        try:
            path = process.exe().lower()
            is_system_path = 1 if path.startswith(os.environ.get('WINDIR', 'C:\\Windows').lower()) else 0
        except Exception:
            is_system_path = 0

        return cpu, is_sus_parent, is_system_path
    
    except Exception:
        return 0, 0, 0
    

def extract_features(process,connection):
    try:

        pid = process.pid
        proc_name = process.name().lower()

        if not connection.raddr:
            return None
        
        remote_ip = connection.raddr.ip
        remote_port = connection.raddr.port

        # IO ratio
        try:
            io = process.io_counters()
            ratio = io.write_bytes / (io.read_bytes + 1)
        except Exception:
            ratio = 0

        country_risk = get_country_risk(remote_ip)
        proc_type = get_process_type(proc_name)
        conn_rate, is_new, duration = get_behavioral_features(pid,proc_name,remote_port)
        cpu, is_sus_parent, is_system_path = get_extended_info(process)

        features = [
            remote_port,
            country_risk,
            proc_type,
            ratio,
            duration,
            cpu,
            is_sus_parent,
            conn_rate,
            is_new,
            is_system_path
        ]
        return features
    
    except Exception:
        return None
