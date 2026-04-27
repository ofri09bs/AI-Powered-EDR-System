# 🛡️ AI-Powered Autonomous Defense System

![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![AI](https://img.shields.io/badge/AI-Scikit--Learn-orange) ![Status](https://img.shields.io/badge/Status-Active-brightgreen) ![Security](https://img.shields.io/badge/Security-Endpoint%20Protection-red)

This system is a comprehensive, Python-C-based **Endpoint Detection and Response (EDR)** solution. Unlike traditional antiviruses that rely solely on signatures, this system employs a **Hybrid Detection Engine** combining **static rules**, **behavioral analysis**, **honeypots**, **Machine Learning** and **Windows API** data collector to detect **zero-day** threats, **ransomware**, **phishing** and unauthorized users.

---

## Key Features

###  1. AI-Driven Network Threat Detection
* **Algorithm:** Unsupervised Learning using **Isolation Forest**.
* **Functionality:** Analyzes network flow vectors (Port, Bytes Sent/Received, Duration, Country Risk) in real-time.
* **Capability:** Detects **Zero-Day C2 (Command & Control)** channels, beaconing behavior, and slow-rate data exfiltration that bypass traditional signature-based firewalls.
* **Behavioral Rules:** Blocks unauthorized use of system binaries (`powershell.exe`, `cmd.exe`) for external connections.

###  2. ML-Powered Phishing Guard
* **Algorithm:** Supervised Learning using **Random Forest Classifier**.
* **Feature Engineering:** Extracts lexical features from URLs in the clipboard (Entropy, Length, Special Characters, TLD reputation).
* **Capability:** Predicts the probability of a URL being malicious, and detects **Typosquatting** and obfuscated phishing links before the user even pastes them.

###  3. User Guard: Behavioral Biometrics Engine
* **Algorithm:** Statistical Z-Score Analysis & Dynamic Profiling.
* **Detection Logic:** Continuously authenticates the user based on unique motor skills:
    * **Keystroke Dynamics:** Measures "Flight Time" (latency between keys) and "Dwell Time".
    * **Mouse Trajectory:** Analyzes velocity, acceleration, and angular movements.
* **Capability:** Instantly detects **Account Takeover** and physical intrusion. If the behavioral score drops below the threshold, the system initiates a **Hard Lock**.

###  4. Ransomware Guard 
* **Detection Logic:** Honey-pots deployment & File Integrity Monitoring.
* **Mechanism:** Deploys hidden decoy files in sensitive directories (`/Desktop`, `/Documents`).Uses **SHA-256 Hashing** to detect unauthorized encryption. Upon detection, it kills the offending process and **automatically restores** the file from a secure memory buffer, effectively neutralizing the encryption impact.

###  5. Malware Guard 
* **Detection Logic:** Checks **Registry Changes**, **System Processes Name Spoofing**, and **Network Activity**, and gives a final risk score.
* **Key Capabilities:**
    * **Process Lineage Analysis:** Detects suspicious parent-child relationships (e.g., `winword.exe` spawning `cmd.exe` or `powershell.exe`), blocking **Macro-based malware** and **Fileless attacks**.
    * **Backdoor & RAT Detection:** Monitors active process sockets to identify unauthorized listening ports commonly associated with Remote Access Trojans (e.g., DarkComet, Metasploit).

### 6. WinAPI Integration
* **Architecture:** A standalone C-based sensor working alongside the Python backend.
* **Mechanism:** Streams raw, **OS-level** data in real-time using **Pipes** (IPC), Extracts process metadata and deep **TCP network tables** directly from the Windows API and gives it to the python engine to analyze.

---

## 🛠️ Installation & Setup

### Prerequisites
* Python 3.8 or higher.
* Administrator privileges (Required for process termination and file protection).

### 1. Clone the Repository
```bash
git clone [https://github.com/ofri09bs/AI-Powered-EDR-System.git](https://github.com/ofri09bs/AI-Powered-EDR-System.git)
cd AI-Powered-EDR-System
```
### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Initialize AI & Biometrics
Before running the main dashboard, train the system to recognize "Normal" behavior:

**Network AI**: Run ```python utils/collect_model_data.py``` for a few minutes while browsing normally, then run ```python utils/train_network_model.py```.

**User Biometrics:** The system will automatically enter Learning Mode for the first 60 seconds upon first launch.

##  Usage
Run the main dashboard with Admin rights:
```bash
python main.py
```
And after that run the `dataCollectorAgent.exe` file with Admin rights



**The Dashboard**
- Status Indicators: Green (Active) / Red (Disabled).

- Live Logs: View real-time threats and system actions.

- Control Panel: Toggle specific agents on/off dynamically.


### 📂 Project Structure
```

├── agents/                 # The Core Logic Modules
│   ├── malware_guard.py    # Process & Signature Scanner
│   ├── network_guard.py    # AI & Rule-based Traffic Monitor
│   ├── ransom_guard.py     # Honeypot & File Integrity Monitor
│   ├── phishing_guard.py   # Clipboard Analyzer
│   └── user_guard.py       # Biometric Behavioral Analysis
│
├── data/                   # Storage for Models & Logs
│   ├── isolation_forest.pkl # Trained Network AI Model
│   ├── user_profile.json    # Biometric User Profile
│   └── traffic_data.csv     # Dataset for training
│
├── models/                  # All the trained Models
│   ├── network_isolation_forest.pkl # Network Traffic Model
│   └── phishing_model.pkl           # Phishing Detection Model  
│
├── utils/                  # Utility
│   ├── collect_model_data.py  # Network Model Data Collector (for training)
│   ├── train_network_model.py # Network Model Trainer
│   └── network_features.py    # Feature Extraction Logic
│
├── winapi_module/          # The Windows API Data Collector
│   ├── dataCollector.c        # The source code for the data collector
│   ├── dataCollectorAgent.exe # The collector executable
│   └── winapi_pipe_server.py  # The server that reads the data from the pipe
│
├── main.py                 # Central GUI & Controller
└── requirements.txt        # Dependencies
```

### ⚠️ Disclaimer
Educational Purpose Only. This software was developed for research and educational purposes to demonstrate EDR concepts. It is not intended to replace commercial antivirus products. The author is not responsible for any damage caused by misuse of this tool.
