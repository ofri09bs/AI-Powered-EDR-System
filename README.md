# 🛡️ AEGIS - AI-Powered Autonomous Defense System

![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![AI](https://img.shields.io/badge/AI-Scikit--Learn-orange) ![Status](https://img.shields.io/badge/Status-Active-brightgreen) ![Security](https://img.shields.io/badge/Security-Endpoint%20Protection-red)

**AEGIS** (Advanced Endpoint Guard & Intelligence System) is a comprehensive, Python-based **Endpoint Detection and Response (EDR)** solution. Unlike traditional antiviruses that rely solely on signatures, AEGIS employs a **Hybrid Detection Engine** combining **static rules**, **behavioral analysis**, **honeypots**, and **Artificial Intelligence** (Unsupervised Learning) to detect zero-day threats, **ransomware**, and unauthorized users.

---

## 🚀 Key Features (Technical Breakdown)

### 🧠 1. AI-Driven Network Threat Detection
* **Algorithm:** Unsupervised Learning using **Isolation Forest**.
* **Functionality:** Analyzes network flow vectors (Port, Bytes Sent/Received, Duration, Country Risk) in real-time.
* **Capability:** Detects **Zero-Day C2 (Command & Control)** channels, beaconing behavior, and slow-rate data exfiltration that bypass traditional signature-based firewalls.
* **Behavioral Rules:** Blocks unauthorized use of system binaries (`powershell.exe`, `cmd.exe`) for external connections (Living-off-the-Land attacks).

### 🎣 2. ML-Powered Phishing Guard
* **Algorithm:** Supervised Learning using **Random Forest Classifier**.
* **Feature Engineering:** Extracts lexical features from URLs in the clipboard (Entropy, Length, Special Characters, TLD reputation).
* **Capability:** Predicts the probability of a URL being malicious in milliseconds.
* **Defense:** Detects sophisticated **Typosquatting**, Homograph attacks, and obfuscated phishing links before the user even pastes them.

### 👤 3. User Guard: Behavioral Biometrics Engine
* **Algorithm:** Statistical Z-Score Analysis & Dynamic Profiling.
* **Detection Logic:** Continuously authenticates the user based on unique motor skills:
    * **Keystroke Dynamics:** Measures "Flight Time" (latency between keys) and "Dwell Time".
    * **Mouse Trajectory:** Analyzes velocity, acceleration, and angular movements.
* **Defense:** Instantly detects **Account Takeover (ATO)** and physical intrusion. If the behavioral score drops below the threshold, the system initiates a **Hard Lock**.

### 🔒 4. Ransomware Guard (Canary System)
* **Detection Logic:** Honey-token deployment & File Integrity Monitoring (FIM).
* **Mechanism:** Deploys hidden decoy files ("Canaries") in sensitive directories (`/Desktop`, `/Documents`).
* **Auto-Remediation:** Uses **SHA-256 Hashing** to detect unauthorized encryption. Upon detection, it kills the offending process and **automatically restores** the file from a secure memory buffer, effectively neutralizing the encryption impact.

### 🦠 5. Malware Guard (Heuristic Process Hunter)
* **Detection Logic:** Goes beyond simple signature matching by analyzing the *context* of running processes in real-time.
* **Key Capabilities:**
    * **Process Lineage Analysis:** Detects suspicious parent-child relationships (e.g., `winword.exe` spawning `cmd.exe` or `powershell.exe`), blocking **Macro-based malware** and **Fileless attacks**.
    * **Volatile Execution Detection:** Flags unsigned binaries executing from high-risk, ephemeral directories (e.g., `%TEMP%`, `AppData`, `Downloads`) often used by droppers.
    * **Backdoor & RAT Detection:** Monitors active process sockets to identify unauthorized listening ports commonly associated with Remote Access Trojans (e.g., DarkComet, Metasploit).
    * **Signature Verification:** Cross-references file hashes (SHA-256) against a local Threat Intelligence database of known malware families.

---

## 🛠️ Installation & Setup

### Prerequisites
* Python 3.8 or higher.
* Administrator privileges (Required for process termination and file protection).

### 1. Clone the Repository
```bash
git clone [https://github.com/YourUsername/AEGIS-EDR.git](https://github.com/YourUsername/AEGIS-EDR.git)
cd AEGIS-EDR
```
### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Initialize AI & Biometrics
Before running the main dashboard, train the system to recognize "Normal" behavior:

**Network AI**: Run ```python tools/collect_model_data.py``` for a few minutes while browsing normally, then run ```python tools/train_network_model.py```.

**User Biometrics:** The system will automatically enter Learning Mode for the first 60 seconds upon first launch.

## 🎮 Usage
Run the main dashboard with Admin rights:
```bash
python main.py
```

**The Dashboard**
- Status Indicators: Green (Active) / Red (Disabled).

- Live Logs: View real-time threats and system actions.

- Control Panel: Toggle specific agents on/off dynamically.


### 📂 Project Structure
```
AEGIS/
│
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
├── tools/                  # Utilities
│   ├── collect_data.py     # Network Traffic Sniffer
│   ├── train_model.py      # AI Model Trainer
│   ├── full_system_test.py # (Legacy) Red-Team Simulation
│   └── final_system_test.py# Full Integration Test Suite
│
├── utils/                  # Shared Helpers
│   └── network_features.py # Feature Extraction Logic
│
├── main.py                 # Central GUI & Controller
└── requirements.txt        # Dependencies
```

### ⚠️ Disclaimer
Educational Purpose Only. This software was developed for research and educational purposes to demonstrate EDR concepts. It is not intended to replace commercial antivirus products. The author is not responsible for any damage caused by misuse of this tool.
