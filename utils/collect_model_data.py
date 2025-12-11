import psutil
import time
import csv
import os
import sys
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from utils.network_features import extract_features, FEATURE_COLUMNS

DATA_FILE = os.path.join(BASE_DIR, 'data', 'network_traffic_data.csv')

CSV_HEADER = ["ConnectionID"] + FEATURE_COLUMNS

def load_existing_ids():
    if not os.path.exists(DATA_FILE):
        return set()
    
    try:
        df = pd.read_csv(DATA_FILE, usecols=["ConnectionID"])
        return set(df["ConnectionID"].tolist())
    except Exception:
        return set()

def start_data_collection():
    print(f"[DataCollector] Starting network data collection...")

    file_exits = os.path.exists(DATA_FILE)

    seen_connections = load_existing_ids()

    with open(DATA_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        if not file_exits:
            writer.writerow(CSV_HEADER)
            f.flush()

        new_samples = 0

        try:
            while True:
                connections = psutil.net_connections(kind='inet')

                current_pids = set()

                for conn in connections:
                    if conn.status != 'ESTABLISHED':
                        continue


                    conn_id = f"{conn.pid}:{conn.raddr.ip}:{conn.raddr.port}"
                    current_pids.add(conn.pid)
                    if conn_id in seen_connections:
                        continue

                    try:
                        process = psutil.Process(conn.pid)
                        features = extract_features(process, conn)
                        if features:
                            row = [conn_id] + features
                            writer.writerow(row)
                            f.flush()
                            os.fsync(f.fileno())
                            seen_connections.add(conn_id)
                            new_samples += 1

                    except Exception as e:
                        print(f"[DataCollector] Could not extract features for PID {conn.pid} : {e}")
                        continue

                time.sleep(1)

        except KeyboardInterrupt:
            print("[DataCollector] Data collection stopped by user.")

    print(f"[DataCollector] Data collection complete. {new_samples} records saved to {DATA_FILE}.")

if __name__ == "__main__":
    if not os.path.exists(os.path.join(BASE_DIR, 'data')):
        os.makedirs(os.path.join(BASE_DIR, 'data'))

    start_data_collection()