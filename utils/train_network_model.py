import pandas as pd
import joblib
import os
from sklearn.ensemble import IsolationForest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_FILE = os.path.join(BASE_DIR, 'data', 'network_traffic_data.csv')
MODEL_FILE = os.path.join(BASE_DIR, 'models', 'network_isolation_forest.pkl')

def train_network_model():
    print("[ModelTrainer] Training network anomaly detection model...")
    if not os.path.exists(DATA_FILE):
        print(f"[ModelTrainer] Data file {DATA_FILE} not found. Cannot train model.")
        return
    
    try:
        data = pd.read_csv(DATA_FILE)
        feature_columns = [
            "RemotePort", "CountryRisk", "ProcType", "BytesRatio", 
            "Duration", "CPU", "SuspiciousParent", "ConnRate", 
            "NewPort", "SystemPath"
        ]
    except Exception as e:
        print(f"[ModelTrainer] Error reading data file: {e}")
        return
    
    if len(data) < 50:
        print("[ModelTrainer] Not enough data to train the model. Need at least 100 records.")
        return
    
    X = data[feature_columns]

    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    model.fit(X)
        
    joblib.dump(model, MODEL_FILE)
    print(f"[ModelTrainer] Model trained and saved to {MODEL_FILE}.")

if __name__ == "__main__":
    train_network_model()