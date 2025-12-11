import time
import re
from urllib.parse import urlparse
import pyperclip  
import joblib
import pandas as pd
import os

#***************** Static URL analysis ****************

PROTECTED_DOMAINS = [
    "google.com", "gmail.com",
    "facebook.com", "instagram.com", "whatsapp.com",
    "twitter.com", "x.com",
    "linkedin.com", "reddit.com", 
    "paypal.com", "venmo.com", "square.com", 
    "netflix.com", "youtube.com",
    "apple.com", "icloud.com",
    "microsoft.com", "office.com",
    "amazon.com", 
    "bankhapoalim.co.il", "leumi.co.il", "discountbank.co.il" 
]

suswords = [
    'login', 'signin', 'verify', 'account', 'password',
    'secure', 'security', 'update', 'confirm', 'banking',
    'paypal','support', 'admin', 'service', 'webscr','bank'
]

sus_suffixes = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.zip', '.ru', '.xyz','.php'
]

def calculate_levenshtein(s1, s2):
    if len(s1) < len(s2):
        return calculate_levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def is_url(txt):
    if len(txt) > 1500:
        return False
    
    url_pattern = re.compile(
        r'^(https?://)?'  
        r'(([A-Za-z0-9-]+\.)+[A-Za-z]{2,6}|'  
        r'localhost|'  
        r'(\d{1,3}\.){3}\d{1,3})'  
        r'(:\d+)?'  
        r'(/[\w./?%&=-]*)?$'  
    )

    return re.match(url_pattern, txt) is not None
   

def analyze_url(url):
    score = 0
    reasons = []

    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()

        if domain.startswith('www.'):
            domain = domain[4:]

        if ':' in domain:
            domain = domain.split(':')[0]

        if not domain:
            return 0, []
        
        # Direct IP usage check
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            score += 60
            reasons.append(f"Direct IP usage detected ({domain})")

        # Suspicious suffix check
        for suffix in sus_suffixes:
            if domain.endswith(suffix):
                score += 20
                reasons.append(f"Suspicious domain suffix detected ({suffix})")
                break
        
        # Suspicious word check
        if domain not in PROTECTED_DOMAINS:
            for word in suswords:
                if word in url.lower():
                    score += 10
                    reasons.append(f"Suspicious word '{word}' found in domain")

        # Levenshtein distance check
        if domain not in PROTECTED_DOMAINS:
            for protected in PROTECTED_DOMAINS:
                distance = calculate_levenshtein(domain, protected)
                if 0 < distance <= 2 and len(domain) >= 4:
                    score += 50
                    reasons.append(f"Spoofing attempt of '{protected}' detected: '{domain}'")
                    break

        # ML model check
        model_score = calc_model_score(url)
        if model_score > 0:
            score += model_score
            reasons.append(f"Phishing URL detection model flagged the URL with score {model_score:.2f}")

    except Exception as e:
        print(f"Error parsing URL: {e}")
        return 0, []
    
    return score, reasons
        

#***************** Phishing URL Detection Model ****************
try:
    model = joblib.load('models/phishing_model.pkl')
except Exception:
    model = None
    print("[PhishingGuard] Warning: Could not load phishing detection model.")


def count_words(url):
  count = 0
  for word in suswords:
    if word in url.lower():
      count += 1
  return count

def has_sus_suffix(url):
  for suffix in sus_suffixes:
    if url.lower().endswith(suffix):
      return 1
  return 0



def extract_features(url):
  features = {}
  features['length'] = len(url)
  features['count_dots'] = url.count('.')
  features['count_dashes'] = url.count('-')
  features['has_https'] = int(url.startswith('https'))
  features['has_at'] = int('@' in url)
  features['has_www'] = int(url.startswith('www'))
  features['has_ip'] = int(url.replace('.', '').isdigit())
  parsed_url = urlparse(url)
  hostname = parsed_url.hostname if parsed_url.hostname else ''
  parts = hostname.split('.')
  num_subdomains = len(parts) - 2 
  features['num_of_subdomains'] = max(0, num_subdomains)
  features['path_slashes'] = parsed_url.path.count('/')
  features['double_slash_in_path'] = int('//' in parsed_url.path)
  features['suswords_count'] = count_words(url)
  features['has_sus_suffix'] = has_sus_suffix(url)

  features_name = model.feature_names_in_
  features = pd.DataFrame([features], columns=features_name)
  features = features.fillna(0)

  return features


def calc_model_score(url):
    features = extract_features(url)
    prediction = model.predict(features)[0]
    confidence = model.predict_proba(features).max() * 100

    return confidence * 50/100 if prediction == 'bad' else 0

def start_monitoring(alert_queue , stop_event):
    print("[PhishingGuard] Monitoring Clipboard...")

    last_clipboard = ""

    while not stop_event.is_set():
        try:
            current_clipboard = pyperclip.paste().strip()

            if current_clipboard != last_clipboard and current_clipboard:
                last_clipboard = current_clipboard

                if is_url(current_clipboard):
                    risk_score, reasons = analyze_url(current_clipboard)

                    if risk_score >= 60:
                        msg = f"PHISHING DETECTED!\nURL: {current_clipboard}\nScore: {risk_score}\nReasons: {', '.join(reasons)}"
                        alert_queue.put(("THREAT",msg))

                        pyperclip.copy("")
                        alert_queue.put(("INFO", "AUTO-RESPONSE: Malicious link removed from clipboard."))

            time.sleep(1)
    
        except Exception as e:
            time.sleep(1)
    