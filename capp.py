import re
import os
from urllib.parse import urlparse
import pandas as pd
import numpy as np
import streamlit as st
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

MODEL_FILE = "phishing_model.pkl"

# ==========================================
# 1. FEATURE EXTRACTION MODULE
# ==========================================
def extract_features(url: str) -> dict:
    """
    Extracts 9 lexical and structural features from a raw URL string.
    0 indicates benign/safe behavior, 1 indicates suspicious/phishing indicators.
    """
    features = {}
    parsed = urlparse(url if "://" in url else "http://" + url)
    netloc = parsed.netloc
    path = parsed.path

    # 1. Total length of URL (phishing URLs often conceal destinations with long paths)
    features['url_length'] = len(url)
    
    # 2. Presence of IP address directly in hostname
    ip_pattern = r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])'
    features['has_ip'] = 1 if re.search(ip_pattern, netloc) else 0

    # 3. Presence of '@' symbol (ignores anything before @ in HTTP standard)
    features['has_at_symbol'] = 1 if "@" in url else 0

    # 4. Count of dots in URL
    features['count_dots'] = url.count('.')

    # 5. Count of hyphens (attackers frequently use hyphens to mimic legitimate brands)
    features['count_hyphens'] = url.count('-')

    # 6. Check for URL shortening service domains
    shorteners = r'(bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly)'
    features['is_shortened'] = 1 if re.search(shorteners, netloc.lower()) else 0

    # 7. Use of HTTPS protocol
    features['is_https'] = 1 if parsed.scheme == 'https' else 0

    # 8. Suspicious keywords in URL string
    keywords = ['login', 'verify', 'update', 'banking', 'secure', 'account', 'signin', 'confirm']
    features['has_suspicious_keyword'] = 1 if any(kw in url.lower() for kw in keywords) else 0

    # 9. Count of subdomains
    subdomains = netloc.split('.')
    features['subdomain_count'] = len(subdomains) - 2 if len(subdomains) > 2 else 0

    return features

# ==========================================
# 2. MODEL INITIALIZATION & TRAINING
# ==========================================
def generate_sample_dataset():
    """Generates a representative baseline dataset for immediate evaluation."""
    sample_urls = [
        # Legitimate URLs
        ("https://www.google.com", 0),
        ("https://www.github.com/torvalds/linux", 0),
        ("https://aktu.ac.in/syllabus.html", 0),
        ("https://en.wikipedia.org/wiki/Machine_learning", 0),
        ("https://stackoverflow.com/questions/tagged/python", 0),
        ("https://www.microsoft.com/en-in", 0),
        ("https://www.amazon.in/dp/B08L5WHFT9", 0),
        ("https://docs.python.org/3/library/urllib.parse.html", 0),
        ("https://kaggle.com/datasets", 0),
        ("https://scikit-learn.org/stable/modules/classes.html", 0),
        # Phishing / Suspicious URLs
        ("http://192.168.1.1/login.php?user=admin", 1),
        ("http://secure-login-update-account-bank.com/auth", 1),
        ("http://bit.ly/3xY90Pz-banking-verify", 1),
        ("http://paypal-verification-center.account-support.xyz/login", 1),
        ("http://google.com-update-security-alert.net/auth", 1),
        ("http://update-kyc-documents.sbi-support.co.vu/", 1),
        ("http://netflix-billing-issue-confirm.com/signin", 1),
        ("http://218.45.10.12/webscr?cmd=_login-run", 1),
        ("http://tinyurl.com/free-gift-card-claim-now", 1),
        ("http://account-recovery-verify-credentials.org/security", 1),
    ]
    
    rows = []
    for url, label in sample_urls:
        feats = extract_features(url)
        feats['label'] = label
        rows.append(feats)
    return pd.DataFrame(rows)

def train_and_save_model():
    """Trains a Random Forest classifier and persists it to disk."""
    df = generate_sample_dataset()
    X = df.drop(columns=['label'])
    y = df['label']

    clf = RandomForestClassifier(n_estimators=50, random_state=42)
    clf.fit(X, y)
    joblib.dump(clf, MODEL_FILE)
    return clf

def load_or_train_model():
    if os.path.exists(MODEL_FILE):
        return joblib.load(MODEL_FILE)
    return train_and_save_model()

# ==========================================
# 3. STREAMLIT FRONTEND APPLICATION
# ==========================================
st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Phishing URL & Malicious Link Classifier")
st.markdown(
    "Analyze web links in real time using **lexical and structural feature extraction** "
    "powered by a **Random Forest Classifier**."
)

model = load_or_train_model()

# User Input Section
url_input = st.text_input(
    "Enter URL to inspect:",
    placeholder="e.g., https://paypal-security-alert.account-update.xyz/login"
)

if st.button("Inspect Link", type="primary"):
    if not url_input.strip():
        st.warning("Please enter a valid URL to analyze.")
    else:
        # Extract features
        features = extract_features(url_input)
        features_df = pd.DataFrame([features])

        # Inference
        prediction = model.predict(features_df)[0]
        prediction_prob = model.predict_proba(features_df)[0]
        phishing_prob = prediction_prob[1] * 100

        st.markdown("---")
        col1, col2 = st.columns([1, 1])

        with col1:
            st.subheader("Verdict")
            if prediction == 1 or phishing_prob >= 50.0:
                st.error(f"⚠️ **MALICIOUS / PHISHING DETECTED**\n\nConfidence: **{phishing_prob:.1f}%**")
            else:
                st.success(f"✅ **LEGITIMATE / BENIGN URL**\n\nSafety Score: **{100 - phishing_prob:.1f}%**")

            st.progress(int(phishing_prob))
            st.caption("Bar represents the estimated threat probability index.")

        with col2:
            st.subheader("Extracted Heuristics")
            st.dataframe(features_df.T.rename(columns={0: "Extracted Value"}))

st.markdown("---")
with st.expander("ℹ️ How the Detection Engine Works"):
    st.markdown(
        """
        - **IP Address in Hostname:** Attackers use direct IPs to bypass domain registration and DNS blacklists.
        - **Symbol Analysis (`@`, `-`, `.`):** Heavy usage of hyphens and subdomains is typical in typo-squatting.
        - **Keyword Spotting:** Tokens such as `login`, `verify`, `banking`, and `update` trigger higher threat scoring when combined with abnormal domain depth.
        - **Transport Security:** Verifies whether HTTP or HTTPS encryption is configured on the link.
        """
    )