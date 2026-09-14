# Phishing URL and Malicious Link Detector

A mini project by  **Nishant Sharma** to detect whether a given URL is safe or a phishing attempt using machine learning and lexical feature extraction.

Built with Python, Scikit-learn, and Streamlit.

---

## 📌 About the Project

Phishing attacks trick users into sharing sensitive credentials and personal data through fake websites. While standard antivirus tools and browser extensions rely on blacklists (which only work if the malicious URL has already been reported), this project uses machine learning to inspect the **structure and patterns of the URL string itself**.

It extracts lexical and structural indicators (like IP addresses in URLs, excessive subdomains, presence of `@`, and suspicious keywords) and runs them through a trained **Random Forest** model to classify the URL as **Legitimate** or **Phishing** in real time.

---

## 🚀 Features

- **Real-time link analysis:** Works in sub-seconds without sending HTTP requests to the target site (safe from drive-by downloads).
- **Lexical feature extraction:** Extracts 9 key structural features directly from the URL string.
- **Interactive web UI:** Clean dashboard made with Streamlit.
- **Threat confidence score:** Displays the probability percentage of the prediction.
- **Feature breakdown table:** Shows exactly which parameters (dots, hyphens, keywords, protocol) were detected for viva/demo explanation.

---

## 🛠️ Tech Stack

- **Language:** Python 3.9+
- **Machine Learning:** Scikit-learn (Random Forest Classifier)
- **Data Handling:** Pandas, NumPy
- **Model Serialization:** Joblib
- **Web App / UI:** Streamlit

---

## 📂 Project Structure

```text
phishing_detector/
├── app.py                 # Main application script (UI + feature extraction + model)
├── phishing_model.pkl     # Saved trained model file (generated on first run)
├── requirements.txt       # Project dependencies
└── README.md              # Project documentation
```

---

## ⚙️ How to Setup and Run

### 1. Clone or download this project
Put all files in a single folder on your computer.

### 2. Create a virtual environment (Optional but recommended)
```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate
```

### 3. Install requirements
```bash
pip install -r requirements.txt
```
*(Or install directly: `pip install streamlit scikit-learn pandas numpy joblib`)*

### 4. Run the Streamlit app
```bash
streamlit run app.py
```

After running the command, open your browser and go to:
```text
http://localhost:8501
```

---

## 🔍 How Feature Extraction Works

The model evaluates key structural features from the raw URL:
1. **URL Length:** Long, bloated URLs are commonly used by attackers to hide destinations.
2. **IP Address in Hostname:** Direct IP addresses (e.g., `http://192.168.1.1/...`) often indicate bypassed domain registration.
3. **Presence of `@` Symbol:** In URL syntax, browsers ignore everything before the `@`, redirecting to whatever follows.
4. **Dot (`.`) and Hyphen (`-`) counts:** Excessive subdomains and hyphenated brand names (e.g., `paypal-security-update.com`) indicate typosquatting.
5. **URL Shorteners:** Flags common shortening domains (`bit.ly`, `tinyurl`, etc.) often used to hide the final landing page.
6. **HTTPS check:** Checks whether the site uses SSL/TLS.
7. **Sensitive Keywords:** Detects trigger words like `login`, `verify`, `banking`, `secure`, and `update`.

---

## 🔮 Future Improvements

- Train on larger benchmark datasets like PhishTank and Kaggle URL sets (50,000+ links).
- Add WHOIS domain age checking via python-whois.
- Package as a browser extension for Google Chrome.
- Test deep learning sequence models like Bi-LSTM.

---

## 👨‍💻 Author

- **Nishant Sharma**
- B.Tech CSE 
