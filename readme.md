
# 🛡️ Phishing URL Detection Web App

A Flask-based web application that predicts whether a given URL is phishing or legitimate using a trained machine learning model. The model analyzes the URL's structure and lexical features — no web scraping or third-party lookups required.


## 🚀 Features

- Fast and lightweight — feature extraction from the URL only

- Flask API backend with interactive frontend UI

- Detects suspicious patterns like:

    - IP addresses

    - Multiple subdomains

    - Suspicious file extensions

    - Randomized domains

    - URL shorteners


## 📁 Project Structure
```
phishing-url-detector/
│
├── app.py
├── model.pkl
├── requirements.txt
└── templates/
    └── index.html
```


## 📦 Installation

✅ 1. Clone the repository

```bash
git clone https://github.com/doofenzy/Phishing-Detector-Web.git
cd Phishing-Detector-Web
```
    
✅ 2. Create a virtual environment (recommended)
```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```

✅ 3. Install dependencies
```bash
pip install -r requirements.txt
```


## 🧪 Run the App

```bash
  python app.py
```
Then open your browser and go to:
```bash
  http://127.0.0.1:5000/
```
## 🧾 Author

- [@JeromeInfante](https://www.github.com/doofenzy)

