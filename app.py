# import all modules needed
from flask import Flask, render_template, request, jsonify
import joblib
import tldextract
import pandas as pd
import re
from urllib.parse import urlparse

app = Flask(__name__)
model = joblib.load("model.pkl") #load the model file

def extract_features(url):
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    features = {
        'length_url': len(url),
        'length_hostname': len(hostname),
        'ip': int(bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", hostname))),  # IP format check
        'nb_dots': url.count("."),
        'nb_hyphens': url.count("-"),
        'nb_at': url.count("@"),
        'nb_qm': url.count("?"),
        'nb_and': url.count("&"),
        'nb_or': url.count("|"),
        'nb_eq': url.count("="),
        'nb_underscore': url.count("_"),
        'nb_tilde': url.count("~"),
        'nb_percent': url.count("%"),
        'nb_slash': url.count("/"),
        'nb_star': url.count("*"),
        'nb_colon': url.count(":"),
        'nb_comma': url.count(","),
        'nb_semicolumn': url.count(";"),
        'nb_dollar': url.count("$"),
        'nb_space': url.count(" "),
        'nb_www': url.lower().count("www"),
        'nb_com': url.lower().count("com"),
        'nb_dslash': url.count("//"),
        'http_in_path': int("http" in path.lower()),
        'https_token': int("https" in url.lower().replace("https://", "")),
        'ratio_digits_url': sum(c.isdigit() for c in url) / len(url),
        'ratio_digits_host': sum(c.isdigit() for c in hostname) / len(hostname) if hostname else 0,
        'punycode': int(hostname.startswith("xn--")),
        'port': int(bool(parsed.port)),
        'tld_in_path': int(ext.suffix in path.lower()),
        'tld_in_subdomain': int(ext.suffix in ext.subdomain.lower()),
        'abnormal_subdomain': int(len(ext.subdomain.split('.')) > 3),
        'nb_subdomains': len(ext.subdomain.split('.')) if ext.subdomain else 0,
        'prefix_suffix': int('-' in ext.domain),
        'random_domain': int(bool(re.fullmatch(r"[a-z0-9]{10,}", ext.domain))),
        'shortening_service': int(ext.domain in ['bit', 'goo', 'tinyurl', 'ow', 't', 'is', 'cli']),
        'path_extension': int(bool(re.search(r"\.(exe|php|asp|aspx|jsp|txt|html|js)$", path)))
    }

    return features

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/predict", methods=['POST'])
def predict():
    data = request.get_json()

    if not data or 'url' not in data:
        return jsonify({'error': 'No URL provided'}), 400

    url = data['url'] 
    features = extract_features(url)
    X = pd.DataFrame([features]) 
    prediction = model.predict(X)[0]
    res = {}

    if prediction == 1:
        res['prediction'] = "Phishing"
    else:
        res['prediction'] = "Legitimate"
    return jsonify(res)

if __name__ == "__main__":
    app.run()