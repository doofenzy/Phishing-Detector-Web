import tldextract
import re
from urllib.parse import urlparse
from joblib import load
import socket

def getIPAddress(url):
    try:
        parsed_url = urlparse()

def extract(url):
    parsed = urlparse(url)
    ext = tldextract.extract(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""

    features = {
        'length_url': len(url),
        'length_hostname': len(path),
        'ip': d,
        'nb_dots',
        'nb_hyphens',
        'nb_at',
        'nb_qm',
        'nb_and',
        'nb_or',
        'nb_eq',
        'nb_underscore',
        'nb_tilde',
        'nb_percent',
        'nb_slash',
        'nb_star',
        'nb_colon',
        'nb_comma',
        'nb_semicolumn',
        'nb_dollar',
        'nb_space',
        'nb_www',
        'nb_com',
        'nb_dslash',
        'http_in_path',
        'https_token',
        'ratio_digits_url',
        'ratio_digits_host',
        'punycode',
        'port',
        'tld_in_path',
        'tld_in_subdomain',
        'abnormal_subdomain',
        'nb_subdomains',
        'prefix_suffix',
        'random_domain',
        'shortening_service',
        'path_extension'
    }

model = load('easy_phishing_detector.pkl')

url = input("Enter URL: ")
print(tldextract.extract(url))

