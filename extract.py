import json
import pandas as pd
from urllib.parse import urlparse
import re


def is_ip_address(url):
    ip_pattern = re.compile(r'^(?:http|ftp)s?://'  # http:// or https://
                            r'(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3})'  # IP address
                            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(ip_pattern, url) is not None


def count_symbols(url, symbol):
    return url.count(symbol)


def count_digits(url):
    return sum(c.isdigit() for c in url)


def extract_features(url, label):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path
    subdomains = domain.split('.')

    features = {
        'url_length': len(url),
        'use_https': int(parsed_url.scheme == 'https'),
        'domain_length': len(domain),
        'num_subdomains': len(subdomains) - 2 if len(subdomains) > 2 else 0,
        'path_length': len(path),
        'use_ip': int(is_ip_address(url)),
        'count_slash': count_symbols(url, '/'),
        'count_dot': count_symbols(url, '.'),
        'count_ampersand': count_symbols(url, '&'),
        'count_at': count_symbols(url, '@'),
        'count_dash': count_symbols(url, '−'),
        'count_equals': count_symbols(url, '='),
        'count_question': count_symbols(url, '?'),
        'count_semicolon': count_symbols(url, ';'),
        'count_digits': count_digits(url),
        'label': label
    }

    return features


def process_json_file(file_path, label, limit=36000):
    with open(file_path, 'r') as file:
        urls = json.load(file)
    limited_urls = urls[:limit]
    return [extract_features(url, label) for url in limited_urls]


legitimate_data = process_json_file(
    'data_legitimate.json', 0)  # Label 0 for legitimate
phishing_data = process_json_file(
    'data_phishing.json', 1)  # Label 1 for phishing

# Combine and create a DataFrame
df = pd.DataFrame(legitimate_data + phishing_data)

# Write to CSV
df.to_csv('url_features_dataset.csv', index=False)
