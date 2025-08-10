import re
import sys
import argparse
from urllib.parse import urlparse, unquote
from collections import Counter
URL_SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly', 'is.gd', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'clck.ru', 'tr.im', 'x.co', 'v.gd', 'su.pr'}
SUSPICIOUS_KEYWORDS = ['login', 'verify', 'secure', 'update', 'account', 'bank', 'paypal', 'signin', 'confirm', 'password', 'credential', 'authenticate', 'reset', 'billing']
WEIGHT_LONG_URL = 1
WEIGHT_IP_ADDRESS = 3
WEIGHT_MANY_SUBDOMAINS = 2
WEIGHT_KEYWORDS = 2
WEIGHT_SHORTENER = 3
WEIGHT_AT_SIGN = 3
WEIGHT_MANY_HYPHENS = 2
WEIGHT_NO_HTTPS = 1
THRESHOLD_SUSPICIOUS = 3
THRESHOLD_PHISHING = 6
LONG_URL_THRESHOLD = 75
MAX_SAFE_SUBDOMAINS = 2

def extract_features(url: str) -> dict:
    if not url.startswith(('http://', 'https://', 'ftp://')):
        url = 'http://' + url
    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    path = parsed.path or ''
    query = parsed.query or ''
    full_url = unquote(url)
    features = {}
    features['url_length'] = len(full_url)
    ip_pattern = re.compile('^(\\d{1,3}\\.){3}\\d{1,3}$')
    features['has_ip_address'] = bool(ip_pattern.match(hostname))
    if hostname:
        parts = hostname.split('.')
        subdomain_count = max(len(parts) - 2, 0)
    else:
        subdomain_count = 0
    features['subdomain_count'] = subdomain_count
    url_lower = full_url.lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    features['suspicious_keywords'] = found_keywords
    clean_host = hostname.lstrip('www.').lower() if hostname else ''
    if clean_host.startswith('www.'):
        clean_host = clean_host[4:]
    features['is_shortener'] = clean_host in URL_SHORTENERS
    features['has_at_sign'] = '@' in full_url
    features['hyphen_count'] = hostname.count('-')
    features['uses_https'] = parsed.scheme.lower() == 'https'
    return features

def score_features(features: dict) -> tuple:
    score = 0
    items = []
    length = features['url_length']
    fired = length > LONG_URL_THRESHOLD
    if fired:
        score += WEIGHT_LONG_URL
    items.append({'check': 'URL Length', 'result': '{} characters'.format(length), 'weight': WEIGHT_LONG_URL, 'fired': fired, 'reason': 'URLs longer than {} chars are often padded to hide the real domain.'.format(LONG_URL_THRESHOLD)})
    fired = features['has_ip_address']
    if fired:
        score += WEIGHT_IP_ADDRESS
    items.append({'check': 'IP Address as Host', 'result': 'YES -- raw IP detected' if fired else 'No IP detected', 'weight': WEIGHT_IP_ADDRESS, 'fired': fired, 'reason': 'Legitimate services use domain names. Raw IPs bypass DNS reputation checks.'})
    count = features['subdomain_count']
    fired = count > MAX_SAFE_SUBDOMAINS
    if fired:
        score += WEIGHT_MANY_SUBDOMAINS
    items.append({'check': 'Subdomain Count', 'result': '{} subdomain(s)'.format(count), 'weight': WEIGHT_MANY_SUBDOMAINS, 'fired': fired, 'reason': 'More than {} subdomains often used to embed trusted brand names.'.format(MAX_SAFE_SUBDOMAINS)})
    kws = features['suspicious_keywords']
    fired = len(kws) > 0
    if fired:
        score += WEIGHT_KEYWORDS
    items.append({'check': 'Suspicious Keywords', 'result': 'Found: {}'.format(kws) if fired else 'None found', 'weight': WEIGHT_KEYWORDS, 'fired': fired, 'reason': "Words like 'login', 'verify', 'secure' in URLs mimic legitimate action pages."})
    fired = features['is_shortener']
    if fired:
        score += WEIGHT_SHORTENER
    items.append({'check': 'URL Shortener', 'result': 'YES -- known shortener' if fired else 'Not a shortener', 'weight': WEIGHT_SHORTENER, 'fired': fired, 'reason': 'Shorteners conceal the true destination; frequently used in phishing campaigns.'})
    fired = features['has_at_sign']
    if fired:
        score += WEIGHT_AT_SIGN
    items.append({'check': '@ Sign in URL', 'result': 'YES -- @ sign detected' if fired else 'No @ sign', 'weight': WEIGHT_AT_SIGN, 'fired': fired, 'reason': "Browsers navigate to host AFTER the @, so 'paypal.com@evil.com' goes to evil.com."})
    hyphens = features['hyphen_count']
    fired = hyphens >= 3
    if fired:
        score += WEIGHT_MANY_HYPHENS
    items.append({'check': 'Hyphens in Domain', 'result': '{} hyphen(s)'.format(hyphens), 'weight': WEIGHT_MANY_HYPHENS, 'fired': fired, 'reason': 'Phishing domains stack hyphens to mimic brands (e.g., my-secure-bank-login.com).'})
    fired = not features['uses_https']
    if fired:
        score += WEIGHT_NO_HTTPS
    items.append({'check': 'HTTPS', 'result': 'HTTP only -- no encryption' if fired else 'HTTPS present', 'weight': WEIGHT_NO_HTTPS, 'fired': fired, 'reason': 'HTTP sends data in plain text. Note: HTTPS alone does NOT prove legitimacy.'})
    return (score, items)

def classify(score: int) -> str:
    if score >= THRESHOLD_PHISHING:
        return 'LIKELY PHISHING'
    elif score >= THRESHOLD_SUSPICIOUS:
        return 'SUSPICIOUS'
    else:
        return 'SAFE (low risk)'

def print_report(url: str, score: int, items: list) -> None:
    label = classify(score)
    symbol_map = {'LIKELY PHISHING': '[!!] LIKELY PHISHING', 'SUSPICIOUS': '[!]  SUSPICIOUS', 'SAFE (low risk)': '[OK] SAFE (low risk)'}
    verdict_display = symbol_map.get(label, label)
    max_score = WEIGHT_LONG_URL + WEIGHT_IP_ADDRESS + WEIGHT_MANY_SUBDOMAINS + WEIGHT_KEYWORDS + WEIGHT_SHORTENER + WEIGHT_AT_SIGN + WEIGHT_MANY_HYPHENS + WEIGHT_NO_HTTPS
    sep = '=' * 78
    sep2 = '-' * 78
    print()
    print(sep)
    print('  PHISHING URL DETECTOR -- Analysis Report')
    print(sep)
    print('  URL     : {}'.format(url))
    print('  Score   : {} / {}'.format(score, max_score))
    print('  Verdict : {}'.format(verdict_display))
    print(sep2)
    print('  {:<26} {:<30} {:>5}  {}'.format('CHECK', 'RESULT', 'RISK', 'FIRED'))
    print('  {:<26} {:<30} {:>5}  {}'.format('-' * 26, '-' * 30, '-' * 5, '-' * 5))
    for item in items:
        status = '[X]' if item['fired'] else '[ ]'
        risk = '+{}'.format(item['weight']) if item['fired'] else '  0'
        result_str = str(item['result'])
        if len(result_str) > 28:
            result_str = result_str[:25] + '...'
        print('  {} {:<24} {:<30} {:>5}  {}'.format(status, item['check'], result_str, risk, 'YES' if item['fired'] else 'no'))
    print()
    print(sep2)
    print('  Educational Notes (fired checks only):')
    fired_any = False
    for item in items:
        if item['fired']:
            fired_any = True
            print('  * {}: {}'.format(item['check'], item['reason']))
    if not fired_any:
        print('  * No risk factors fired. URL appears low-risk by heuristic analysis.')
    print()
    print('  REMEMBER: This is a heuristic only. Always verify URLs through')
    print('  official channels before entering credentials or personal data.')
    print(sep)
    print()

def analyse_url(url: str) -> None:
    url = url.strip()
    if not url:
        return
    features = extract_features(url)
    score, items = score_features(features)
    print_report(url, score, items)

def main() -> None:
    parser = argparse.ArgumentParser(prog='phishing_url_detector', description='Educational Phishing URL Detector -- static heuristic analysis.', formatter_class=argparse.RawDescriptionHelpFormatter, epilog='\nExamples:\n  python phishing_url_detector.py --url "http://paypal-secure-login.update.evil.com/verify"\n  python phishing_url_detector.py --file urls.txt\n        ')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--url', '-u', type=str, help='A single URL to analyse.')
    group.add_argument('--file', '-f', type=str, help='Path to a text file containing one URL per line.')
    args = parser.parse_args()
    if args.url:
        analyse_url(args.url)
    elif args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as fh:
                urls = fh.readlines()
        except FileNotFoundError:
            print('[ERROR] File not found: {}'.format(args.file), file=sys.stderr)
            sys.exit(1)
        except OSError as exc:
            print('[ERROR] Cannot read file: {}'.format(exc), file=sys.stderr)
            sys.exit(1)
        urls = [u.strip() for u in urls if u.strip() and (not u.strip().startswith('#'))]
        if not urls:
            print('[INFO] No URLs found in file.', file=sys.stderr)
            sys.exit(0)
        print("\n  Analysing {} URL(s) from '{}' ...\n".format(len(urls), args.file))
        for url in urls:
            analyse_url(url)
        verdicts = Counter()
        for url in urls:
            url = url.strip()
            if not url:
                continue
            features = extract_features(url)
            score, _ = score_features(features)
            verdicts[classify(score)] += 1
        print('=' * 50)
        print('  BATCH SUMMARY')
        print('=' * 50)
        for verdict, count in verdicts.most_common():
            print('    {:<25}  {} URL(s)'.format(verdict, count))
        print('=' * 50)
        print()
if __name__ == '__main__':
    main()