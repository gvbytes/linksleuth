# LinkSleuth

LinkSleuth is a static URL checker. It does not visit the target site; it looks at the URL string itself and scores common phishing signals such as raw IP hosts, suspicious keywords, URL shorteners, missing HTTPS, and unusual domain structure.

---

## Reading the URL

A legitimate URL is usually short, direct, and easy to identify:
- `https://paypal.com`
- `https://google.com/account`

Phishing URLs often lean on confusing structure: fake brand words, long paths, misleading subdomains, shorteners, or raw IP addresses. The script turns those observations into a simple risk score.

---

## Checks performed

### 1. URL length
Long URLs are not automatically malicious, but phishing links often use long paths to bury the real destination:

```
http://secure-paypal-account-verify-login-update-now.xyz/confirm/user/details/step1
```

The default threshold flags URLs longer than **75 characters**.

---

### 2. IP address instead of a domain
Every website lives on a computer that has a numbered address (like `192.168.1.1`). Real websites pay for a proper name like `amazon.com`. Phishers often skip that and use the raw number — it's cheaper, harder to trace, and looks weird:

```
http://192.168.45.99/paypal/login
```

A raw IP host is worth investigating, especially when the path imitates a login or billing page.

---

### 3. Too many subdomains
Domains have levels separated by dots. The **last two parts** are the real address. Everything before those is extra (called a subdomain). Phishers add fake brand names as subdomains to confuse you:

```
http://paypal.com.secure.login.evil.net
```

Here, the **real** domain is `evil.net`! The `paypal.com` part is just a label added to fool you. More than **2 dots' worth of prefixes** is suspicious.

---

### 4. Suspicious words in the URL
Phishers sprinkle trust-sounding words into the URL so it looks like a real action page. Our script watches for words like:

> `login`, `verify`, `secure`, `update`, `account`, `bank`, `paypal`, `signin`, `confirm`, `password`

Finding these in a random unknown URL raises the alarm!

---

### 5. URL shorteners
Services like **bit.ly** or **tinyurl.com** take a long link and make it tiny. That sounds handy — but phishers love them because a shortened link completely **hides** where you're going. You have NO idea if `bit.ly/AbCd123` goes to your bank or to a hacker's trap.

Our script knows all the popular shortener services and flags them automatically.

---

### 6. The @ symbol
Here's a sneaky one. Web browsers have a rule: if there's an `@` in the URL, everything **before** the `@` is treated as login info, and everything **after** it is the real website. So:

```
http://paypal.com@evil-hacker.com/
```

Your browser actually goes to **evil-hacker.com**! You see "paypal.com" and feel safe — but you're not. The `@` sign in a URL is almost always a phishing trick.

---

### 7. 🔴 Lots of Hyphens in the Domain — my-secure-bank-login.com
Real company domains are usually simple: `paypal.com`, `amazon.com`, `hsbc.com`. When phishers can't grab the real domain, they register something like:

```
paypal-secure-account-verify.com
my-bank-login-update-now.com
```

Three or more hyphens in the domain name is suspicious.

---

### 8. 🟡 HTTP Instead of HTTPS — The Padlock Check
You've probably seen the little padlock icon in your browser. That means the site uses **HTTPS** — your data travels encrypted and private. If a site uses plain **HTTP**, there's no encryption — anyone on the same WiFi could spy on what you type.

**Important note:** HTTPS does NOT mean a site is safe! Phishing sites can (and do) use HTTPS too. It just means the connection is private, not that the site is honest. So we give it a small penalty but not a huge one.

---

## How the Scoring Works

Think of it like a quiz. Each suspicious sign above adds points to a **"Risk Score"**:

| Warning Sign | Points Added |
|---|---|
| URL too long | +1 |
| Raw IP address | +3 |
| Too many subdomains | +2 |
| Suspicious keywords | +2 |
| URL shortener used | +3 |
| @ sign in URL | +3 |
| 3+ hyphens in domain | +2 |
| HTTP instead of HTTPS | +1 |

**Maximum possible score: 17**

After adding up all the points, the script gives a verdict:

| Total Score | Verdict |
|---|---|
| 0 – 2 | ✅ SAFE (low risk) |
| 3 – 5 | ⚠️ SUSPICIOUS |
| 6 or more | ❌ LIKELY PHISHING |

---

## How to Run the Script

You need **Python 3** installed. No extra libraries needed — it uses only Python's built-in tools!

**Check a single URL:**
```
python phishing_url_detector.py --url "http://paypal-secure-login.update.evil.com/verify"
```

**Check a whole file of URLs (one per line):**
```
python phishing_url_detector.py --file my_urls.txt
```

---

## Example Output

```
==============================================================================
  PHISHING URL DETECTOR -- Analysis Report
==============================================================================
  URL     : http://paypal-secure-login.update.evil.com/verify?account=123
  Score   : 8 / 17
  Verdict : [!!] LIKELY PHISHING
------------------------------------------------------------------------------
  CHECK                      RESULT                          RISK   FIRED
  -------------------------- ------------------------------ -----   -----
  [ ] URL Length             69 characters                      0   no
  [ ] IP Address as Host     No IP detected                     0   no
  [X] Subdomain Count        3 subdomain(s)                    +2   YES
  [X] Suspicious Keywords    Found: ['paypal', 'login', ...    +2   YES
  [ ] URL Shortener          Not a shortener                    0   no
  [ ] @ Sign in URL          No @ sign                          0   no
  [X] Hyphens in Domain      3 hyphen(s)                       +2   YES
  [X] HTTPS                  HTTP only -- no encryption        +1   YES
```

---

## Important: What This Script CAN'T Do

This script only looks at the **shape** of a URL — it never visits the page or connects to the internet. That means:

- A very clever phisher could make a clean-looking URL that fools this script
- A legitimate but unusual URL might get flagged incorrectly
- **Never** rely on this alone — always double-check suspicious links through official apps or websites

**This tool is for learning, not for final security decisions.**

---

## Quick Safety Rules (No Script Needed!)

1. **Never click links from unexpected emails or texts** — go to the website yourself by typing it
2. **Check the last two parts of a domain** — that's the real owner. `paypal.com.evil.net` is owned by `evil.net`
3. **When in doubt, don't click**
4. **Use a password manager** — it only fills passwords on the real site, not fakes
5. **Enable two-factor authentication** — even if a phisher gets your password, they can't log in without your phone

---

*Happy learning! The best security tool is a curious, questioning mind.*



