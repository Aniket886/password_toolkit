# 🎯 Password Toolkit Demo Website

## 🚨 **EDUCATIONAL USE ONLY** 🚨

This is an **intentionally vulnerable** web application designed for educational purposes to demonstrate how brute force attacks work and how to defend against them.

**⚠️ WARNING: Never use these techniques on systems you don't own or lack explicit permission to test!**

---

## 📋 Quick Start

### 1. Install Dependencies
```bash
cd demo
pip install -r requirements.txt
```

### 2. Start the Demo Website
```bash
python app.py
```
The website will be available at: http://localhost:5000

### 3. Run a Brute Force Attack
```bash
python brute_force_web.py --target http://localhost:5000/login --username admin --wordlist-file ../wordlists/common_passwords.txt
```

---

## 📁 Demo Files

| File | Description |
|------|-------------|
| `app.py` | Main Flask application with vulnerable login |
| `brute_force_web.py` | Web-based brute force attack tool |
| `DEMO_GUIDE.md` | **Complete step-by-step tutorial** |
| `SECURITY_WARNINGS.md` | **Important legal and ethical guidelines** |
| `templates/` | HTML templates for the web interface |
| `requirements.txt` | Python dependencies |

---

## 🎓 What You'll Learn

- How brute force attacks work against web applications
- Common vulnerabilities in authentication systems
- Rate limiting and security measures
- Ethical hacking principles and responsible disclosure

---

## 🔐 Demo Accounts

The demo website includes these intentionally weak accounts:

| Username | Password | Purpose |
|----------|----------|---------|
| `admin` | `admin` | Administrative account |
| `user` | `password` | Standard user account |
| `test` | `123456` | Test account |
| `demo` | `demo` | Demo account |
| `guest` | `guest` | Guest account |

---

## 🛠️ Available Attack Methods

### Dictionary Attack
```bash
python brute_force_web.py --target http://localhost:5000/login --username admin --wordlist-file ../wordlists/common_passwords.txt
```

### Brute Force Attack
```bash
python brute_force_web.py --target http://localhost:5000/login --username admin --brute-force --max-length 6
```

### Custom Attack
```bash
python brute_force_web.py --target http://localhost:5000/login --username admin --passwords password,admin,123456
```

---

## 📊 API Endpoints

The demo includes API endpoints for monitoring:

- `GET /api/users` - List all users (usernames and emails only)
- `GET /api/login-attempts` - View recent login attempts
- `GET /admin` - Admin panel for monitoring attacks

---

## 🔍 Key Features

### Vulnerable Website
- ✅ No rate limiting
- ✅ Weak password policy
- ✅ Predictable usernames
- ✅ Detailed error messages
- ✅ No account lockouts

### Attack Tool
- ✅ Multi-threaded attacks
- ✅ Rate limiting options
- ✅ Progress monitoring
- ✅ Result logging
- ✅ Multiple attack modes

---

## 📚 Documentation

### 📖 Complete Tutorial
Read **[DEMO_GUIDE.md](DEMO_GUIDE.md)** for detailed step-by-step instructions.

### ⚖️ Legal & Ethical Guidelines
**MUST READ**: [SECURITY_WARNINGS.md](SECURITY_WARNINGS.md) before using this toolkit.

---

## 🛡️ Security Lessons

### What Makes This Vulnerable?
1. **No Rate Limiting** - Unlimited login attempts
2. **Weak Passwords** - Common, easily guessable passwords
3. **No Account Lockouts** - Failed attempts don't lock accounts
4. **Predictable Usernames** - Common usernames like 'admin', 'user'
5. **No CAPTCHA** - No human verification required

### How to Fix These Issues?
1. **Implement Rate Limiting** - Limit attempts per IP/user
2. **Strong Password Policy** - Require complex passwords
3. **Account Lockouts** - Lock accounts after failed attempts
4. **Multi-Factor Authentication** - Add second authentication factor
5. **CAPTCHA** - Add human verification for suspicious activity
6. **Monitoring & Alerting** - Log and alert on suspicious activity

---

## 🎯 Learning Objectives

After completing this demo, you should understand:

- ✅ How brute force attacks work technically
- ✅ Why certain security measures are important
- ✅ How to identify authentication vulnerabilities
- ✅ The importance of strong password policies
- ✅ Real-world attack scenarios and their impact
- ✅ Ethical considerations in security testing

---

## 🚀 Advanced Usage

### Custom Wordlists
Create your own wordlist file:
```bash
echo -e "password\nadmin\n123456\nqwerty" > custom_passwords.txt
python brute_force_web.py --target http://localhost:5000/login --username admin --wordlist-file custom_passwords.txt
```

### Multiple Usernames
Test multiple usernames:
```bash
python brute_force_web.py --target http://localhost:5000/login --usernames admin,user,test --wordlist-file ../wordlists/common_passwords.txt
```

### Adjust Attack Speed
Control attack speed with delays:
```bash
python brute_force_web.py --target http://localhost:5000/login --username admin --wordlist-file ../wordlists/common_passwords.txt --delay 2 --threads 1
```

---

## 📈 Monitoring Attacks

### Real-time Monitoring
1. Open http://localhost:5000/admin in your browser
2. Start an attack in another terminal
3. Watch the login attempts appear in real-time

### API Monitoring
```bash
# Check recent login attempts
curl http://localhost:5000/api/login-attempts

# List all users
curl http://localhost:5000/api/users
```

---

## 🔧 Troubleshooting

### Common Issues

**Website won't start:**
```bash
# Make sure you're in the demo directory
cd demo
# Install dependencies
pip install Flask Werkzeug requests
# Try starting again
python app.py
```

**Attack tool errors:**
```bash
# Make sure the website is running first
# Check if localhost:5000 is accessible
curl http://localhost:5000
```

**Permission errors:**
```bash
# Make sure you have write permissions in the demo directory
# Results are saved to JSON files in the current directory
```

---

## 📞 Support

If you encounter issues:

1. **Check the logs** - Both the website and attack tool provide detailed logs
2. **Read the documentation** - DEMO_GUIDE.md has troubleshooting tips
3. **Verify setup** - Ensure all dependencies are installed correctly
4. **Check permissions** - Make sure you have proper file permissions

---

## ⚖️ Legal Disclaimer

This toolkit is provided for **educational purposes only**. Users are responsible for:

- ✅ Only testing systems they own or have explicit permission to test
- ✅ Complying with all applicable laws and regulations
- ✅ Using the toolkit ethically and responsibly
- ✅ Not causing harm or unauthorized access

**The authors are not liable for any misuse of this toolkit.**

---

## 🎓 Educational Resources

### Learn More About:
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Web Application Security](https://owasp.org/www-project-web-security-testing-guide/)
- [Ethical Hacking](https://www.sans.org/white-papers/1305/)
- [Penetration Testing](https://owasp.org/www-project-penetration-testing-methodologies/)

### Professional Certifications:
- Certified Ethical Hacker (CEH)
- Offensive Security Certified Professional (OSCP)
- GIAC Penetration Tester (GPEN)

---

**Remember: With great power comes great responsibility. Use this knowledge to make the internet safer! 🛡️**