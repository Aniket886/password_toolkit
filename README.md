# Password Cracking & Hashing Toolkit 🔐

**Author:** [Aniket886](https://github.com/Aniket886)  
**GitHub:** https://github.com/Aniket886  
**Project:** Educational Cybersecurity Toolkit  
**Created:** 2025  

## ⚠️ EDUCATIONAL PURPOSE ONLY

**IMPORTANT:** This toolkit is designed for educational purposes to understand password security concepts. It should ONLY be used on systems you own or have explicit permission to test. Unauthorized access to computer systems is illegal and unethical.

## 📋 Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
- [Modules](#modules)
- [Security Considerations](#security-considerations)
- [Educational Resources](#educational-resources)
- [Legal & Ethical Notice](#legal--ethical-notice)

## 🎯 Overview

The Password Cracking & Hashing Toolkit is a comprehensive Python educational tool designed to demonstrate:
- How passwords are securely hashed
- Common attack methods against password hashes
- Password strength analysis
- Security best practices

This toolkit implements both offensive (cracking) and defensive (secure hashing) capabilities with strict educational safeguards including rate limiting and length restrictions.

## ✨ Features

### 🔐 Defensive (Security)
- **Multiple Hashing Algorithms**: bcrypt (recommended), SHA-256, SHA-512, PBKDF2, MD5 (educational only)
- **Secure Salt Generation**: Cryptographically secure random salts
- **Password Strength Analysis**: Entropy calculation, pattern detection, OWASP compliance checking
- **Batch Processing**: Hash multiple passwords efficiently

### ⚔️ Offensive (Educational Testing)
- **Dictionary Attack**: Wordlist-based with rule variations (leet speak, case changes, number appending)
- **Brute Force Attack**: Systematic generation with checkpoint/resume capability
- **Combined Attack**: Dictionary followed by smart brute force
- **Multi-threading**: Optimized performance with configurable thread count

### 📊 Analysis & Reporting
- **Entropy Calculation**: Shannon entropy and character space analysis
- **Pattern Detection**: Sequences, repetitions, keyboard patterns, dates
- **Time-to-Crack Estimates**: Based on character space and length
- **Visual Strength Meters**: Easy-to-understand password strength indicators
- **Export Capabilities**: JSON, CSV, and text format exports

## 🚀 Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package manager)

### Steps

1. **Clone or Download the Repository**
```bash
# If you have the files in a folder:
cd password_toolkit
```

2. **Install Dependencies**
```bash
pip install -r requirements.txt
```

3. **Verify Installation**
```bash
python src/password_cracker.py --help
```

## 🎮 Quick Start

### Interactive Mode
```bash
cd password_toolkit
python src/password_cracker.py
```

This launches the interactive menu with all features available.

### Command Line Mode

**Hash a password:**
```bash
python src/password_cracker.py --hash "MyPassword123" --algorithm bcrypt
```

**Analyze password strength:**
```bash
python src/password_cracker.py --analyze "MyPassword123"
```

**Crack a hash (with wordlist):**
```bash
python src/password_cracker.py --crack "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" --wordlist wordlists/common_passwords.txt
```

## 📖 Usage Guide

### Main Menu Options

1. **🔐 Hash Password (Defensive)**
   - Hash single passwords with various algorithms
   - Batch hash multiple passwords
   - Compare algorithm performance

2. **📖 Dictionary Attack**
   - Load wordlists (built-in or custom)
   - Apply rule-based variations
   - Multi-threaded execution

3. **🔢 Brute Force Attack**
   - Configurable character sets
   - Length ranges (1-8 characters max)
   - Checkpoint/resume capability

4. **🎯 Combined Attack**
   - Tries dictionary first
   - Falls back to smart brute force

5. **📊 Password Strength Analysis**
   - Entropy calculation
   - Pattern detection
   - OWASP compliance check
   - Detailed security reports

## 🧩 Modules

### password_hasher.py
Implements secure password hashing with multiple algorithms.

```python
from password_hasher import PasswordHasher

hasher = PasswordHasher()
result = hasher.hash_password("MyPassword", "bcrypt")
is_valid = hasher.verify_password("MyPassword", result['hash'], "bcrypt")
```

### dictionary_attack.py
Dictionary-based password cracking with rule variations.

```python
from dictionary_attack import DictionaryAttacker

attacker = DictionaryAttacker()
attacker.load_wordlist("wordlists/common_passwords.txt")
password = attacker.crack_hash(target_hash, algorithm="sha256")
```

### brute_force.py
Systematic password generation and testing.

```python
from brute_force import BruteForceAttacker

attacker = BruteForceAttacker()
password = attacker.crack_hash(target_hash, charset_config="lowercase", min_len=1, max_len=4)
```

### security_analyzer.py
Comprehensive password strength analysis.

```python
from security_analyzer import PasswordAnalyzer

analyzer = PasswordAnalyzer()
strength = analyzer.check_strength("MyPassword123")
report = analyzer.generate_report("MyPassword123")
```

## 🔒 Security Considerations

### Built-in Safeguards
- **Rate Limiting**: Max 1000 attempts/second to prevent abuse
- **Length Restrictions**: Maximum 8 characters for brute force
- **Educational Warnings**: Displayed at every module initialization
- **Audit Logging**: All operations are logged with timestamps

### Password Security Best Practices
1. **Use Strong, Unique Passwords**: Minimum 12 characters with mixed types
2. **Enable 2FA/MFA**: Add additional authentication layers
3. **Use Password Managers**: Generate and store unique passwords
4. **Regular Updates**: Change passwords for sensitive accounts periodically
5. **Avoid Personal Information**: Don't use names, birthdays, etc.
6. **Check for Breaches**: Verify passwords haven't been exposed

## 📚 Educational Resources

### Hashing vs Encryption
- **Hashing**: One-way function, cannot be reversed
- **Encryption**: Two-way, can be decrypted with key
- Passwords should always be hashed, never encrypted

### Time-to-Crack Estimates (1 billion attempts/second)
| Password Type | Length | Character Set | Time to Crack |
|--------------|--------|---------------|---------------|
| Numeric PIN | 4 | 10 (0-9) | < 1 second |
| Lowercase | 6 | 26 (a-z) | 5 seconds |
| Alphanumeric | 8 | 62 (a-z,A-Z,0-9) | 7 days |
| All Characters | 8 | 94 (all printable) | 92 days |
| Alphanumeric | 12 | 62 (a-z,A-Z,0-9) | 300 years |

### OWASP Password Guidelines
- Minimum length: 8 characters (12+ recommended)
- Maximum length: 64+ characters
- Allow all Unicode characters
- Check against known breach databases
- Implement account lockout policies
- Use secure hashing (bcrypt, Argon2, PBKDF2)

## 📝 Wordlists

The toolkit includes two carefully curated wordlists:

### common_passwords.txt
- **118 unique passwords** (cleaned, no duplicates)
- Most commonly used passwords from real breaches
- Optimized for quick testing
- Quality Score: 90/100 ⭐⭐⭐⭐⭐

### enhanced_wordlist.txt  
- **185+ unique passwords** organized in 18 categories
- Categories include: Common, Numeric, Keyboard patterns, Names, Sports, Tech, etc.
- Includes variations with special characters and substitutions
- Quality Score: 65/100 ⭐⭐⭐⭐
- Perfect for comprehensive testing

### Wordlist Statistics Tool
Analyze any wordlist with:
```bash
python src/wordlist_stats.py
```

## 🎯 Testing

The toolkit includes test data in `tests/test_hashes.json` with known password-hash pairs for validation.

### Running Tests
```bash
# Test dictionary attack
python src/dictionary_attack.py

# Test brute force
python src/brute_force.py

# Test hashing
python src/password_hasher.py

# Test analyzer
python src/security_analyzer.py
```

## ⚖️ Legal & Ethical Notice

### Acceptable Use
✅ Testing your own passwords
✅ Educational demonstrations in controlled environments
✅ Security research with proper authorization
✅ Learning about cryptography and security

### Unacceptable Use
❌ Attempting to crack passwords without authorization
❌ Using on systems you don't own
❌ Bypassing security measures illegally
❌ Any malicious or harmful activities

### Legal Disclaimer
This toolkit is provided "as is" for educational purposes only. The authors assume no liability for misuse or damage caused by this program. Users are responsible for complying with all applicable laws and regulations.

## 🤝 Contributing

This is an educational project. Contributions that enhance the educational value while maintaining ethical safeguards are welcome.

## 📄 License

This project is released under the MIT License with additional ethical use restrictions. See LICENSE file for details.

## 🙏 Acknowledgments

- OWASP for password security guidelines
- The cryptography community for secure hashing algorithms
- Security researchers who promote ethical hacking education

---

**Remember**: With great power comes great responsibility. Use this knowledge to improve security, not to compromise it.

## 📞 Contact & Support

For educational questions or ethical security discussions, please use appropriate forums and always emphasize the educational nature of your queries.

---

## 👨‍💻 Developer

**Aniket886**  
🔗 GitHub: [https://github.com/Aniket886](https://github.com/Aniket886)  
💻 Projects: Cybersecurity Tools & Educational Software  
🔒 Focus: Ethical Hacking & Security Education  

---

*Created for educational purposes to understand password security. Always use ethically and legally.*  
*© 2025 Aniket886 - Educational Cybersecurity Toolkit*
