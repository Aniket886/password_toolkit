#!/usr/bin/env python3
"""
Password Cracking & Hashing Toolkit - Main Interface
Educational Cybersecurity Toolkit - For authorized educational use only
Interactive menu system for password security operations

Author: Aniket886
GitHub: https://github.com/Aniket886
Project: Educational Cybersecurity Toolkit
Created: 2025
"""

import sys
import os
import time
import json
import getpass
import argparse
import hashlib
from datetime import datetime
from typing import Dict, Optional, List

# Add src directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import our modules
from password_hasher import PasswordHasher
from dictionary_attack import DictionaryAttacker
from brute_force import BruteForceAttacker
from security_analyzer import PasswordAnalyzer


class PasswordCracker:
    """
    Main interface for the Password Toolkit.
    Provides interactive menu and coordinates between modules.
    """
    
    def __init__(self):
        """Initialize the password toolkit."""
        self.hasher = None
        self.dict_attacker = None
        self.brute_attacker = None
        self.analyzer = None
        self.results_history = []
        self._display_banner()
    
    def _display_banner(self):
        """Display the application banner."""
        print("\n" + "=" * 70)
        print(r"""
 ____                                     _   _____           _ _    _ _   
|  _ \ __ _ ___ _____      _____  _ __ __| | |_   _|__   ___ | | | _(_) |_ 
| |_) / _` / __/ __\ \ /\ / / _ \| '__/ _` |   | |/ _ \ / _ \| | |/ / | __|
|  __/ (_| \__ \__ \\ V  V / (_) | | | (_| |   | | (_) | (_) | |   <| | |_ 
|_|   \__,_|___/___/ \_/\_/ \___/|_|  \__,_|   |_|\___/ \___/|_|_|\_\_|\__|
        """)
        print("=" * 70)
        print("EDUCATIONAL CYBERSECURITY TOOLKIT")
        print("Developed by: Aniket886 | GitHub: https://github.com/Aniket886")
        print("FOR AUTHORIZED USE ONLY")
        print("=" * 70)
        print("\n⚠ WARNING: This tool is for educational purposes only!")
        print("Never use on systems you don't own or without explicit permission.")
        print("=" * 70)
    
    def main_menu(self):
        """Display and handle the main menu."""
        while True:
            print("\n" + "=" * 50)
            print("MAIN MENU")
            print("=" * 50)
            print("1. 🔐 Hash Password (Defensive)")
            print("2. 📖 Dictionary Attack")
            print("3. 🔢 Brute Force Attack")
            print("4. 🎯 Combined Attack (Dictionary → Brute Force)")
            print("5. 📊 Password Strength Analysis")
            print("6. 📁 View Results History")
            print("7. 🔧 Configuration & Settings")
            print("8. 📚 Educational Resources")
            print("9. ❌ Exit")
            print("=" * 50)
            
            choice = input("\nSelect option (1-9): ").strip()
            
            if choice == '1':
                self.hash_password_menu()
            elif choice == '2':
                self.dictionary_attack_menu()
            elif choice == '3':
                self.brute_force_menu()
            elif choice == '4':
                self.combined_attack_menu()
            elif choice == '5':
                self.password_analysis_menu()
            elif choice == '6':
                self.view_results_history()
            elif choice == '7':
                self.configuration_menu()
            elif choice == '8':
                self.educational_resources()
            elif choice == '9':
                self.exit_application()
            else:
                print("❌ Invalid option. Please try again.")
    
    def hash_password_menu(self):
        """Handle password hashing operations."""
        if not self.hasher:
            self.hasher = PasswordHasher()
        
        print("\n" + "=" * 50)
        print("PASSWORD HASHING")
        print("=" * 50)
        
        print("1. Hash single password")
        print("2. Batch hash passwords")
        print("3. Compare hashing algorithms")
        print("4. Back to main menu")
        
        choice = input("\nSelect option (1-4): ").strip()
        
        if choice == '1':
            # Single password hashing
            password = getpass.getpass("Enter password to hash: ")
            
            print("\nSelect algorithm:")
            print("1. bcrypt (Recommended)")
            print("2. SHA-256")
            print("3. SHA-512")
            print("4. PBKDF2")
            print("5. MD5 (NOT SECURE - Educational only)")
            
            algo_choice = input("Choice (1-5): ").strip()
            
            algo_map = {
                '1': 'bcrypt',
                '2': 'sha256',
                '3': 'sha512',
                '4': 'pbkdf2',
                '5': 'md5'
            }
            
            algorithm = algo_map.get(algo_choice, 'bcrypt')
            
            result = self.hasher.hash_password(password, algorithm)
            
            print("\n" + "=" * 50)
            print("HASHING RESULT")
            print("=" * 50)
            print(f"Algorithm: {result['algorithm']}")
            print(f"Hash: {result['hash']}")
            print(f"Salt: {result['salt']}")
            if result['metadata']:
                print(f"Metadata: {result['metadata']}")
            
            # Save result
            self._save_result({
                'operation': 'hash',
                'algorithm': algorithm,
                'hash': result['hash'],
                'timestamp': datetime.now().isoformat()
            })
            
            # Export option
            export = input("\nExport result? (y/n): ").lower()
            if export == 'y':
                format_choice = input("Format (json/csv/text): ").lower()
                exported = self.hasher.export_hash(result, format_choice)
                filename = f"hash_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format_choice}"
                with open(f"password_toolkit/results/{filename}", 'w') as f:
                    f.write(exported)
                print(f"✓ Exported to {filename}")
        
        elif choice == '2':
            # Batch hashing
            print("\nEnter passwords (one per line, empty line to finish):")
            passwords = []
            while True:
                pwd = input()
                if not pwd:
                    break
                passwords.append(pwd)
            
            if passwords:
                algorithm = input("Algorithm (bcrypt/sha256/sha512/pbkdf2): ").lower()
                results = self.hasher.batch_hash(passwords, algorithm)
                print(f"\n✓ Hashed {len(results)} passwords")
        
        elif choice == '3':
            # Compare algorithms
            password = getpass.getpass("Enter password to test: ")
            comparison = self.hasher.compare_algorithms(password)
            
            print("\n" + "=" * 50)
            print("ALGORITHM COMPARISON COMPLETE")
            print("=" * 50)
            print("Check the output above for details")
        
        input("\nPress Enter to continue...")
    
    def dictionary_attack_menu(self):
        """Handle dictionary attack operations."""
        if not self.dict_attacker:
            self.dict_attacker = DictionaryAttacker()
        
        print("\n" + "=" * 50)
        print("DICTIONARY ATTACK")
        print("=" * 50)
        
        # Get target hash
        hash_input = input("Enter hash to crack: ").strip()
        algorithm = input("Hash algorithm (sha256/md5/sha512/bcrypt): ").lower()
        
        # Salt handling
        salt = None
        if algorithm != 'bcrypt':
            has_salt = input("Does the hash use salt? (y/n): ").lower()
            if has_salt == 'y':
                salt = input("Enter salt (base64 encoded): ").strip()
        
        # Wordlist selection
        print("\nWordlist options:")
        print("1. Use common passwords list (118 passwords)")
        print("2. Use enhanced wordlist (200+ passwords with categories)")
        print("3. Load custom wordlist file")
        print("4. Enter words manually")
        
        wordlist_choice = input("Choice (1-4): ").strip()
        
        if wordlist_choice == '1':
            # Common passwords list
            try:
                self.dict_attacker.load_wordlist("password_toolkit/wordlists/common_passwords.txt")
            except FileNotFoundError:
                # Fallback to built-in if file not found
                common_passwords = [
                    "password", "123456", "password123", "admin", "letmein",
                    "welcome", "monkey", "dragon", "master", "qwerty",
                    "abc123", "111111", "iloveyou", "sunshine", "princess"
                ]
                self.dict_attacker.generate_wordlist(common_passwords)
        
        elif wordlist_choice == '2':
            # Enhanced wordlist
            try:
                self.dict_attacker.load_wordlist("password_toolkit/wordlists/enhanced_wordlist.txt")
            except FileNotFoundError:
                print("❌ Enhanced wordlist not found!")
                return
        
        elif wordlist_choice == '3':
            # Custom wordlist file
            filepath = input("Enter wordlist file path: ").strip()
            try:
                self.dict_attacker.load_wordlist(filepath)
            except FileNotFoundError:
                print("❌ Wordlist file not found!")
                return
        
        elif wordlist_choice == '4':
            # Manual entry
            print("Enter passwords (one per line, empty line to finish):")
            passwords = []
            while True:
                pwd = input()
                if not pwd:
                    break
                passwords.append(pwd)
            self.dict_attacker.generate_wordlist(passwords)
        
        # Run attack
        print("\nStarting dictionary attack...")
        start_time = time.time()
        
        result = self.dict_attacker.attack_with_progress(hash_input, algorithm, salt)
        
        elapsed = time.time() - start_time
        
        # Save result
        if result:
            self._save_result({
                'operation': 'dictionary_attack',
                'hash': hash_input[:50] + '...',
                'password': result,
                'algorithm': algorithm,
                'time': elapsed,
                'timestamp': datetime.now().isoformat()
            })
        
        input("\nPress Enter to continue...")
    
    def brute_force_menu(self):
        """Handle brute force attack operations."""
        if not self.brute_attacker:
            self.brute_attacker = BruteForceAttacker()
        
        print("\n" + "=" * 50)
        print("BRUTE FORCE ATTACK")
        print("=" * 50)
        
        # Get target hash
        hash_input = input("Enter hash to crack: ").strip()
        algorithm = input("Hash algorithm (sha256/md5/sha512/bcrypt): ").lower()
        
        # Salt handling
        salt = None
        if algorithm != 'bcrypt':
            has_salt = input("Does the hash use salt? (y/n): ").lower()
            if has_salt == 'y':
                salt = input("Enter salt (base64 encoded): ").strip()
        
        # Character set selection
        print("\nCharacter set options:")
        print("1. Digits only (0-9)")
        print("2. Lowercase letters (a-z)")
        print("3. Uppercase letters (A-Z)")
        print("4. Letters only (a-z, A-Z)")
        print("5. Alphanumeric (a-z, A-Z, 0-9)")
        print("6. Common (a-z, 0-9)")
        print("7. Full (letters, numbers, symbols)")
        print("8. Custom character set")
        
        charset_choice = input("Choice (1-8): ").strip()
        
        charset_map = {
            '1': 'digits',
            '2': 'lowercase',
            '3': 'uppercase',
            '4': 'alpha',
            '5': 'alphanumeric',
            '6': 'common',
            '7': 'full'
        }
        
        if charset_choice == '8':
            charset = input("Enter custom characters: ").strip()
        else:
            charset = charset_map.get(charset_choice, 'common')
        
        # Length range
        min_len = int(input("Minimum password length (1-8): ") or "1")
        max_len = int(input("Maximum password length (1-8): ") or "4")
        
        # Show time estimate
        charset_str = self.brute_attacker.get_charset(charset)
        estimate = self.brute_attacker.estimate_time(charset_str, min_len, max_len)
        print(f"\n⏱ Estimated time: {estimate}")
        
        proceed = input("Proceed with attack? (y/n): ").lower()
        if proceed != 'y':
            return
        
        # Run attack
        start_time = time.time()
        
        result = self.brute_attacker.crack_hash(
            hash_input, charset, min_len, max_len, algorithm, salt
        )
        
        elapsed = time.time() - start_time
        
        # Save result
        if result:
            self._save_result({
                'operation': 'brute_force',
                'hash': hash_input[:50] + '...',
                'password': result,
                'algorithm': algorithm,
                'charset': charset,
                'time': elapsed,
                'timestamp': datetime.now().isoformat()
            })
        
        input("\nPress Enter to continue...")
    
    def combined_attack_menu(self):
        """Run combined dictionary + brute force attack."""
        print("\n" + "=" * 50)
        print("COMBINED ATTACK")
        print("=" * 50)
        print("This will try dictionary attack first, then brute force if needed.")
        
        # Get target hash
        hash_input = input("Enter hash to crack: ").strip()
        algorithm = input("Hash algorithm (sha256/md5/sha512): ").lower()
        
        # Initialize attackers
        if not self.dict_attacker:
            self.dict_attacker = DictionaryAttacker()
        if not self.brute_attacker:
            self.brute_attacker = BruteForceAttacker()
        
        print("\n[Phase 1: Dictionary Attack]")
        print("-" * 30)
        
        # Try dictionary first
        common_passwords = [
            "password", "123456", "password123", "admin", "letmein",
            "welcome", "monkey", "dragon", "master", "qwerty"
        ]
        self.dict_attacker.generate_wordlist(common_passwords)
        
        result = self.dict_attacker.crack_hash(hash_input, algorithm)
        
        if result:
            print(f"\n✓ Password found in dictionary: {result}")
        else:
            print("\n✗ Not found in dictionary, trying brute force...")
            print("\n[Phase 2: Smart Brute Force]")
            print("-" * 30)
            
            result = self.brute_attacker.smart_attack(hash_input, algorithm)
            
            if result:
                print(f"\n✓ Password found by brute force: {result}")
            else:
                print("\n✗ Password not found")
        
        input("\nPress Enter to continue...")
    
    def password_analysis_menu(self):
        """Handle password strength analysis."""
        if not self.analyzer:
            self.analyzer = PasswordAnalyzer()
        
        print("\n" + "=" * 50)
        print("PASSWORD STRENGTH ANALYSIS")
        print("=" * 50)
        
        print("1. Analyze single password")
        print("2. Batch analyze passwords")
        print("3. Generate detailed report")
        print("4. Back to main menu")
        
        choice = input("\nSelect option (1-4): ").strip()
        
        if choice == '1':
            password = getpass.getpass("Enter password to analyze: ")
            
            # Quick analysis
            strength = self.analyzer.check_strength(password)
            entropy = self.analyzer.calculate_entropy(password)
            patterns = self.analyzer.detect_patterns(password)
            
            # Visual strength meter
            meter_length = 30
            filled = int(meter_length * strength['score'] / 100)
            meter = '█' * filled + '░' * (meter_length - filled)
            
            print("\n" + "=" * 50)
            print("ANALYSIS RESULTS")
            print("=" * 50)
            print(f"Strength: {strength['strength']}")
            print(f"Score: {strength['score']}/100")
            print(f"[{meter}]")
            print(f"\nEntropy: {entropy:.2f} bits")
            print(f"Length: {len(password)} characters")
            
            # Show patterns
            pattern_count = sum(len(v) for v in patterns.values())
            if pattern_count > 0:
                print(f"\n⚠ {pattern_count} patterns detected:")
                for pattern_type, found in patterns.items():
                    if found:
                        print(f"  • {pattern_type}: {', '.join(found[:3])}")
            
            # Suggestions
            if strength['suggestions']:
                print("\n📝 Suggestions:")
                for suggestion in strength['suggestions']:
                    print(f"  • {suggestion}")
        
        elif choice == '2':
            print("\nEnter passwords to analyze (one per line, empty to finish):")
            passwords = []
            while True:
                pwd = input()
                if not pwd:
                    break
                passwords.append(pwd)
            
            if passwords:
                results = self.analyzer.batch_analyze(passwords)
                
                print("\n" + "=" * 50)
                print("BATCH ANALYSIS RESULTS")
                print("=" * 50)
                
                for i, result in enumerate(results, 1):
                    strength = result['strength']['strength']
                    score = result['strength']['score']
                    print(f"{i}. Length: {result['length']:2} | "
                          f"Strength: {strength:12} | "
                          f"Score: {score:3}/100")
        
        elif choice == '3':
            password = getpass.getpass("Enter password for detailed report: ")
            report = self.analyzer.generate_report(password)
            print(report)
            
            # Save option
            save = input("\nSave report to file? (y/n): ").lower()
            if save == 'y':
                filename = f"password_toolkit/results/analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                os.makedirs(os.path.dirname(filename), exist_ok=True)
                with open(filename, 'w') as f:
                    f.write(report)
                print(f"✓ Report saved to {filename}")
        
        input("\nPress Enter to continue...")
    
    def view_results_history(self):
        """Display history of results."""
        print("\n" + "=" * 50)
        print("RESULTS HISTORY")
        print("=" * 50)
        
        if not self.results_history:
            print("No results in history")
        else:
            for i, result in enumerate(self.results_history[-10:], 1):
                print(f"\n{i}. {result['operation']} - {result['timestamp']}")
                if 'password' in result:
                    print(f"   Password found: {result['password']}")
                if 'algorithm' in result:
                    print(f"   Algorithm: {result['algorithm']}")
                if 'time' in result:
                    print(f"   Time: {result['time']:.2f}s")
        
        if self.results_history:
            export = input("\nExport history? (y/n): ").lower()
            if export == 'y':
                filename = f"password_toolkit/results/history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                os.makedirs(os.path.dirname(filename), exist_ok=True)
                with open(filename, 'w') as f:
                    json.dump(self.results_history, f, indent=2)
                print(f"✓ History exported to {filename}")
        
        input("\nPress Enter to continue...")
    
    def configuration_menu(self):
        """Display configuration options."""
        print("\n" + "=" * 50)
        print("CONFIGURATION & SETTINGS")
        print("=" * 50)
        
        print("Current Settings:")
        print(f"  • Dictionary threads: 4")
        print(f"  • Rate limit: 1000 attempts/second")
        print(f"  • Max password length: 8 characters")
        print(f"  • Checkpoint interval: 10000 attempts")
        
        print("\n⚠ Note: Settings are configured for educational use")
        print("Rate limiting and length restrictions prevent misuse")
        
        input("\nPress Enter to continue...")
    
    def educational_resources(self):
        """Display educational information."""
        print("\n" + "=" * 70)
        print("EDUCATIONAL RESOURCES")
        print("=" * 70)
        
        print("""
📚 PASSWORD SECURITY FUNDAMENTALS

1. HASHING vs ENCRYPTION
   • Hashing: One-way function (cannot reverse)
   • Encryption: Two-way (can decrypt with key)
   • Passwords should always be hashed, never encrypted

2. SECURE HASHING ALGORITHMS
   ✓ bcrypt: Designed for passwords, includes salt, configurable work factor
   ✓ PBKDF2: Key derivation function, many iterations
   ✓ Argon2: Modern, memory-hard algorithm
   ✗ MD5: Broken, only for educational purposes
   ✗ SHA-1: Deprecated, vulnerable to collisions

3. SALT & PEPPER
   • Salt: Random data added to password before hashing
   • Prevents rainbow table attacks
   • Should be unique per password
   • Pepper: Secret salt stored separately

4. ATTACK METHODS
   • Dictionary: Tests common passwords
   • Brute Force: Tries all combinations
   • Rainbow Tables: Precomputed hashes
   • Hybrid: Combines methods

5. PASSWORD STRENGTH FACTORS
   • Length (most important!)
   • Character variety
   • Unpredictability
   • No personal information
   • No common patterns

6. OWASP RECOMMENDATIONS
   • Minimum 8 characters
   • Maximum 64+ characters allowed
   • Support all Unicode characters
   • Check against breach databases
   • Implement account lockout policies

7. TIME-TO-CRACK ESTIMATES
   8 chars (lowercase): ~5 hours
   8 chars (mixed case): ~62 hours  
   8 chars (alphanumeric): ~7 days
   8 chars (all symbols): ~92 days
   12 chars (alphanumeric): ~300 years
   
8. BEST PRACTICES
   • Use password managers
   • Enable 2FA/MFA
   • Unique password per service
   • Regular password updates for sensitive accounts
   • Passphrases > complex passwords
        """)
        
        input("\nPress Enter to continue...")
    
    def _save_result(self, result: Dict):
        """Save result to history."""
        self.results_history.append(result)
        
        # Also save to file
        os.makedirs('password_toolkit/results', exist_ok=True)
        filename = f"password_toolkit/results/result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(result, f, indent=2)
        except:
            pass  # Silent fail for auto-save
    
    def exit_application(self):
        """Exit the application."""
        print("\n" + "=" * 50)
        print("Thank you for using Password Toolkit!")
        print("Remember: Use responsibly and ethically")
        print("=" * 50)
        sys.exit(0)


def main():
    """Main entry point with command line argument support."""
    parser = argparse.ArgumentParser(
        description='Password Cracking & Hashing Toolkit - Educational Tool'
    )
    
    parser.add_argument(
        '--hash',
        help='Hash a password directly',
        metavar='PASSWORD'
    )
    
    parser.add_argument(
        '--analyze',
        help='Analyze password strength',
        metavar='PASSWORD'
    )
    
    parser.add_argument(
        '--algorithm',
        help='Hash algorithm to use',
        choices=['bcrypt', 'sha256', 'sha512', 'md5', 'pbkdf2'],
        default='bcrypt'
    )
    
    parser.add_argument(
        '--crack',
        help='Attempt to crack a hash',
        metavar='HASH'
    )
    
    parser.add_argument(
        '--wordlist',
        help='Wordlist file for dictionary attack',
        metavar='FILE'
    )
    
    args = parser.parse_args()
    
    # Handle command line arguments
    if args.hash:
        hasher = PasswordHasher()
        result = hasher.hash_password(args.hash, args.algorithm)
        print(f"Hash ({args.algorithm}): {result['hash']}")
        print(f"Salt: {result['salt']}")
        
    elif args.analyze:
        analyzer = PasswordAnalyzer()
        report = analyzer.generate_report(args.analyze)
        print(report)
        
    elif args.crack:
        if args.wordlist:
            attacker = DictionaryAttacker()
            attacker.load_wordlist(args.wordlist)
            result = attacker.crack_hash(args.crack, args.algorithm)
            if result:
                print(f"Password found: {result}")
            else:
                print("Password not found")
        else:
            print("Please specify --wordlist for dictionary attack")
    
    else:
        # Interactive mode
        app = PasswordCracker()
        try:
            app.main_menu()
        except KeyboardInterrupt:
            print("\n\nInterrupted by user")
            app.exit_application()


if __name__ == "__main__":
    main()