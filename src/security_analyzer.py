"""
Security Analyzer Module
Educational Cybersecurity Toolkit - For authorized educational use only
Implements password strength analysis and security assessment

Author: Aniket886
GitHub: https://github.com/Aniket886
Project: Educational Cybersecurity Toolkit
Created: 2025
"""

import math
import re
import string
from typing import Dict, List, Tuple, Optional
from collections import Counter
import json


class PasswordAnalyzer:
    """
    Password security analysis implementation.
    Evaluates password strength based on entropy, patterns, and OWASP guidelines.
    """
    
    # Common passwords list (top 100)
    COMMON_PASSWORDS = [
        "password", "123456", "password123", "admin", "12345678", "qwerty",
        "abc123", "123456789", "111111", "1234567", "iloveyou", "adobe123",
        "123123", "welcome", "1234567890", "photoshop", "1234", "password1",
        "12345", "000000", "password123!", "letmein", "monkey", "dragon",
        "master", "sunshine", "princess", "qwertyuiop", "superman", "123qwe"
    ]
    
    # Keyboard patterns
    KEYBOARD_PATTERNS = [
        "qwerty", "asdf", "zxcv", "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "1234", "4321", "12345", "54321", "123456", "654321",
        "qwer", "asdf", "zxcv", "1qaz", "2wsx", "3edc"
    ]
    
    # Common substitutions
    LEET_SUBSTITUTIONS = {
        '@': 'a', '4': 'a',
        '3': 'e',
        '1': 'i', '!': 'i',
        '0': 'o',
        '5': 's', '$': 's',
        '7': 't'
    }
    
    def __init__(self):
        """Initialize the password analyzer."""
        self._display_security_notice()
    
    def _display_security_notice(self):
        """Display educational use disclaimer."""
        print("=" * 60)
        print("PASSWORD SECURITY ANALYZER")
        print("Educational tool for understanding password strength")
        print("=" * 60)
    
    def calculate_entropy(self, password: str) -> float:
        """
        Calculate Shannon entropy of password.
        
        Args:
            password: Password to analyze
            
        Returns:
            Entropy value in bits
        """
        if not password:
            return 0.0
        
        # Character frequency analysis
        freq_map = Counter(password)
        length = len(password)
        
        # Calculate Shannon entropy: -sum(p * log2(p))
        entropy = 0.0
        for count in freq_map.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        # Total entropy = entropy per character * length
        total_entropy = entropy * length
        
        # Also calculate based on character space
        char_space = self._get_character_space(password)
        if char_space > 0:
            # Theoretical maximum entropy
            max_entropy = length * math.log2(char_space)
            # Return average of Shannon and theoretical entropy
            return (total_entropy + max_entropy) / 2
        
        return total_entropy
    
    def _get_character_space(self, password: str) -> int:
        """
        Determine the character space used in password.
        
        Args:
            password: Password to analyze
            
        Returns:
            Size of character space
        """
        space = 0
        
        if any(c in string.ascii_lowercase for c in password):
            space += 26
        if any(c in string.ascii_uppercase for c in password):
            space += 26
        if any(c in string.digits for c in password):
            space += 10
        if any(c in string.punctuation for c in password):
            space += len(string.punctuation)
        
        return space
    
    def detect_patterns(self, password: str) -> Dict[str, List[str]]:
        """
        Detect common patterns in password.
        
        Args:
            password: Password to analyze
            
        Returns:
            Dictionary of detected patterns
        """
        patterns = {
            'sequences': [],
            'repetitions': [],
            'keyboard': [],
            'dates': [],
            'words': []
        }
        
        password_lower = password.lower()
        
        # Check for sequences (123, abc, etc.)
        sequences = self._find_sequences(password)
        if sequences:
            patterns['sequences'] = sequences
        
        # Check for repetitions (aaa, 111, etc.)
        repetitions = self._find_repetitions(password)
        if repetitions:
            patterns['repetitions'] = repetitions
        
        # Check for keyboard patterns
        for pattern in self.KEYBOARD_PATTERNS:
            if pattern in password_lower:
                patterns['keyboard'].append(pattern)
        
        # Check for date patterns (YYYY, MM/DD, etc.)
        date_patterns = re.findall(r'\b(19|20)\d{2}\b|\b\d{1,2}[/\-\.]\d{1,2}\b', password)
        if date_patterns:
            patterns['dates'] = date_patterns
        
        # Check for dictionary words (simple check)
        words = self._find_dictionary_words(password_lower)
        if words:
            patterns['words'] = words
        
        return patterns
    
    def _find_sequences(self, password: str) -> List[str]:
        """Find sequential characters in password."""
        sequences = []
        
        for i in range(len(password) - 2):
            # Check for numeric sequences
            if password[i:i+3].isdigit():
                if int(password[i+1]) == int(password[i]) + 1 and \
                   int(password[i+2]) == int(password[i+1]) + 1:
                    seq = password[i:i+3]
                    # Extend sequence
                    j = i + 3
                    while j < len(password) and password[j].isdigit() and \
                          int(password[j]) == int(password[j-1]) + 1:
                        seq += password[j]
                        j += 1
                    if len(seq) >= 3:
                        sequences.append(seq)
            
            # Check for alphabetic sequences
            if password[i:i+3].isalpha():
                if ord(password[i+1].lower()) == ord(password[i].lower()) + 1 and \
                   ord(password[i+2].lower()) == ord(password[i+1].lower()) + 1:
                    seq = password[i:i+3]
                    # Extend sequence
                    j = i + 3
                    while j < len(password) and password[j].isalpha() and \
                          ord(password[j].lower()) == ord(password[j-1].lower()) + 1:
                        seq += password[j]
                        j += 1
                    if len(seq) >= 3:
                        sequences.append(seq)
        
        return sequences
    
    def _find_repetitions(self, password: str) -> List[str]:
        """Find repeated characters in password."""
        repetitions = []
        
        i = 0
        while i < len(password):
            char = password[i]
            count = 1
            
            while i + count < len(password) and password[i + count] == char:
                count += 1
            
            if count >= 3:
                repetitions.append(char * count)
            
            i += count
        
        return repetitions
    
    def _find_dictionary_words(self, password: str) -> List[str]:
        """Find common dictionary words in password."""
        found_words = []
        
        # Common English words (simplified list)
        common_words = [
            "password", "admin", "user", "test", "demo", "hello", "world",
            "love", "master", "dragon", "monkey", "shadow", "sunshine",
            "princess", "football", "baseball", "superman", "batman"
        ]
        
        for word in common_words:
            if word in password and len(word) >= 4:
                found_words.append(word)
        
        return found_words
    
    def check_strength(self, password: str) -> Dict[str, any]:
        """
        Check password strength based on OWASP guidelines.
        
        Args:
            password: Password to analyze
            
        Returns:
            Strength assessment dictionary
        """
        results = {
            'score': 0,
            'strength': 'Very Weak',
            'length': len(password),
            'checks': {
                'length': False,
                'uppercase': False,
                'lowercase': False,
                'numbers': False,
                'symbols': False,
                'no_common': False,
                'no_patterns': False,
                'entropy': False
            },
            'suggestions': []
        }
        
        # Length check (OWASP recommends minimum 8)
        if len(password) >= 8:
            results['checks']['length'] = True
            results['score'] += 20
        elif len(password) >= 6:
            results['score'] += 10
            results['suggestions'].append("Increase length to at least 8 characters")
        else:
            results['suggestions'].append("Password too short - use at least 8 characters")
        
        # Character type checks
        if any(c.isupper() for c in password):
            results['checks']['uppercase'] = True
            results['score'] += 15
        else:
            results['suggestions'].append("Add uppercase letters")
        
        if any(c.islower() for c in password):
            results['checks']['lowercase'] = True
            results['score'] += 15
        else:
            results['suggestions'].append("Add lowercase letters")
        
        if any(c.isdigit() for c in password):
            results['checks']['numbers'] = True
            results['score'] += 15
        else:
            results['suggestions'].append("Add numbers")
        
        if any(c in string.punctuation for c in password):
            results['checks']['symbols'] = True
            results['score'] += 15
        else:
            results['suggestions'].append("Add special symbols")
        
        # Check against common passwords
        password_lower = password.lower()
        
        # Remove leet speak for common password check
        deleet = password_lower
        for leet, normal in self.LEET_SUBSTITUTIONS.items():
            deleet = deleet.replace(leet, normal)
        
        if password_lower not in self.COMMON_PASSWORDS and deleet not in self.COMMON_PASSWORDS:
            results['checks']['no_common'] = True
            results['score'] += 10
        else:
            results['suggestions'].append("Avoid common passwords")
            results['score'] -= 20  # Penalty for common password
        
        # Pattern detection
        patterns = self.detect_patterns(password)
        pattern_count = sum(len(v) for v in patterns.values())
        
        if pattern_count == 0:
            results['checks']['no_patterns'] = True
            results['score'] += 10
        else:
            results['suggestions'].append("Avoid predictable patterns")
            results['score'] -= 5 * pattern_count  # Penalty for patterns
        
        # Entropy check
        entropy = self.calculate_entropy(password)
        if entropy >= 50:  # High entropy
            results['checks']['entropy'] = True
            results['score'] += 20
        elif entropy >= 30:  # Medium entropy
            results['score'] += 10
        else:
            results['suggestions'].append("Increase password randomness")
        
        # Determine strength level
        results['score'] = max(0, min(100, results['score']))  # Clamp to 0-100
        
        if results['score'] >= 80:
            results['strength'] = 'Excellent'
        elif results['score'] >= 65:
            results['strength'] = 'Strong'
        elif results['score'] >= 50:
            results['strength'] = 'Good'
        elif results['score'] >= 35:
            results['strength'] = 'Fair'
        elif results['score'] >= 20:
            results['strength'] = 'Weak'
        else:
            results['strength'] = 'Very Weak'
        
        return results
    
    def generate_report(self, password: str) -> str:
        """
        Generate comprehensive security report for password.
        
        Args:
            password: Password to analyze
            
        Returns:
            Formatted report string
        """
        # Mask the actual password for security
        masked_password = password[0] + '*' * (len(password) - 2) + password[-1] if len(password) > 2 else '*' * len(password)
        
        report = []
        report.append("\n" + "=" * 60)
        report.append("PASSWORD SECURITY ANALYSIS REPORT")
        report.append("=" * 60)
        report.append(f"Password (masked): {masked_password}")
        report.append(f"Length: {len(password)} characters")
        
        # Calculate entropy
        entropy = self.calculate_entropy(password)
        report.append(f"\nEntropy: {entropy:.2f} bits")
        
        # Time to crack estimates
        char_space = self._get_character_space(password)
        if char_space > 0:
            combinations = char_space ** len(password)
            # Assuming 1 billion attempts per second
            seconds_to_crack = combinations / 1_000_000_000
            
            report.append(f"Character space: {char_space}")
            report.append(f"Possible combinations: {combinations:.2e}")
            
            if seconds_to_crack < 1:
                report.append("Time to crack: < 1 second")
            elif seconds_to_crack < 60:
                report.append(f"Time to crack: {seconds_to_crack:.0f} seconds")
            elif seconds_to_crack < 3600:
                report.append(f"Time to crack: {seconds_to_crack/60:.1f} minutes")
            elif seconds_to_crack < 86400:
                report.append(f"Time to crack: {seconds_to_crack/3600:.1f} hours")
            elif seconds_to_crack < 31536000:
                report.append(f"Time to crack: {seconds_to_crack/86400:.1f} days")
            else:
                report.append(f"Time to crack: {seconds_to_crack/31536000:.1f} years")
        
        # Pattern detection
        report.append("\n" + "-" * 40)
        report.append("PATTERN ANALYSIS")
        report.append("-" * 40)
        
        patterns = self.detect_patterns(password)
        pattern_found = False
        
        for pattern_type, found_patterns in patterns.items():
            if found_patterns:
                pattern_found = True
                report.append(f"⚠ {pattern_type.capitalize()}: {', '.join(found_patterns)}")
        
        if not pattern_found:
            report.append("✓ No common patterns detected")
        
        # Strength assessment
        report.append("\n" + "-" * 40)
        report.append("STRENGTH ASSESSMENT")
        report.append("-" * 40)
        
        strength = self.check_strength(password)
        
        # Visual strength meter
        meter_length = 30
        filled = int(meter_length * strength['score'] / 100)
        meter = '█' * filled + '░' * (meter_length - filled)
        
        report.append(f"Strength: {strength['strength']}")
        report.append(f"Score: {strength['score']}/100")
        report.append(f"[{meter}]")
        
        # Checklist
        report.append("\nSecurity Checklist:")
        check_symbols = {'✓' if v else '✗' for k, v in strength['checks'].items()}
        
        report.append(f"  {'✓' if strength['checks']['length'] else '✗'} Length >= 8 characters")
        report.append(f"  {'✓' if strength['checks']['uppercase'] else '✗'} Contains uppercase letters")
        report.append(f"  {'✓' if strength['checks']['lowercase'] else '✗'} Contains lowercase letters")
        report.append(f"  {'✓' if strength['checks']['numbers'] else '✗'} Contains numbers")
        report.append(f"  {'✓' if strength['checks']['symbols'] else '✗'} Contains special symbols")
        report.append(f"  {'✓' if strength['checks']['no_common'] else '✗'} Not a common password")
        report.append(f"  {'✓' if strength['checks']['no_patterns'] else '✗'} No predictable patterns")
        report.append(f"  {'✓' if strength['checks']['entropy'] else '✗'} High entropy")
        
        # Suggestions
        if strength['suggestions']:
            report.append("\n" + "-" * 40)
            report.append("SUGGESTIONS FOR IMPROVEMENT")
            report.append("-" * 40)
            for suggestion in strength['suggestions']:
                report.append(f"• {suggestion}")
        
        # OWASP compliance
        report.append("\n" + "-" * 40)
        report.append("OWASP COMPLIANCE")
        report.append("-" * 40)
        
        owasp_compliant = (
            len(password) >= 8 and
            strength['checks']['uppercase'] and
            strength['checks']['lowercase'] and
            strength['checks']['numbers'] and
            strength['checks']['no_common']
        )
        
        if owasp_compliant:
            report.append("✓ Meets OWASP password requirements")
        else:
            report.append("✗ Does not meet OWASP requirements")
            report.append("  OWASP requires: 8+ chars, mixed case, numbers, not common")
        
        report.append("=" * 60)
        
        return '\n'.join(report)
    
    def batch_analyze(self, passwords: List[str]) -> List[Dict]:
        """
        Analyze multiple passwords.
        
        Args:
            passwords: List of passwords to analyze
            
        Returns:
            List of analysis results
        """
        results = []
        
        print(f"\nAnalyzing {len(passwords)} passwords...")
        
        for i, password in enumerate(passwords, 1):
            analysis = {
                'index': i,
                'length': len(password),
                'entropy': self.calculate_entropy(password),
                'strength': self.check_strength(password),
                'patterns': self.detect_patterns(password)
            }
            results.append(analysis)
            
            # Progress indicator
            if i % 10 == 0 or i == len(passwords):
                print(f"Progress: {i}/{len(passwords)}")
        
        return results
    
    def export_analysis(self, password: str, format: str = 'json') -> str:
        """
        Export analysis in various formats.
        
        Args:
            password: Password to analyze
            format: Export format ('json', 'csv', 'text')
            
        Returns:
            Formatted analysis
        """
        analysis = {
            'length': len(password),
            'entropy': self.calculate_entropy(password),
            'strength': self.check_strength(password),
            'patterns': self.detect_patterns(password),
            'character_space': self._get_character_space(password)
        }
        
        if format == 'json':
            return json.dumps(analysis, indent=2)
        
        elif format == 'csv':
            strength = analysis['strength']
            return ','.join([
                str(analysis['length']),
                f"{analysis['entropy']:.2f}",
                strength['strength'],
                str(strength['score']),
                str(len(analysis['patterns']))
            ])
        
        elif format == 'text':
            return self.generate_report(password)
        
        else:
            raise ValueError(f"Unsupported format: {format}")


# Example usage and testing
if __name__ == "__main__":
    analyzer = PasswordAnalyzer()
    
    # Test passwords of varying strength
    test_passwords = [
        "password",          # Very weak - common
        "Password1",         # Weak - predictable
        "P@ssw0rd123",      # Fair - patterns
        "MyS3cur3P@ss!",    # Good
        "Tr0ub4dor&3",      # Strong
        "correct horse battery staple",  # Passphrase
        "xK9#mP2$vL5@nQ8"   # Excellent - random
    ]
    
    print("\n=== Password Security Analysis ===\n")
    
    for password in test_passwords:
        print(f"\nAnalyzing: {'*' * len(password)}")
        print("-" * 40)
        
        # Quick strength check
        strength = analyzer.check_strength(password)
        entropy = analyzer.calculate_entropy(password)
        
        # Visual meter
        meter_length = 20
        filled = int(meter_length * strength['score'] / 100)
        meter = '█' * filled + '░' * (meter_length - filled)
        
        print(f"Strength: {strength['strength']:12} [{meter}] {strength['score']}/100")
        print(f"Entropy:  {entropy:.2f} bits")
        print(f"Length:   {len(password)} characters")
        
        # Show any patterns
        patterns = analyzer.detect_patterns(password)
        pattern_count = sum(len(v) for v in patterns.values())
        if pattern_count > 0:
            print(f"⚠ Warning: {pattern_count} patterns detected")
    
    # Generate full report for one password
    print("\n" + "=" * 60)
    print("DETAILED REPORT EXAMPLE")
    print(analyzer.generate_report("P@ssw0rd123"))