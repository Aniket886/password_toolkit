"""
Dictionary Attack Module
Educational Cybersecurity Toolkit - For authorized educational use only
Implements dictionary-based password cracking with rule variations

Author: Aniket886
GitHub: https://github.com/Aniket886
Project: Educational Cybersecurity Toolkit
Created: 2025
"""

import threading
import time
import os
import hashlib
import bcrypt
import base64
from typing import List, Dict, Optional, Tuple, Callable
from queue import Queue
from datetime import datetime, timedelta
import json


class DictionaryAttacker:
    """
    Dictionary-based password cracking implementation.
    Uses wordlists and rule-based variations to crack password hashes.
    """
    
    MAX_THREADS = 4
    RATE_LIMIT = 1000  # attempts per second
    
    def __init__(self, thread_count: int = 4):
        """
        Initialize dictionary attacker.
        
        Args:
            thread_count: Number of threads to use (max 4)
        """
        self.thread_count = min(thread_count, self.MAX_THREADS)
        self.wordlist = []
        self.attempts = 0
        self.found = False
        self.found_password = None
        self.start_time = None
        self.queue = Queue()
        self.lock = threading.Lock()
        self._display_security_notice()
    
    def _display_security_notice(self):
        """Display educational use disclaimer."""
        print("=" * 60)
        print("DICTIONARY ATTACK MODULE")
        print("EDUCATIONAL PURPOSE ONLY - AUTHORIZED USE REQUIRED")
        print("Rate limited to prevent misuse")
        print("=" * 60)
    
    def load_wordlist(self, filename: str, max_words: int = None, skip_comments: bool = True) -> int:
        """
        Load wordlist from file.
        
        Args:
            filename: Path to wordlist file
            max_words: Maximum number of words to load
            skip_comments: Skip lines starting with #
            
        Returns:
            Number of words loaded
        """
        self.wordlist = []
        
        if not os.path.exists(filename):
            raise FileNotFoundError(f"Wordlist file not found: {filename}")
        
        print(f"Loading wordlist from {filename}...")
        
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    word = line.strip()
                    # Skip empty lines and comments if enabled
                    if word and not (skip_comments and word.startswith('#')):
                        # Remove duplicates
                        if word not in self.wordlist:
                            self.wordlist.append(word)
                    
                    # Progress indicator
                    if line_num % 10000 == 0:
                        print(f"  Loaded {line_num} lines, {len(self.wordlist)} unique words...")
                    
                    if max_words and len(self.wordlist) >= max_words:
                        break
            
            print(f"✓ Loaded {len(self.wordlist)} unique words from wordlist")
            return len(self.wordlist)
            
        except Exception as e:
            raise Exception(f"Error loading wordlist: {str(e)}")
    
    def generate_wordlist(self, base_words: List[str]) -> List[str]:
        """
        Generate a wordlist from base words (for testing).
        
        Args:
            base_words: List of base words
            
        Returns:
            Generated wordlist
        """
        self.wordlist = base_words
        return self.wordlist
    
    def apply_rules(self, password: str) -> List[str]:
        """
        Apply rule-based variations to generate password candidates.
        
        Args:
            password: Base password
            
        Returns:
            List of password variations
        """
        variations = [password]  # Include original
        
        # Leet speak substitutions
        leet_map = {
            'a': ['@', '4'],
            'e': ['3'],
            'i': ['1', '!'],
            'o': ['0'],
            's': ['5', '$'],
            'l': ['1'],
            't': ['7'],
            'g': ['9']
        }
        
        # Generate leet variations
        leet_variant = password.lower()
        for char, replacements in leet_map.items():
            for replacement in replacements:
                if char in leet_variant:
                    variations.append(leet_variant.replace(char, replacement))
        
        # Case variations
        variations.extend([
            password.lower(),
            password.upper(),
            password.capitalize(),
            password.swapcase()
        ])
        
        # If password is all lowercase, try title case
        if password.islower():
            variations.append(password.title())
        
        # Number appending (common patterns)
        base_variations = variations.copy()
        for base in base_variations[:5]:  # Limit to prevent explosion
            # Common numbers
            for num in ['1', '12', '123', '1234', '2', '69', '420', '007', '99', '2000']:
                variations.append(base + num)
            
            # Years
            for year in range(1990, 2026):
                variations.append(base + str(year))
            
            # Common suffixes
            for suffix in ['!', '@', '#', '!!', '123!', '!@#']:
                variations.append(base + suffix)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_variations = []
        for var in variations:
            if var not in seen:
                seen.add(var)
                unique_variations.append(var)
        
        return unique_variations
    
    def _hash_password(self, password: str, algorithm: str, salt: bytes = None) -> str:
        """
        Hash a password using specified algorithm.
        
        Args:
            password: Password to hash
            algorithm: Hash algorithm
            salt: Salt bytes (for non-bcrypt algorithms)
            
        Returns:
            Hash string
        """
        if algorithm == 'bcrypt':
            # For testing against bcrypt, we can't generate the exact hash
            # This is placeholder - in real use, we'd compare using bcrypt.checkpw
            return None
        
        elif algorithm == 'md5':
            if salt:
                return hashlib.md5(salt + password.encode()).hexdigest()
            return hashlib.md5(password.encode()).hexdigest()
        
        elif algorithm == 'sha256':
            if salt:
                return hashlib.sha256(salt + password.encode()).hexdigest()
            return hashlib.sha256(password.encode()).hexdigest()
        
        elif algorithm == 'sha512':
            if salt:
                return hashlib.sha512(salt + password.encode()).hexdigest()
            return hashlib.sha512(password.encode()).hexdigest()
        
        return None
    
    def _check_password(self, password: str, target_hash: str, 
                       algorithm: str, salt: str = None) -> bool:
        """
        Check if password matches target hash.
        
        Args:
            password: Password to test
            target_hash: Target hash to match
            algorithm: Hash algorithm
            salt: Salt (base64 encoded for non-bcrypt)
            
        Returns:
            True if match, False otherwise
        """
        try:
            if algorithm == 'bcrypt':
                return bcrypt.checkpw(password.encode(), target_hash.encode())
            
            else:
                salt_bytes = None
                if salt and salt != 'none':
                    try:
                        salt_bytes = base64.b64decode(salt)
                    except:
                        salt_bytes = salt.encode() if isinstance(salt, str) else salt
                
                test_hash = self._hash_password(password, algorithm, salt_bytes)
                return test_hash == target_hash
                
        except Exception:
            return False
    
    def _worker_thread(self, target_hash: str, algorithm: str, 
                      salt: str = None, use_rules: bool = True):
        """
        Worker thread for parallel password checking.
        
        Args:
            target_hash: Target hash to crack
            algorithm: Hash algorithm
            salt: Salt for hash
            use_rules: Whether to apply rule variations
        """
        while not self.found:
            # Get password from queue
            try:
                password = self.queue.get(timeout=1)
            except:
                break
            
            if password is None:
                break
            
            # Rate limiting
            with self.lock:
                self.attempts += 1
                if self.attempts % self.RATE_LIMIT == 0:
                    time.sleep(1)
            
            # Generate variations if rules enabled
            candidates = self.apply_rules(password) if use_rules else [password]
            
            # Test each candidate
            for candidate in candidates:
                if self._check_password(candidate, target_hash, algorithm, salt):
                    with self.lock:
                        self.found = True
                        self.found_password = candidate
                        print(f"\n✓ PASSWORD FOUND: {candidate}")
                        return
            
            self.queue.task_done()
    
    def crack_hash(self, target_hash: str, algorithm: str = 'sha256', 
                   salt: str = None, use_rules: bool = True) -> Optional[str]:
        """
        Attempt to crack a hash using dictionary attack.
        
        Args:
            target_hash: Hash to crack
            algorithm: Hash algorithm
            salt: Salt (if applicable)
            use_rules: Apply rule-based variations
            
        Returns:
            Cracked password if found, None otherwise
        """
        if not self.wordlist:
            raise ValueError("No wordlist loaded. Call load_wordlist() first.")
        
        print(f"\nStarting dictionary attack...")
        print(f"Target hash: {target_hash[:32]}...")
        print(f"Algorithm: {algorithm}")
        print(f"Wordlist size: {len(self.wordlist)} words")
        print(f"Rules enabled: {use_rules}")
        print(f"Threads: {self.thread_count}")
        print("-" * 40)
        
        # Reset state
        self.found = False
        self.found_password = None
        self.attempts = 0
        self.start_time = time.time()
        
        # Fill queue with passwords
        for password in self.wordlist:
            self.queue.put(password)
        
        # Add sentinel values for threads
        for _ in range(self.thread_count):
            self.queue.put(None)
        
        # Start worker threads
        threads = []
        for _ in range(self.thread_count):
            t = threading.Thread(
                target=self._worker_thread,
                args=(target_hash, algorithm, salt, use_rules)
            )
            t.start()
            threads.append(t)
        
        # Monitor progress
        last_update = time.time()
        while any(t.is_alive() for t in threads):
            current_time = time.time()
            if current_time - last_update >= 1:  # Update every second
                self._show_progress()
                last_update = current_time
            
            if self.found:
                break
            
            time.sleep(0.1)
        
        # Wait for threads to finish
        for t in threads:
            t.join()
        
        # Final status
        elapsed = time.time() - self.start_time
        print(f"\n{'=' * 40}")
        print(f"Attack completed in {elapsed:.2f} seconds")
        print(f"Total attempts: {self.attempts}")
        print(f"Rate: {self.attempts / elapsed:.0f} attempts/second")
        
        if self.found:
            print(f"✓ SUCCESS: Password = '{self.found_password}'")
            self._save_result(target_hash, self.found_password, algorithm, elapsed)
        else:
            print("✗ Password not found in wordlist")
        
        return self.found_password
    
    def attack_with_progress(self, target_hash: str, algorithm: str = 'sha256',
                           salt: str = None) -> Optional[str]:
        """
        Attack with real-time progress tracking and ETA.
        
        Args:
            target_hash: Hash to crack
            algorithm: Hash algorithm
            salt: Salt if applicable
            
        Returns:
            Cracked password if found
        """
        return self.crack_hash(target_hash, algorithm, salt, use_rules=True)
    
    def _show_progress(self):
        """Display progress with ETA calculation."""
        if not self.start_time:
            return
        
        elapsed = time.time() - self.start_time
        rate = self.attempts / elapsed if elapsed > 0 else 0
        
        # Estimate remaining time
        remaining_words = len(self.wordlist) - self.attempts
        if rate > 0:
            eta_seconds = remaining_words / rate
            eta = timedelta(seconds=int(eta_seconds))
        else:
            eta = "Unknown"
        
        # Progress bar
        progress = min(self.attempts / len(self.wordlist) * 100, 100)
        bar_length = 30
        filled = int(bar_length * progress / 100)
        bar = '█' * filled + '░' * (bar_length - filled)
        
        print(f"\r[{bar}] {progress:.1f}% | "
              f"Attempts: {self.attempts} | "
              f"Rate: {rate:.0f}/s | "
              f"ETA: {eta}", end='', flush=True)
    
    def _save_result(self, hash_value: str, password: str, 
                    algorithm: str, time_taken: float):
        """
        Save successful crack result.
        
        Args:
            hash_value: Cracked hash
            password: Found password
            algorithm: Algorithm used
            time_taken: Time to crack in seconds
        """
        result = {
            'timestamp': datetime.now().isoformat(),
            'hash': hash_value[:50] + '...' if len(hash_value) > 50 else hash_value,
            'password': password,
            'algorithm': algorithm,
            'time_seconds': round(time_taken, 2),
            'attempts': self.attempts,
            'method': 'dictionary'
        }
        
        # Ensure results directory exists
        os.makedirs('password_toolkit/results', exist_ok=True)
        
        # Save to JSON file
        filename = f"password_toolkit/results/crack_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"Result saved to: {filename}")
        except Exception as e:
            print(f"Could not save result: {str(e)}")
    
    def benchmark(self, num_passwords: int = 100) -> Dict[str, float]:
        """
        Benchmark dictionary attack performance.
        
        Args:
            num_passwords: Number of test passwords
            
        Returns:
            Performance statistics
        """
        print("\nRunning benchmark...")
        
        # Generate test data
        test_passwords = [f"test{i}" for i in range(num_passwords)]
        self.wordlist = test_passwords
        
        # Test hash (SHA256 of "test50")
        test_hash = hashlib.sha256("test50".encode()).hexdigest()
        
        start = time.time()
        result = self.crack_hash(test_hash, 'sha256', use_rules=False)
        elapsed = time.time() - start
        
        stats = {
            'total_time': elapsed,
            'passwords_tested': self.attempts,
            'rate': self.attempts / elapsed if elapsed > 0 else 0,
            'found': result is not None
        }
        
        print(f"\nBenchmark Results:")
        print(f"  Passwords tested: {stats['passwords_tested']}")
        print(f"  Time: {stats['total_time']:.2f}s")
        print(f"  Rate: {stats['rate']:.0f} passwords/second")
        
        return stats


# Example usage and testing
if __name__ == "__main__":
    attacker = DictionaryAttacker(thread_count=4)
    
    # Generate sample wordlist for testing
    sample_words = [
        "password", "123456", "admin", "test", "user",
        "Password123", "qwerty", "letmein", "monkey", "dragon",
        "master", "hello", "freedom", "whatever", "shadow"
    ]
    
    attacker.generate_wordlist(sample_words)
    
    # Test with known password hash
    # Hash of "Password123" with SHA256
    test_hash = hashlib.sha256("Password123".encode()).hexdigest()
    
    print("\n=== Dictionary Attack Test ===")
    result = attacker.crack_hash(test_hash, algorithm='sha256', use_rules=True)
    
    if result:
        print(f"\n✓ Successfully cracked password: {result}")
    else:
        print("\n✗ Failed to crack password")
    
    # Run benchmark
    print("\n=== Performance Benchmark ===")
    attacker.benchmark(100)