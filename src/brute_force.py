"""
Brute Force Attack Module
Educational Cybersecurity Toolkit - For authorized educational use only
Implements systematic password generation and brute force cracking

Author: Aniket886
GitHub: https://github.com/Aniket886
Project: Educational Cybersecurity Toolkit
Created: 2025
"""

import itertools
import string
import time
import hashlib
import bcrypt
import base64
import json
import os
import threading
from typing import List, Dict, Optional, Iterator, Tuple
from datetime import datetime, timedelta
import pickle


class BruteForceAttacker:
    """
    Brute force password cracking implementation.
    Systematically generates all possible combinations within constraints.
    """
    
    CHARSETS = {
        'lowercase': string.ascii_lowercase,
        'uppercase': string.ascii_uppercase,
        'digits': string.digits,
        'safe_symbols': '!@#$%&*-_=+',
        'alphanumeric': string.ascii_letters + string.digits,
        'alpha': string.ascii_letters,
        'common': string.ascii_lowercase + string.digits,  # Most common charset
        'full': string.ascii_letters + string.digits + '!@#$%&*-_=+'
    }
    
    MAX_PASSWORD_LENGTH = 8  # Safety limit
    RATE_LIMIT = 1000  # attempts per second
    CHECKPOINT_INTERVAL = 10000  # Save progress every N attempts
    
    def __init__(self):
        """Initialize brute force attacker."""
        self.attempts = 0
        self.found = False
        self.found_password = None
        self.start_time = None
        self.checkpoint_file = None
        self.current_state = None
        self._display_security_notice()
    
    def _display_security_notice(self):
        """Display educational use disclaimer."""
        print("=" * 60)
        print("BRUTE FORCE ATTACK MODULE")
        print("EDUCATIONAL PURPOSE ONLY - AUTHORIZED USE REQUIRED")
        print("Rate limited and length restricted for safety")
        print("Maximum password length: 8 characters")
        print("=" * 60)
    
    def get_charset(self, charset_config: str) -> str:
        """
        Get character set based on configuration.
        
        Args:
            charset_config: Name of charset or custom string
            
        Returns:
            Character set string
        """
        if charset_config in self.CHARSETS:
            return self.CHARSETS[charset_config]
        else:
            # Custom charset provided
            return charset_config
    
    def calculate_combinations(self, charset: str, min_len: int, max_len: int) -> int:
        """
        Calculate total number of possible combinations.
        
        Args:
            charset: Character set
            min_len: Minimum password length
            max_len: Maximum password length
            
        Returns:
            Total combinations count
        """
        total = 0
        charset_size = len(charset)
        
        for length in range(min_len, max_len + 1):
            total += charset_size ** length
        
        return total
    
    def generate_combinations(self, charset: str, min_len: int = 1, 
                            max_len: int = 6) -> Iterator[str]:
        """
        Generate all possible combinations systematically.
        
        Args:
            charset: Characters to use
            min_len: Minimum length
            max_len: Maximum length
            
        Yields:
            Password combinations
        """
        # Enforce safety limits
        max_len = min(max_len, self.MAX_PASSWORD_LENGTH)
        
        if not charset:
            raise ValueError("Charset cannot be empty")
        
        # Sort charset for consistent ordering
        charset = ''.join(sorted(set(charset)))
        
        print(f"Generating combinations:")
        print(f"  Charset: {charset[:20]}{'...' if len(charset) > 20 else ''}")
        print(f"  Charset size: {len(charset)} characters")
        print(f"  Length range: {min_len}-{max_len}")
        
        total = self.calculate_combinations(charset, min_len, max_len)
        print(f"  Total combinations: {total:,}")
        
        # Generate combinations by length
        for length in range(min_len, max_len + 1):
            print(f"\nTrying length {length}...")
            
            # Use itertools.product for systematic generation
            for combo in itertools.product(charset, repeat=length):
                password = ''.join(combo)
                yield password
    
    def _hash_password(self, password: str, algorithm: str, salt: bytes = None) -> str:
        """
        Hash a password using specified algorithm.
        
        Args:
            password: Password to hash
            algorithm: Hash algorithm
            salt: Salt bytes
            
        Returns:
            Hash string
        """
        if algorithm == 'md5':
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
            target_hash: Target hash
            algorithm: Hash algorithm
            salt: Salt (base64 encoded)
            
        Returns:
            True if match
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
    
    def crack_hash(self, target_hash: str, charset_config: str = 'common',
                   min_len: int = 1, max_len: int = 6,
                   algorithm: str = 'sha256', salt: str = None) -> Optional[str]:
        """
        Attempt to crack hash using brute force.
        
        Args:
            target_hash: Hash to crack
            charset_config: Character set configuration
            min_len: Minimum password length
            max_len: Maximum password length
            algorithm: Hash algorithm
            salt: Salt if applicable
            
        Returns:
            Cracked password if found
        """
        # Get character set
        charset = self.get_charset(charset_config)
        max_len = min(max_len, self.MAX_PASSWORD_LENGTH)
        
        print(f"\nStarting brute force attack...")
        print(f"Target hash: {target_hash[:32]}...")
        print(f"Algorithm: {algorithm}")
        print("-" * 40)
        
        # Reset state
        self.found = False
        self.found_password = None
        self.attempts = 0
        self.start_time = time.time()
        
        # Check for checkpoint
        checkpoint_data = self.load_checkpoint(target_hash)
        if checkpoint_data:
            print(f"Resuming from checkpoint (attempt {checkpoint_data['attempts']})")
            self.attempts = checkpoint_data['attempts']
            min_len = checkpoint_data.get('current_length', min_len)
        
        # Generate and test combinations
        try:
            for password in self.generate_combinations(charset, min_len, max_len):
                self.attempts += 1
                
                # Rate limiting
                if self.attempts % self.RATE_LIMIT == 0:
                    time.sleep(1)
                
                # Check password
                if self._check_password(password, target_hash, algorithm, salt):
                    self.found = True
                    self.found_password = password
                    print(f"\n✓ PASSWORD FOUND: {password}")
                    break
                
                # Progress update
                if self.attempts % 1000 == 0:
                    self._show_progress(password)
                
                # Checkpoint
                if self.attempts % self.CHECKPOINT_INTERVAL == 0:
                    self.save_checkpoint({
                        'target_hash': target_hash,
                        'attempts': self.attempts,
                        'current_password': password,
                        'current_length': len(password),
                        'charset': charset_config,
                        'algorithm': algorithm
                    })
        
        except KeyboardInterrupt:
            print("\n\nAttack interrupted by user")
            self.save_checkpoint({
                'target_hash': target_hash,
                'attempts': self.attempts,
                'charset': charset_config,
                'algorithm': algorithm
            })
        
        # Final results
        elapsed = time.time() - self.start_time
        print(f"\n{'=' * 40}")
        print(f"Attack completed in {elapsed:.2f} seconds")
        print(f"Total attempts: {self.attempts:,}")
        print(f"Rate: {self.attempts / elapsed:.0f} attempts/second")
        
        if self.found:
            print(f"✓ SUCCESS: Password = '{self.found_password}'")
            self._save_result(target_hash, self.found_password, algorithm, elapsed)
        else:
            print("✗ Password not found in search space")
        
        return self.found_password
    
    def save_checkpoint(self, state: Dict):
        """
        Save current attack state for resume capability.
        
        Args:
            state: Current state dictionary
        """
        checkpoint_dir = 'password_toolkit/checkpoints'
        os.makedirs(checkpoint_dir, exist_ok=True)
        
        # Use hash as filename for uniqueness
        hash_prefix = state['target_hash'][:10]
        filename = f"{checkpoint_dir}/brute_force_{hash_prefix}.checkpoint"
        
        try:
            with open(filename, 'w') as f:
                json.dump(state, f, indent=2)
            
            print(f"\nCheckpoint saved: {filename}")
            
        except Exception as e:
            print(f"Could not save checkpoint: {str(e)}")
    
    def load_checkpoint(self, target_hash: str) -> Optional[Dict]:
        """
        Load checkpoint for resuming attack.
        
        Args:
            target_hash: Hash being attacked
            
        Returns:
            Checkpoint data if exists
        """
        checkpoint_dir = 'password_toolkit/checkpoints'
        hash_prefix = target_hash[:10]
        filename = f"{checkpoint_dir}/brute_force_{hash_prefix}.checkpoint"
        
        if os.path.exists(filename):
            try:
                with open(filename, 'r') as f:
                    data = json.load(f)
                
                print(f"Found checkpoint: {filename}")
                
                # Ask user if they want to resume
                response = input("Resume from checkpoint? (y/n): ").lower()
                if response == 'y':
                    return data
                else:
                    # Delete old checkpoint
                    os.remove(filename)
                    print("Starting fresh attack")
                    
            except Exception as e:
                print(f"Could not load checkpoint: {str(e)}")
        
        return None
    
    def _show_progress(self, current_password: str):
        """
        Display progress information.
        
        Args:
            current_password: Current password being tested
        """
        elapsed = time.time() - self.start_time
        rate = self.attempts / elapsed if elapsed > 0 else 0
        
        print(f"\rAttempts: {self.attempts:,} | "
              f"Current: {current_password:8} | "
              f"Rate: {rate:.0f}/s | "
              f"Time: {elapsed:.0f}s", end='', flush=True)
    
    def _save_result(self, hash_value: str, password: str, 
                    algorithm: str, time_taken: float):
        """
        Save successful crack result.
        
        Args:
            hash_value: Cracked hash
            password: Found password
            algorithm: Algorithm used
            time_taken: Time to crack
        """
        result = {
            'timestamp': datetime.now().isoformat(),
            'hash': hash_value[:50] + '...' if len(hash_value) > 50 else hash_value,
            'password': password,
            'algorithm': algorithm,
            'time_seconds': round(time_taken, 2),
            'attempts': self.attempts,
            'method': 'brute_force'
        }
        
        # Ensure results directory exists
        os.makedirs('password_toolkit/results', exist_ok=True)
        
        # Save to JSON file
        filename = f"password_toolkit/results/brute_force_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"Result saved to: {filename}")
        except Exception as e:
            print(f"Could not save result: {str(e)}")
    
    def estimate_time(self, charset: str, min_len: int, max_len: int, 
                     rate: int = 1000) -> str:
        """
        Estimate time to complete brute force attack.
        
        Args:
            charset: Character set
            min_len: Minimum length
            max_len: Maximum length
            rate: Attempts per second
            
        Returns:
            Time estimate string
        """
        total = self.calculate_combinations(charset, min_len, max_len)
        seconds = total / rate
        
        # Convert to human readable format
        if seconds < 60:
            return f"{seconds:.0f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        else:
            return f"{seconds/31536000:.1f} years"
    
    def smart_attack(self, target_hash: str, algorithm: str = 'sha256',
                    salt: str = None) -> Optional[str]:
        """
        Smart brute force with optimized character ordering.
        
        Args:
            target_hash: Hash to crack
            algorithm: Hash algorithm
            salt: Salt if applicable
            
        Returns:
            Cracked password if found
        """
        # Try common patterns first
        strategies = [
            ('digits', 1, 4),           # PIN codes
            ('lowercase', 1, 4),        # Simple words
            ('common', 1, 5),           # Common alphanumeric
            ('alphanumeric', 1, 6),    # Full alphanumeric
        ]
        
        print("\nUsing smart brute force strategy...")
        
        for charset_name, min_len, max_len in strategies:
            print(f"\n→ Trying {charset_name} (length {min_len}-{max_len})")
            
            result = self.crack_hash(
                target_hash, charset_name,
                min_len, max_len, algorithm, salt
            )
            
            if result:
                return result
        
        return None
    
    def benchmark(self, max_attempts: int = 10000) -> Dict[str, float]:
        """
        Benchmark brute force performance.
        
        Args:
            max_attempts: Maximum attempts for benchmark
            
        Returns:
            Performance statistics
        """
        print("\nRunning brute force benchmark...")
        
        # Generate test hash
        test_password = "test"
        test_hash = hashlib.sha256(test_password.encode()).hexdigest()
        
        start = time.time()
        attempts = 0
        
        for password in self.generate_combinations('lowercase', 1, 4):
            attempts += 1
            self._check_password(password, test_hash, 'sha256')
            
            if attempts >= max_attempts or password == test_password:
                break
        
        elapsed = time.time() - start
        
        stats = {
            'attempts': attempts,
            'time': elapsed,
            'rate': attempts / elapsed if elapsed > 0 else 0
        }
        
        print(f"\nBenchmark Results:")
        print(f"  Attempts: {stats['attempts']:,}")
        print(f"  Time: {stats['time']:.2f}s")
        print(f"  Rate: {stats['rate']:.0f} attempts/second")
        
        return stats


# Example usage and testing
if __name__ == "__main__":
    attacker = BruteForceAttacker()
    
    print("\n=== Brute Force Time Estimates ===")
    # Show time estimates for different configurations
    configs = [
        ('digits', 4, 4, "4-digit PIN"),
        ('lowercase', 1, 4, "Lowercase 1-4 chars"),
        ('alphanumeric', 1, 6, "Alphanumeric 1-6 chars"),
        ('full', 1, 8, "Full charset 1-8 chars")
    ]
    
    for charset, min_len, max_len, desc in configs:
        charset_str = attacker.get_charset(charset)
        estimate = attacker.estimate_time(charset_str, min_len, max_len)
        total = attacker.calculate_combinations(charset_str, min_len, max_len)
        print(f"{desc:25} → {total:15,} combinations → {estimate}")
    
    # Test with a simple password
    print("\n=== Brute Force Attack Test ===")
    test_password = "abc"
    test_hash = hashlib.sha256(test_password.encode()).hexdigest()
    
    print(f"Test password: {test_password}")
    print(f"Test hash: {test_hash[:32]}...")
    
    result = attacker.crack_hash(
        test_hash, 
        charset_config='lowercase',
        min_len=1,
        max_len=3,
        algorithm='sha256'
    )
    
    if result:
        print(f"\n✓ Successfully cracked: {result}")
    else:
        print("\n✗ Failed to crack password")
    
    # Run benchmark
    print("\n=== Performance Benchmark ===")
    attacker.benchmark(10000)