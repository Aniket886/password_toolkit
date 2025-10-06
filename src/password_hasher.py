"""
Password Hashing Engine
Educational Cybersecurity Toolkit - For authorized educational use only
Implements secure password hashing with multiple algorithms

Author: Aniket886
GitHub: https://github.com/Aniket886
Project: Educational Cybersecurity Toolkit
Created: 2025
"""

import bcrypt
import hashlib
import os
import secrets
import base64
import warnings
from typing import List, Tuple, Optional, Dict, Union


class PasswordHasher:
    """
    Secure password hashing implementation supporting multiple algorithms.
    Primary focus on bcrypt for production use, with legacy algorithm support
    for educational purposes.
    """
    
    SUPPORTED_ALGORITHMS = ['bcrypt', 'sha256', 'sha512', 'md5', 'pbkdf2']
    DEFAULT_BCRYPT_ROUNDS = 12
    DEFAULT_PBKDF2_ITERATIONS = 100000
    SALT_LENGTH = 32  # bytes
    
    def __init__(self):
        """Initialize the password hasher with security warnings."""
        self.hashes_generated = 0
        self._display_security_notice()
    
    def _display_security_notice(self):
        """Display educational use disclaimer."""
        print("=" * 60)
        print("EDUCATIONAL CYBERSECURITY TOOLKIT")
        print("FOR AUTHORIZED USE ONLY")
        print("This tool is for learning about password security")
        print("Never use on systems you don't own or without permission")
        print("=" * 60)
    
    def generate_salt(self) -> bytes:
        """
        Generate cryptographically secure random salt.
        
        Returns:
            bytes: Secure random salt
        """
        return os.urandom(self.SALT_LENGTH)
    
    def hash_password(self, password: str, algorithm: str = 'bcrypt', 
                     rounds: int = DEFAULT_BCRYPT_ROUNDS) -> Dict[str, str]:
        """
        Hash a password using the specified algorithm.
        
        Args:
            password: Plain text password to hash
            algorithm: Hashing algorithm to use
            rounds: Number of rounds for bcrypt (4-16)
            
        Returns:
            Dictionary containing hash, algorithm, and metadata
        """
        if not password:
            raise ValueError("Password cannot be empty")
        
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Security warning for weak algorithms
        if algorithm in ['md5']:
            warnings.warn(
                "MD5 is cryptographically broken and should NOT be used in production. "
                "This is for educational purposes only!",
                category=UserWarning
            )
        
        result = {
            'algorithm': algorithm,
            'hash': '',
            'salt': '',
            'metadata': {}
        }
        
        if algorithm == 'bcrypt':
            # Ensure rounds are within valid range
            rounds = max(4, min(16, rounds))
            result['metadata']['rounds'] = rounds
            
            # bcrypt handles its own salt generation
            salt = bcrypt.gensalt(rounds=rounds)
            hash_bytes = bcrypt.hashpw(password.encode('utf-8'), salt)
            result['hash'] = hash_bytes.decode('utf-8')
            result['salt'] = 'embedded'  # bcrypt embeds salt in hash
            
        elif algorithm == 'sha256':
            salt = self.generate_salt()
            hash_obj = hashlib.sha256()
            hash_obj.update(salt + password.encode('utf-8'))
            result['hash'] = hash_obj.hexdigest()
            result['salt'] = base64.b64encode(salt).decode('utf-8')
            
        elif algorithm == 'sha512':
            salt = self.generate_salt()
            hash_obj = hashlib.sha512()
            hash_obj.update(salt + password.encode('utf-8'))
            result['hash'] = hash_obj.hexdigest()
            result['salt'] = base64.b64encode(salt).decode('utf-8')
            
        elif algorithm == 'md5':
            salt = self.generate_salt()
            hash_obj = hashlib.md5()
            hash_obj.update(salt + password.encode('utf-8'))
            result['hash'] = hash_obj.hexdigest()
            result['salt'] = base64.b64encode(salt).decode('utf-8')
            
        elif algorithm == 'pbkdf2':
            salt = self.generate_salt()
            iterations = self.DEFAULT_PBKDF2_ITERATIONS
            hash_bytes = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                iterations
            )
            result['hash'] = base64.b64encode(hash_bytes).decode('utf-8')
            result['salt'] = base64.b64encode(salt).decode('utf-8')
            result['metadata']['iterations'] = iterations
        
        self.hashes_generated += 1
        return result
    
    def verify_password(self, password: str, stored_hash: str, 
                       algorithm: str = 'bcrypt', salt: str = None) -> bool:
        """
        Verify a password against a stored hash.
        
        Args:
            password: Plain text password to verify
            stored_hash: Previously generated hash
            algorithm: Algorithm used for hashing
            salt: Salt used (if not embedded in hash)
            
        Returns:
            bool: True if password matches, False otherwise
        """
        if algorithm == 'bcrypt':
            try:
                return bcrypt.checkpw(
                    password.encode('utf-8'), 
                    stored_hash.encode('utf-8')
                )
            except Exception:
                return False
                
        elif algorithm in ['sha256', 'sha512', 'md5']:
            if not salt:
                raise ValueError(f"Salt required for {algorithm} verification")
            
            salt_bytes = base64.b64decode(salt.encode('utf-8'))
            
            if algorithm == 'sha256':
                hash_obj = hashlib.sha256()
            elif algorithm == 'sha512':
                hash_obj = hashlib.sha512()
            else:  # md5
                hash_obj = hashlib.md5()
            
            hash_obj.update(salt_bytes + password.encode('utf-8'))
            calculated_hash = hash_obj.hexdigest()
            
            # Constant time comparison to prevent timing attacks
            return secrets.compare_digest(calculated_hash, stored_hash)
            
        elif algorithm == 'pbkdf2':
            if not salt:
                raise ValueError("Salt required for PBKDF2 verification")
            
            salt_bytes = base64.b64decode(salt.encode('utf-8'))
            stored_hash_bytes = base64.b64decode(stored_hash.encode('utf-8'))
            
            calculated_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt_bytes,
                self.DEFAULT_PBKDF2_ITERATIONS
            )
            
            return secrets.compare_digest(calculated_hash, stored_hash_bytes)
        
        return False
    
    def batch_hash(self, password_list: List[str], algorithm: str = 'bcrypt',
                   rounds: int = DEFAULT_BCRYPT_ROUNDS) -> List[Dict[str, str]]:
        """
        Efficiently hash multiple passwords.
        
        Args:
            password_list: List of passwords to hash
            algorithm: Hashing algorithm to use
            rounds: Number of rounds for bcrypt
            
        Returns:
            List of hash dictionaries
        """
        results = []
        total = len(password_list)
        
        print(f"\nBatch hashing {total} passwords with {algorithm}...")
        
        for i, password in enumerate(password_list, 1):
            try:
                hash_result = self.hash_password(password, algorithm, rounds)
                results.append(hash_result)
                
                # Progress indicator
                if i % 10 == 0 or i == total:
                    progress = (i / total) * 100
                    print(f"Progress: {i}/{total} ({progress:.1f}%)")
                    
            except Exception as e:
                print(f"Error hashing password {i}: {str(e)}")
                results.append({'error': str(e), 'password_index': i})
        
        return results
    
    def compare_algorithms(self, password: str) -> Dict[str, Dict]:
        """
        Hash the same password with all supported algorithms for comparison.
        
        Args:
            password: Password to hash
            
        Returns:
            Dictionary of results for each algorithm
        """
        results = {}
        
        print("\nComparing hash algorithms...")
        print("-" * 40)
        
        for algo in self.SUPPORTED_ALGORITHMS:
            try:
                import time
                start_time = time.time()
                
                if algo == 'bcrypt':
                    result = self.hash_password(password, algo, rounds=12)
                else:
                    result = self.hash_password(password, algo)
                
                elapsed = time.time() - start_time
                
                results[algo] = {
                    'hash': result['hash'],
                    'hash_length': len(result['hash']),
                    'time_ms': round(elapsed * 1000, 3),
                    'secure': algo in ['bcrypt', 'pbkdf2'],
                    'salt': result['salt']
                }
                
                print(f"{algo.upper()}:")
                print(f"  Hash Length: {results[algo]['hash_length']} chars")
                print(f"  Time: {results[algo]['time_ms']}ms")
                print(f"  Secure: {'✓' if results[algo]['secure'] else '✗ (Legacy)'}")
                
            except Exception as e:
                results[algo] = {'error': str(e)}
                print(f"{algo.upper()}: Error - {str(e)}")
        
        return results
    
    def export_hash(self, hash_dict: Dict[str, str], format: str = 'json') -> str:
        """
        Export hash in various formats.
        
        Args:
            hash_dict: Hash dictionary from hash_password()
            format: Export format ('json', 'csv', 'text')
            
        Returns:
            Formatted hash string
        """
        if format == 'json':
            import json
            return json.dumps(hash_dict, indent=2)
        
        elif format == 'csv':
            parts = [
                hash_dict.get('algorithm', ''),
                hash_dict.get('hash', ''),
                hash_dict.get('salt', ''),
                str(hash_dict.get('metadata', {}))
            ]
            return ','.join(parts)
        
        elif format == 'text':
            lines = [
                f"Algorithm: {hash_dict.get('algorithm', 'unknown')}",
                f"Hash: {hash_dict.get('hash', '')}",
                f"Salt: {hash_dict.get('salt', '')}",
            ]
            if hash_dict.get('metadata'):
                lines.append(f"Metadata: {hash_dict['metadata']}")
            return '\n'.join(lines)
        
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def get_statistics(self) -> Dict[str, int]:
        """Get usage statistics."""
        return {
            'hashes_generated': self.hashes_generated,
            'supported_algorithms': len(self.SUPPORTED_ALGORITHMS)
        }


# Example usage and testing
if __name__ == "__main__":
    hasher = PasswordHasher()
    
    # Test single password hashing
    print("\n=== Single Password Test ===")
    test_password = "TestPassword123!"
    
    # Test bcrypt (recommended)
    bcrypt_result = hasher.hash_password(test_password, 'bcrypt')
    print(f"\nBcrypt hash: {bcrypt_result['hash'][:50]}...")
    
    # Verify the password
    is_valid = hasher.verify_password(test_password, bcrypt_result['hash'], 'bcrypt')
    print(f"Verification: {'✓ Valid' if is_valid else '✗ Invalid'}")
    
    # Compare all algorithms
    print("\n=== Algorithm Comparison ===")
    comparison = hasher.compare_algorithms(test_password)
    
    # Batch hashing test
    print("\n=== Batch Hashing Test ===")
    test_passwords = ["password1", "password2", "password3", "test123", "admin"]
    batch_results = hasher.batch_hash(test_passwords, 'sha256')
    print(f"Successfully hashed {len(batch_results)} passwords")
    
    # Display statistics
    stats = hasher.get_statistics()
    print(f"\n=== Statistics ===")
    print(f"Total hashes generated: {stats['hashes_generated']}")