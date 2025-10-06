#!/usr/bin/env python3
"""
Wordlist Statistics Utility
Educational Cybersecurity Toolkit - For authorized educational use only
Analyzes and displays statistics about wordlists

Author: Aniket886
GitHub: https://github.com/Aniket886
Project: Educational Cybersecurity Toolkit
Created: 2025
"""

import os
import sys
from collections import Counter
from typing import Dict, List, Tuple


class WordlistAnalyzer:
    """Analyzes wordlist files for statistics and quality metrics."""
    
    def __init__(self):
        """Initialize the analyzer."""
        self.stats = {}
    
    def analyze_wordlist(self, filepath: str) -> Dict:
        """
        Analyze a wordlist file.
        
        Args:
            filepath: Path to wordlist file
            
        Returns:
            Dictionary of statistics
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Wordlist not found: {filepath}")
        
        stats = {
            'total_lines': 0,
            'unique_passwords': 0,
            'duplicates': 0,
            'comments': 0,
            'empty_lines': 0,
            'avg_length': 0,
            'min_length': float('inf'),
            'max_length': 0,
            'categories': {},
            'character_types': {
                'lowercase_only': 0,
                'uppercase_only': 0,
                'mixed_case': 0,
                'with_numbers': 0,
                'with_symbols': 0,
                'alphanumeric': 0,
                'numeric_only': 0
            },
            'top_lengths': Counter(),
            'passwords': []
        }
        
        seen = set()
        current_category = 'Uncategorized'
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                stats['total_lines'] += 1
                line = line.strip()
                
                if not line:
                    stats['empty_lines'] += 1
                    continue
                
                if line.startswith('#'):
                    stats['comments'] += 1
                    # Extract category name if it's a category header
                    if '===' in line:
                        category = line.replace('=', '').replace('#', '').strip()
                        if category:
                            current_category = category
                            stats['categories'][current_category] = 0
                    continue
                
                # It's a password
                if line in seen:
                    stats['duplicates'] += 1
                else:
                    seen.add(line)
                    stats['passwords'].append(line)
                    
                    # Category tracking
                    if current_category in stats['categories']:
                        stats['categories'][current_category] += 1
                    
                    # Length statistics
                    length = len(line)
                    stats['top_lengths'][length] += 1
                    stats['min_length'] = min(stats['min_length'], length)
                    stats['max_length'] = max(stats['max_length'], length)
                    
                    # Character type analysis
                    if line.isdigit():
                        stats['character_types']['numeric_only'] += 1
                    elif line.islower():
                        stats['character_types']['lowercase_only'] += 1
                    elif line.isupper():
                        stats['character_types']['uppercase_only'] += 1
                    elif line.isalnum():
                        stats['character_types']['alphanumeric'] += 1
                        if any(c.islower() for c in line) and any(c.isupper() for c in line):
                            stats['character_types']['mixed_case'] += 1
                    
                    if any(c.isdigit() for c in line):
                        stats['character_types']['with_numbers'] += 1
                    
                    if not line.isalnum():
                        stats['character_types']['with_symbols'] += 1
        
        stats['unique_passwords'] = len(seen)
        if stats['unique_passwords'] > 0:
            total_length = sum(len(p) for p in stats['passwords'])
            stats['avg_length'] = total_length / stats['unique_passwords']
        
        # Clean up passwords list (we don't need to keep them all)
        stats['sample_passwords'] = stats['passwords'][:10]
        del stats['passwords']
        
        return stats
    
    def print_stats(self, stats: Dict, filename: str):
        """
        Print formatted statistics.
        
        Args:
            stats: Statistics dictionary
            filename: Name of the file analyzed
        """
        print("\n" + "=" * 60)
        print(f"WORDLIST ANALYSIS: {filename}")
        print("=" * 60)
        
        print("\n📊 BASIC STATISTICS:")
        print(f"  Total lines:        {stats['total_lines']:,}")
        print(f"  Unique passwords:   {stats['unique_passwords']:,}")
        print(f"  Duplicates found:   {stats['duplicates']:,}")
        print(f"  Comments:           {stats['comments']:,}")
        print(f"  Empty lines:        {stats['empty_lines']:,}")
        
        print("\n📏 LENGTH STATISTICS:")
        print(f"  Average length:     {stats['avg_length']:.1f} characters")
        print(f"  Minimum length:     {stats['min_length']} characters")
        print(f"  Maximum length:     {stats['max_length']} characters")
        
        # Top 5 most common lengths
        if stats['top_lengths']:
            print("\n  Most common lengths:")
            for length, count in stats['top_lengths'].most_common(5):
                percentage = (count / stats['unique_passwords']) * 100
                print(f"    {length:2} chars: {count:4} passwords ({percentage:.1f}%)")
        
        print("\n🔤 CHARACTER TYPE ANALYSIS:")
        for char_type, count in stats['character_types'].items():
            if count > 0:
                percentage = (count / stats['unique_passwords']) * 100
                formatted_name = char_type.replace('_', ' ').title()
                print(f"  {formatted_name:20} {count:5} ({percentage:.1f}%)")
        
        if stats['categories']:
            print("\n📂 CATEGORIES FOUND:")
            for category, count in stats['categories'].items():
                if count > 0:
                    print(f"  {category}: {count} passwords")
        
        print("\n🔍 SAMPLE PASSWORDS:")
        for i, password in enumerate(stats['sample_passwords'][:5], 1):
            masked = password[0] + '*' * (len(password) - 2) + password[-1] if len(password) > 2 else '*' * len(password)
            print(f"  {i}. {masked} (length: {len(password)})")
        
        print("\n💡 QUALITY ASSESSMENT:")
        quality_score = 0
        recommendations = []
        
        # Calculate quality score
        if stats['unique_passwords'] > 100:
            quality_score += 25
        elif stats['unique_passwords'] > 50:
            quality_score += 15
        else:
            recommendations.append("Add more passwords (100+ recommended)")
        
        if stats['duplicates'] == 0:
            quality_score += 25
        else:
            recommendations.append(f"Remove {stats['duplicates']} duplicate passwords")
        
        variety = len([k for k, v in stats['character_types'].items() if v > 0])
        if variety >= 5:
            quality_score += 25
        elif variety >= 3:
            quality_score += 15
        else:
            recommendations.append("Add more password variety (different character types)")
        
        if stats['avg_length'] >= 8:
            quality_score += 25
        elif stats['avg_length'] >= 6:
            quality_score += 15
        else:
            recommendations.append("Include longer passwords (8+ characters)")
        
        # Print quality score
        print(f"  Quality Score: {quality_score}/100")
        
        if quality_score >= 80:
            print("  Rating: ⭐⭐⭐⭐⭐ Excellent wordlist!")
        elif quality_score >= 60:
            print("  Rating: ⭐⭐⭐⭐ Good wordlist")
        elif quality_score >= 40:
            print("  Rating: ⭐⭐⭐ Decent wordlist")
        elif quality_score >= 20:
            print("  Rating: ⭐⭐ Needs improvement")
        else:
            print("  Rating: ⭐ Poor wordlist")
        
        if recommendations:
            print("\n  Recommendations:")
            for rec in recommendations:
                print(f"    • {rec}")
        
        print("=" * 60)
    
    def compare_wordlists(self, file1: str, file2: str):
        """
        Compare two wordlists.
        
        Args:
            file1: Path to first wordlist
            file2: Path to second wordlist
        """
        print("\n" + "=" * 60)
        print("WORDLIST COMPARISON")
        print("=" * 60)
        
        # Load both wordlists
        words1 = set()
        words2 = set()
        
        with open(file1, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    words1.add(line)
        
        with open(file2, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    words2.add(line)
        
        # Calculate metrics
        common = words1 & words2
        unique_to_1 = words1 - words2
        unique_to_2 = words2 - words1
        
        print(f"\n📊 Comparison Results:")
        print(f"  {os.path.basename(file1)}: {len(words1)} passwords")
        print(f"  {os.path.basename(file2)}: {len(words2)} passwords")
        print(f"\n  Common passwords: {len(common)}")
        print(f"  Unique to {os.path.basename(file1)}: {len(unique_to_1)}")
        print(f"  Unique to {os.path.basename(file2)}: {len(unique_to_2)}")
        print(f"  Total unique: {len(words1 | words2)}")
        
        if common:
            overlap_percentage = (len(common) / len(words1)) * 100
            print(f"\n  Overlap: {overlap_percentage:.1f}% of {os.path.basename(file1)}")


def main():
    """Main entry point."""
    print("=" * 60)
    print("WORDLIST STATISTICS ANALYZER")
    print("Author: Aniket886 | GitHub: https://github.com/Aniket886")
    print("=" * 60)
    
    analyzer = WordlistAnalyzer()
    
    # Analyze common_passwords.txt
    try:
        stats1 = analyzer.analyze_wordlist("wordlists/common_passwords.txt")
        analyzer.print_stats(stats1, "common_passwords.txt")
    except FileNotFoundError:
        print("❌ common_passwords.txt not found")
    
    # Analyze enhanced_wordlist.txt
    try:
        stats2 = analyzer.analyze_wordlist("wordlists/enhanced_wordlist.txt")
        analyzer.print_stats(stats2, "enhanced_wordlist.txt")
    except FileNotFoundError:
        print("❌ enhanced_wordlist.txt not found")
    
    # Compare if both exist
    if 'stats1' in locals() and 'stats2' in locals():
        analyzer.compare_wordlists(
            "wordlists/common_passwords.txt",
            "wordlists/enhanced_wordlist.txt"
        )


if __name__ == "__main__":
    main()