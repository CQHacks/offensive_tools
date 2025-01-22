"""
Title: Hash Cracker
Description: Identifies hashing algorithm, runs dictionary attack against user-defined world list, and if needed, does brute forcing.
Author: Chris Quinn
"""
import argparse
import hashlib
import string
import itertools
import time

def parse_input():
    parser = argparse.ArgumentParser(description="Single hash cracker tool")
    parser.add_argument("--hash", required=True, help="Hash to crack")
    parser.add_argument("--wordlist", default="/usr/share/wordlists/rockyou.txt", 
                       help="Absolute path to the word list file (default: /usr/share/wordlists/rockyou.txt)")
    args = parser.parse_args()
    return args.hash.strip(), args.wordlist

def identify_hash_algorithm(sample_hash):
    length = len(sample_hash)
    if length == 32:
        return 'md5'
    elif length == 40:
        return 'sha1'
    elif length == 64:
        return 'sha256'
    elif length == 128:
        return 'sha512'
    else:
        print("Unsupported hash length.")
        return None

def check_against_wordlist(target_hash, hash_algorithm, wordlist_path):
    try:
        with open(wordlist_path, "r", encoding="latin-1") as file:
            for word in file:
                word = word.strip()  # Remove any extra whitespace or newlines
                hashed_word = hashlib.new(hash_algorithm, word.encode()).hexdigest()
                if hashed_word == target_hash:
                    print(f"Match found! Password is: {word}")
                    return True  # Exit function if match is found
        print("No match found in word list.")
        return False
    except FileNotFoundError:
        print(f"Error: Word list file '{wordlist_path}' not found.")
        return False

def brute_force(target_hash, hash_algorithm):
    characters = string.ascii_lowercase
    total_attempts = 0

    for i in range(4, 8):
        for combination in itertools.product(characters, repeat=i):
            total_attempts += 1
            possible_password = ''.join(combination)
            brute_hash = hashlib.new(hash_algorithm, possible_password.encode()).hexdigest()
            if brute_hash == target_hash:
                print(f"Password match: {possible_password}")
                print(f"Total passwords attempted: {total_attempts:,}")

                return possible_password
    # Return value if no match is found
    print("Password not found.")
    print(f"Total passwords attempted: {total_attempts:,}")
    return False

def main():
    start_time = time.perf_counter()
    target_hash, wordlist_path = parse_input()

    # Identify the hash algorithm based on the target hash
    hash_algorithm = identify_hash_algorithm(target_hash)
    
    if hash_algorithm:
        print(f"Identified hash algorithm: {hash_algorithm}")
        
        # Check against word list first
        print("Checking against word list...")
        wordlist_result = check_against_wordlist(target_hash, hash_algorithm, wordlist_path)
        
        if not wordlist_result:
            print("Moving on to brute forcing...")
            brute_force_result = brute_force(target_hash, hash_algorithm)
            if brute_force_result is False:
                print("Brute force failed. No matching password found.")
    else:
        print("Failed to identify hash algorithm. Exiting.")
    
    end_time = time.perf_counter()
    total_time = end_time - start_time
    print(f"Total time: {total_time:.2f}")

if __name__ == "__main__":
    main()