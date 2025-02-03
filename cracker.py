#!/usr/bin/env python3.11
import requests
import threading
import re
import time
import bcrypt

# Global variable to track if a password is found
password_found_event = threading.Event()

def identify_hash(hash_value):
    print(f"Identifying hash: {hash_value}")
    # Adjust each of these for salt if necessary
    if re.match(r'^[a-fA-F0-9]{32}$', hash_value):
        return 'md5'
    elif re.match(r'^[a-fA-F0-9]{40}$', hash_value):
        return 'sha1'
    elif re.match(r'^[a-fA-F0-9]{64}$', hash_value):
        return 'sha256'
    elif re.match(r'^[a-fA-F0-9]{96}$', hash_value):
        return 'sha384'
    elif re.match(r'^[a-fA-F0-9]{128}$', hash_value):
        return 'sha512'
    elif re.match(r'^\$2a\$\d+\$[a-zA-Z0-9./]{53}$', hash_value):
        return 'bcrypt'
    else:
        return None

def check_bcrypt_hash(password, hash_value):
    if bcrypt.checkpw(password.encode('utf-8'), hash_value.encode('utf-8')):
        print(f"[+] Password cracked for bcrypt hash: {hash_value} -> {password}")
        password_found_event.set()  # Signal that a password has been found
    else:
        print("[-] Password does not match for bcrypt hash.")

def check_online(hash_value):
    url = f'https://weakpass.com/api/v1/search/{hash_value}'
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    try:
        response = requests.get(url, headers=headers)
        print(f"[+] Response status code: {response.status_code}")

        if response.status_code == 200:
            if not response.text.strip():  # Check if response is empty
                print(f"[-] Empty response from WeakPass for {hash_value}")
                return False
            
            try:
                data = response.json()
                if isinstance(data, dict) and 'data' in data and 'password' in data['data']:
                    print(f"[+] Password found: {data['data']['password']}")
                    password_found_event.set()
                    return True
            except requests.exceptions.JSONDecodeError:
                print(f"[-] Invalid JSON response for {hash_value}: {response.text}")
                return False
        elif response.status_code == 404:
            print(f"[-] Password not found for {hash_value}")
        else:
            print(f"[-] Unexpected response {response.status_code}: {response.text}")
    except Exception as e:
        print(f"[-] Request error: {e}")

    return False

def wordlist_attack(hashes, wordlist_url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    try:
        response = requests.get(wordlist_url, headers=headers)
        response.raise_for_status()  # Raises an error for bad responses
        wordlist = [password.strip() for password in response.text.split('\n') if password.strip()]
        
        for password in wordlist:
            if password_found_event.is_set():
                break
            for hash_value in hashes:
                # Identify the hash type
                hash_type = identify_hash(hash_value.strip())
                
                if hash_type == 'bcrypt':
                    # Check bcrypt hash
                    check_bcrypt_hash(password, hash_value.strip())
                    if password_found_event.is_set():  # Stop if password is found
                        return True
                else:
                    # Check online for other hash types
                    if check_online(hash_value.strip()):
                        return True
            time.sleep(1)  # Avoid hitting rate limits
    except requests.RequestException as e:
        print(f"[-] Error downloading wordlist: {e}")

    return False

def main():
    # Load hashes from file
    hashes_file = input("[*] Enter the path to the hashes file: ")
    with open(hashes_file, 'r') as f:
        hashes = f.read().splitlines()

    wordlists = [
        "https://weakpass.com/api/v1/wordlists/10_million_password_list_top_10000.txt",
        "https://weakpass.com/api/v1/wordlists/hashmob.net.small.found.txt",
        "https://weakpass.com/api/v1/wordlists/ignis-10K.txt",
        "https://weakpass.com/api/v1/wordlists/nsa64.rule",
        "https://weakpass.com/api/v1/wordlists/rockyou.txt"
    ]

    # Loop through each wordlist
    threads = []
    for wordlist_url in wordlists:
        # Use a separate thread for each wordlist
        thread = threading.Thread(target=wordlist_attack, args=(hashes, wordlist_url))
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish or stop early if password is found
    for thread in threads:
        thread.join()

    if password_found_event.is_set():
        print("[+] Password found and cracked!")
        input("[*] Press Enter to exit...")
    else:
        print("[-] No password found.")

if __name__ == '__main__':
    main()
