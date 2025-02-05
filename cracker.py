#!/usr/bin/env python3.11
import requests
import threading
import re
import time
import bcrypt
import multiprocessing

# Dictionary to store cracked passwords
cracked_passwords = {}
lock = threading.Lock()  # Ensure thread-safe access to cracked_passwords

def identify_hash(hash_value):
    print(f"Identifying hash: {hash_value}")
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
    elif re.match(r'^\$2[ayb]\$\d{2}\$[a-zA-Z0-9./]{53}$', hash_value):  # More generic bcrypt regex
        return 'bcrypt'
    else:
        return None

def check_bcrypt_hash(password, hash_value):
    if bcrypt.checkpw(password.encode('utf-8'), hash_value.encode('utf-8')):
        with lock:
            cracked_passwords[hash_value] = password
        print(f"[+] Password cracked for bcrypt hash: {hash_value} -> {password}")

def check_online(hash_value):
    url = f'https://weakpass.com/api/v1/search/{hash_value}'
    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, dict) and 'data' in data and 'password' in data['data']:
                with lock:
                    cracked_passwords[hash_value] = data['data']['password']
                print(f"[+] Online match: {hash_value} -> {data['data']['password']}")
                return True
        elif response.status_code == 404:
            print(f"[-] No match found online for {hash_value}")
    except Exception as e:
        print(f"[-] Online check error: {e}")
    
    return False

def process_password_chunk(chunk, hashes):
    for password in chunk:
        for hash_value in hashes:
            hash_type = identify_hash(hash_value)
            if hash_type == 'bcrypt':
                check_bcrypt_hash(password, hash_value)
            elif hash_type:
                check_online(hash_value)
            else:
                print(f"[-] Unknown hash type for {hash_value}")
            time.sleep(0.1)

    print(f"[*] Process {multiprocessing.current_process().name} completed.")

def wordlist_attack(hashes, wordlist_url):
    """Download wordlist and split it across CPU cores."""
    response = requests.get(wordlist_url)
    response.raise_for_status()
    
    wordlist = response.text.splitlines()
    num_cores = multiprocessing.cpu_count()
    
    chunk_size = len(wordlist) // num_cores
    chunks = [wordlist[i:i+chunk_size] for i in range(0, len(wordlist) - chunk_size, chunk_size)]
    chunks.append(wordlist[len(chunks) * chunk_size:])

    processes = []
    for chunk in chunks:
        p = multiprocessing.Process(target=process_password_chunk, args=(chunk, hashes))
        processes.append(p)
        p.start()

    for p in processes:
        p.join()

def main():
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

    threads = []
    for wordlist_url in wordlists:
        thread = threading.Thread(target=wordlist_attack, args=(hashes, wordlist_url))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Print all cracked passwords
    if cracked_passwords:
        print("\n[+] Cracked passwords:")
        for h, p in cracked_passwords.items():
            print(f"{h} -> {p}")
    else:
        print("[-] No passwords were cracked.")

if __name__ == '__main__':
    main()

