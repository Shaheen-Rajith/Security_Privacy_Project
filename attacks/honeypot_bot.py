# honeypot_bot.py (final, works with Flask's form recognition)
import requests
import random
import time

url = "http://127.0.0.1:5000/admin-panel-supersecret"

emails = [
    "admin@example.com",
    "root@linguini.com",
    "testuser@gmail.com",
    "login@target.com",
    "ceo@linguini-boutique.com"
]

passwords = [
    "123456", "password", "admin", "qwerty", "linguini123"
]

headers = {
    "User-Agent": "sqlmap/1.7.8-dev"
}

print("Starting honeypot attack simulation...\n")

for i in range(10):
    email = random.choice(emails)
    password = random.choice(passwords)

    data = {
        "email": email,
        "password": password
    }

    # 不加 Content-Type，让 requests 自动处理为 form
    response = requests.post(url, data=data, headers=headers)

    print(f"[{i+1}] Attempted login with {email} / {password}")
    time.sleep(1)

print("\nAttack simulation completed.")
