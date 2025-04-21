# attacks/honeypot_bot.py

import requests
import time

url = "http://localhost:5000/admin-login"

for i in range(10):
    headers = {
        "User-Agent": f"botnet-agent/{i}",
    }
    r = requests.get(url, headers=headers)
    print(f"[{i+1}/10] Status: {r.status_code}")
    time.sleep(0.5)
