"""
File Name: Website_safe.py

This file implements a website that can effectively defend against DoS attacks.
It includes a login page, registration page, shop page, and checkout page.
"""

import base64
import hashlib
import json
import os
import pickle
import threading
import time

import mysql.connector
import numpy as np
import pandas as pd
import psutil
from flask import Flask, flash, g, redirect, render_template, request, session, url_for

from defence_system.dos_defence import (
    block_strategy,
    build_dos_detection,
    check_ip,
    get_request_features,
    ip_status,
    record_num_requests,
)

app = Flask(__name__)
app.secret_key = "totallysecretkey"


# Setting up connection with SQL Server
def create_server_connection(host_name, user_name, user_password):
    """Create a connection to the MySQL server.
    Args:
        host_name (str): The hostname of the MySQL server.
        user_name (str): The username to connect to the MySQL server.
        user_password (str): The password for the username.
    Returns:
        connection: A MySQL connection object.
    """
    connection = None
    try:
        connection = mysql.connector.connect(
            host=host_name, user=user_name, password=user_password
        )
        print("MySQL Database connection successful")
    except:
        print(f"Error")
    return connection


server_connection = create_server_connection(
    "localhost", "root", "xxx"
)  # Hardcoded, varies per person
cursor = server_connection.cursor()


# Setting up Databases incase they dont already exist
def init_db():
    """Initialize the database and create the necessary tables."""
    # check if database exists
    cursor.execute(
        """
        SHOW DATABASES
    """
    )
    databases = [database[0] for database in cursor.fetchall()]

    if "secpri" not in databases:
        print("Database does not exist")
        cursor.execute(
            """
            CREATE DATABASE secpri
        """
        )
        print("Database Created")
    else:
        print("Database already exists")

    cursor.execute(
        """
        USE secpri
    """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTO_INCREMENT,
            email VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(50) NOT NULL
        )
    """
    )
    server_connection.commit()


init_db()


def monitoring():
    """Monitor the CPU and memory usage of the process and save it to a CSV file."""
    p = psutil.Process(os.getpid())

    # create a folder to store resource usage data
    resource_usage_dir = "./Resource_Usage"
    if not os.path.exists(resource_usage_dir):
        os.makedirs(resource_usage_dir)

    with open(
        os.path.join(resource_usage_dir, "resource_usage.csv"), "w", encoding="utf-8"
    ) as f:
        f.write("timestamp, cpu_usage, memory_usage\n")

    while True:
        # get the current CPU and memory usage
        cpu_current = p.cpu_percent(interval=0.1)
        memory_current = p.memory_info().rss / (1024**2)  # convert to MB

        # get the current timestamp
        timestamp = time.time()

        # write the data to the file
        with open(
            os.path.join(resource_usage_dir, "resource_usage.csv"),
            "a",
            encoding="utf-8",
        ) as f:
            f.write(f"{timestamp}, {cpu_current}, {memory_current}\n")

        # sleep for 1 second
        time.sleep(0.01)


# Start monitoring
@app.before_request
def start_monitoring():
    """define the function to monitor the CPU and memory usage of the process
    and check if the IP is in the blacklist"""
    monitoring_thread = threading.Thread(target=monitoring)
    monitoring_thread.daemon = True
    monitoring_thread.start()
    print("Monitoring started")
    g.start_time = time.time()
    g.raw_request = request.get_data()
    # check if the IP is in the blacklist
    ip = request.remote_addr
    if check_ip(ip):
        return "Too many requests or DoS attack detected", 429


@app.after_request
def after_request(response):
    """define the function to record the request and response data
    Args:
        response: The response object.
    Returns:
        response: The modified response object.
    """
    if request.method != "POST":
        return response
    ip = request.remote_addr
    now = time.time()
    duration = now - g.start_time
    ip_state = ip_status[ip]
    ip_state["flow_duration"].append(duration)
    ip_state["timestamp"].append(now)
    packet_size = len(g.raw_request)
    ip_state["packet_size"].append(packet_size)
    if ip_state["last_time"] is not None:
        iat = now - ip_state["last_time"]
        if iat < 5:
            ip_state["active_duration"].append(iat)
        else:
            ip_state["idle_duration"].append(iat)
    ip_state["last_time"] = now
    return response


# Main Login Page
@app.route("/", methods=["GET", "POST"])
def home():
    """Main login page for the application.
    Returns:
        Rendered HTML template for the login page.
    """
    # # train DoS detection model
    # trainset_file = "./dataset_use.csv"
    # build_dos_detection(trainset_file)

    # load the DoS detection model and scaler
    with open("./model/SVM_model.pkl", "rb") as f:
        svm_model = pickle.load(f)
    with open("./model/scaler.pkl", "rb") as f:
        scaler = pickle.load(f)
    ip = request.remote_addr
    now = time.time()
    # check the number of requests from the IP
    num_requests = record_num_requests(ip, now, request.path, request.method)
    if num_requests > 5:

        # test features collected from our website
        features = get_request_features(ip)

        # # test features collected from CIC-IDS2017
        # features_path = "./test_data.csv"
        # features_data = pd.read_csv(features_path, header=None)
        # features = np.array(features_data.iloc[0, :])

        # check if the request is a DoS attack
        if block_strategy(ip, features, svm_model, scaler):
            return "Too many requests or DoS attack detected", 429

    if request.method == "POST":
        log_email = request.form["email"]
        log_password = request.form["password"]
        puzzle_c = request.form["puzzle_c"]
        puzzle_x = request.form["puzzle_x"]

        # combine the two puzzle strings
        puzzle_combined = puzzle_c.encode() + puzzle_x.encode()
        # hash the combined string
        result = hashlib.sha1(puzzle_combined).digest()

        last_3_bytes = result[-3:]
        val = int.from_bytes(last_3_bytes, "big")
        # check if the last 18 bits are 0
        if (val & 0x3FFFF) != 0:
            flash("Invalid Puzzle", "error")
            return redirect(url_for("home"))

        try:
            cursor.execute(
                f"SELECT * FROM users WHERE email = '{log_email}' AND password = '{log_password}'"
            )
            user = cursor.fetchone()
            if user:
                session["user_Id"] = user[0]
                session["user_email"] = user[1]
                session["price"] = 39  # TEMP
                flash("Successfully Logged in", "success")
                return redirect(url_for("shop"))
            else:
                flash("Invalid Email-id or Password", "error")
                # print("INVALID Email / Password Combination")
                return redirect(url_for("home"))
        except mysql.connector.Error as err:
            flash(f"Database Error: {err}", "error")
            return redirect(url_for("home"))
    # Displaying Login Page upon entering the site
    challenge = base64.b64encode(os.urandom(16)).decode()
    return render_template("login_safe.html", challenge=challenge)


# New User Registration Page
@app.route("/register", methods=["GET", "POST"])
def register():
    """New user registration page.
    Returns:
        Rendered HTML template for the registration page.
    """
    if request.method == "POST":
        reg_email = request.form["email"]
        reg_password = request.form["password"]
        try:
            cursor.execute(
                f"INSERT INTO users (email, password) VALUES ('{reg_email}','{reg_password}')"
            )
            server_connection.commit()
            return redirect(url_for("home"))
        except mysql.connector.Error as err:
            print(f"Error: {err}")
    # Displaying Registration Page for new Users
    return render_template("register.html")


# Shop Page after Logging in Successfully
@app.route("/shop", methods=["GET", "POST"])
def shop():
    if "user_Id" not in session:
        return redirect(url_for('home'))
    
    items = [
        {"id": 1, "name": "White Satin Shirt", "price": 120},
        {"id": 2, "name": "Black Silk Shirt", "price": 125},
        {"id": 3, "name": "Black Polo Shirt", "price": 120},
        {"id": 4, "name": "Gray Cropped Blazer", "price": 550},
        {"id": 5, "name": "Tan Single Breasted Blazer", "price": 450},
        {"id": 6, "name": "Red Leather Blouson", "price": 650},
        {"id": 7, "name": "White Corduroy Trousers", "price": 180},
        {"id": 8, "name": "White Denim Jorts", "price": 110},
        {"id": 9, "name": "Leather Card Wallet", "price": 145},
        {"id": 10, "name": "Red Leather Belt", "price": 150},
    ]

    if "cart" not in session:
        session["cart"] = []
        session["price_t"] = 0

    if request.method == 'POST' and 'clear_cart' in request.form:
       session["cart"] = []
       session["price_t"] = 0
       session.modified = True
       return redirect(url_for('shop'))


    if request.method == 'POST':
        item_id = int(request.form['item_id'])
        for item in items:
            if item["id"] == item_id:
                session["cart"].append(item)
                session["price_t"] += item["price"]
                session.modified = True
                break
        return redirect(url_for('shop'))
    
    return render_template("shop.html", items=items, price_t=session.get("price_t", 0))



# Checkout Page
@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    email = session["user_email"]
    price = session["price_t"]
    if request.method == "POST":
        if 'go_back' in request.form:
            return redirect(url_for('shop'))
        card_num = request.form["card_num"]
        cvv = request.form["cvv"]
        address = request.form["address"]
        zip_code = request.form["zip_code"]
        try:
            cursor.execute(
                f"INSERT INTO orders (email, price, card_num, cvv, address, zip_code) VALUES ('{email}', '{price}', '{card_num}', '{cvv}', '{address}', '{zip_code}')"
            )
            server_connection.commit()
            flash("Sucessfully Placed Order")
            return redirect(url_for("shop"))
        except mysql.connector.Error as err:
            print(f"Error: {err}")
    # Displaying Registration Page for new Users
    return render_template("checkout.html", val_price=price)


# base page
@app.route("/base")
def base():
    return render_template("base.html")


if __name__ == "__main__":
    app.run(debug=True, threaded=True)
