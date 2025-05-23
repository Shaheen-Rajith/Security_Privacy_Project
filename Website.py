import json
import os
import threading
import time

import mysql.connector
import psutil
from flask import Flask, flash, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.secret_key = "totallysecretkey"


# Setting up connection with SQL Server
def create_server_connection(host_name, user_name, user_password):
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
    "localhost", "root", "12345"
)  # Hardcoded, varies per person
cursor = server_connection.cursor()


# Setting up Databases incase they dont already exist
def init_db():
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

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTO_INCREMENT,
            email VARCHAR(50) NOT NULL,
            price INT NOT NULL,
            card_num VARCHAR(16) NOT NULL,
            cvv VARCHAR(3) NOT NULL,
            address VARCHAR(50) NOT NULL,
            zip_code VARCHAR(7) NOT NULL
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
        os.path.join(resource_usage_dir, "resource_usage.csv"),
        "w",
        encoding="utf-8",
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


@app.before_request
def start_monitoring():
    """define the function to monitor the CPU and memory usage of the process
    and check if the IP is in the blacklist"""
    monitoring_thread = threading.Thread(target=monitoring)
    monitoring_thread.daemon = True
    monitoring_thread.start()
    print("Monitoring started")


# Main Login Page
@app.route("/", methods=["GET", "POST"])
def home():
    session.clear()
    if request.method == "POST":
        log_email = request.form["email"]
        log_password = request.form["password"]
        try:
            cursor.execute(
                f"SELECT * FROM users WHERE email = '{log_email}' AND password = '{log_password}'"
            )
            user = cursor.fetchone()
            if user:
                session["user_Id"] = user[0]
                session["user_email"] = user[1]
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
    return render_template("login.html")


# New User Registration Page
@app.route("/register", methods=["GET", "POST"])
def register():
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
        return redirect(url_for("home"))

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

    if request.method == "POST" and "clear_cart" in request.form:
        session["cart"] = []
        session["price_t"] = 0
        session.modified = True
        return redirect(url_for("shop"))

    if request.method == "POST":
        item_id = int(request.form["item_id"])
        for item in items:
            if item["id"] == item_id:
                session["cart"].append(item)
                session["price_t"] += item["price"]
                session.modified = True
                break
        return redirect(url_for("shop"))

    return render_template("shop.html", items=items, price_t=session.get("price_t", 0))


# Checkout Page
@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    email = session["user_email"]
    price = session["price_t"]
    if request.method == "POST":
        if "go_back" in request.form:
            return redirect(url_for("shop"))
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
    # Displaying Checkout Page
    return render_template("checkout.html", val_price=price)


# base page
@app.route("/base")
def base():
    return render_template("base.html")


if __name__ == "__main__":
    app.run(debug=True, threaded=True)
