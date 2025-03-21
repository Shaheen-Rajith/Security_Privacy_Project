import json

import mysql.connector
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
    "localhost", "root", "xxx"
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
    server_connection.commit()


init_db()


# Main Login Page
@app.route("/", methods=["GET", "POST"])
def home():
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


# Shop Page after Logging in Successfully, THE ONLY THING LEFT
@app.route("/shop", methods=["GET", "POST"])
def shop():
    return """<p> WORK IN PROGRESS, COME BACK LATER :) </p>
    <button type="button" onclick="window.location.href='/checkout'">Checkout</button>
    """


# Checkout Page
@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    email = session["user_email"]
    price = session["price"]
    if request.method == "POST":
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
    app.run(debug=True)
