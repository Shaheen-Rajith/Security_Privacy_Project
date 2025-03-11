from flask import Flask, render_template, request, redirect, session, url_for
import mysql.connector
import json

app = Flask(__name__)
app.secret_key = 'totallysecretkey'


# Setting up connection with SQL Server
def create_server_connection(host_name, user_name, user_password):
    connection = None
    try:
        connection = mysql.connector.connect(
            host=host_name,
            user=user_name,
            password=user_password
        )
        print("MySQL Database connection successful")
    except:
        print(f"Error")
    return connection
server_connection = create_server_connection("localhost", "root","12345") #Hardcoded, varies per person
cursor = server_connection.cursor()


# Setting up Databases incase they dont already exist
def init_db():
    cursor.execute("""
        USE secpri
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTO_INCREMENT,
            email VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(50) NOT NULL
        )
    """)
    server_connection.commit()
init_db()


# Main Login Page
@app.route('/', methods =['GET','POST'])
def home():
    if request.method == 'POST':
        log_email = request.form['email']
        log_password = request.form['password']
        try:
            cursor.execute(f"SELECT * FROM users WHERE email = '{log_email}' AND password = '{log_password}'")
            user = cursor.fetchone()
            if user:
                session["user_Id"] = user[0]
                return redirect(url_for('shop'))
            else:
                print("INVALID Email / Password Combination")
                return redirect(url_for('home'))
        except mysql.connector.Error as err:
            print(f"Error: {err}")
            return redirect(url_for('home'))
    # Displaying Login Page upon entering the site
    return render_template("login.html")


# New User Registration Page
@app.route('/register', methods =['GET','POST'])
def register():
    if request.method == 'POST':
        reg_email = request.form['email']
        reg_password = request.form['password']
        try:
            cursor.execute(f"INSERT INTO users (email, password) VALUES ('{reg_email}','{reg_password}')")
            server_connection.commit()
            return redirect(url_for('home'))
        except mysql.connector.Error as err:
            print(f"Error: {err}")
    # Displaying Registration Page for new Users
    return render_template("register.html")


# Shop Page after Logging in Successfully
@app.route('/shop', methods =['GET','POST'])
def shop():
    return """<p> WORK IN PROGRESS, COME BACK LATER :) </p>"""


if __name__ == "__main__":
    app.run()