from flask import Flask, render_template, request, redirect, session
import pysqlite3
import json
# ALL CAPS COMMENTS ARE FUTURE WORK
app = Flask(__name__)
app.secret_key = 'totallysecretkey'

def init_db():
    # NEED TO SETUP SQL DATABASES HERE
    i=0

    
@app.route('/', methods =['GET','POST'])
def home():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
    # CHECK WITH TABLE AND PROCEED IF VALID
    # Displaying Login Page upon entering the site
    return render_template("login.html")

@app.route('/register', methods =['GET','POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
    # ADD USERNAME AND PASSWORD TO TABLE
    # Displaying Registration Page for new Users
    return render_template("register.html")

@app.route('/login', methods =['GET','POST'])
def shop():
    return """<p> WORK IN PROGRESS, COME BACK LATER :) </p>"""


if __name__ == "__main__":
    app.run()