from flask import Flask, render_template, request, redirect, session
import pysqlite3
import json

app = Flask(__name__)
app.secret_key = 'totallysecretkey'

def init_db():
    # NEED TO SETUP SQL DATABASES HERE
    i=0

    
@app.route('/')
def home():
    # Displaying Login Page upon entering the site
    return render_template("login.html")

if __name__ == "__main__":
    app.run()

"------------------------------------ WORK IN PROGRESS ------------------------------------"