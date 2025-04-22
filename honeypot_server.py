# honeypot_server.py
from flask import Flask, request, render_template_string
import csv
import os
import time

app = Flask(__name__)

# 日志目录准备
if not os.path.exists("logs"):
    os.makedirs("logs")
log_path = "logs/honeypot_log.csv"

# HTML 页面模板：仿项目原登录页（已移除 Jinja2）
fake_login_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Giorgio Linguini Boutique Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            background-color: #f4f4f4;
            margin: 0;
        }
        .container {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        input {
            display: block;
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #ccc;
            border-radius: 5px;
        }
        button {
            background-color: #ff9900;
            color: white;
            border: none;
            padding: 10px;
            width: 49%;
            cursor: pointer;
            border-radius: 5px;
            margin-bottom: 10px;
        }
        button:hover {
            background-color: #cc7b00;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Welcome to Giorgio Linguini Luxury Boutique</h2>
        <form method="post" action="/admin-panel-supersecret">
            <input type="text" name="email" placeholder="Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
            <button type="button" onclick="window.location.href='/register'">New User Sign Up</button>
        </form>
    </div>
</body>
</html>
"""

@app.route("/admin-panel-supersecret", methods=["GET", "POST"])
def honeypot():
    form_data = dict(request.form)  # 更保险
    email = form_data.get("email", "<none>")
    password = form_data.get("password", "<none>")

    with open(log_path, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            request.remote_addr,
            request.headers.get("User-Agent"),
            request.method,
            request.path,
            email,
            password
        ])
    return render_template_string(fake_login_html)





if __name__ == "__main__":
    app.run(port=5000)
