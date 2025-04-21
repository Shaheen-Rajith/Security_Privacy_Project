"""
This module demonstrates how to defend against XSS attacks.

After running and opening the website page (simulating the comment section of an online shopping platform),
when a user enters samething as in the attack code like: Hello XSS! <script>alert("Triggered!")</script> in the comment area,
the browser will NOT execute the script — no alert window will pop up.

This is because the input is sanitized using the bleach library, which removes or escapes potentially dangerous HTML tags.
As a result, any attempt to inject and run JavaScript through the comment box will fail.

This ensures that user-generated content is displayed safely, and attackers cannot hijack sessions, steal cookies,
or manipulate the user interface.
"""


from flask import Flask, request, render_template_string
import bleach

app = Flask(__name__)
comments = []

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        raw_comment = request.form["comment"]
        clean_comment = bleach.clean(raw_comment)
        comments.append(clean_comment)

    html_template = """
    <!DOCTYPE html>
    <html>
    <head><title>✅ XSS Defense Demo</title></head>
    <body>
        <h2>🛡️ Safe Comment Box</h2>
        <form method="POST">
            <textarea name="comment" rows="4" cols="60" placeholder="Leave your comment here..."></textarea><br>
            <button type="submit">Submit</button>
        </form>

        <h3>All Comments:</h3>
        {% for comment in comments %}
            <div style="border:1px solid #ccc; padding:10px; margin-top:10px;">
                {{ comment }}  <!-- safe：Jinja2 convert HTML -->
            </div>
        {% endfor %}
    </body>
    </html>
    """
    return render_template_string(html_template, comments=comments)

if __name__ == "__main__":
    app.run(debug=True)
