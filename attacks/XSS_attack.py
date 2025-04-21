"""
This module demos a XSS attack. 
After running and go to the website page simulate for the comment function of an online shopping website.
When you enter something, for example like: Hello XSS! <script>alert("Triggered!")</script> in the comment area,
A window will pop up on the web page saying Triggered! 
This means that the browser has executed the script, and the attacker can steal cookies or control the interface.
 """



from flask import Flask, request, render_template_string

app = Flask(__name__)
comments = []


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        comment = request.form["comment"]
        comments.append(comment) 

    html_template = """
    <!DOCTYPE html>
    <html>
    <head><title>XSS Demo</title></head>
    <body>
        <h2>🛍️ XSS Demo Comment Box</h2>
        <form method="POST">
            <textarea name="comment" rows="4" cols="60" placeholder="Leave your comment here..."></textarea><br>
            <button type="submit">Submit</button>
        </form>

        <h3>All Comments:</h3>
        {% for comment in comments %}
            <div style="border:1px solid #ccc; padding:10px; margin-top:10px;">
                {{ comment | safe }}
            </div>
        {% endfor %}
    </body>
    </html>
    """
    return render_template_string(html_template, comments=comments)

if __name__ == "__main__":
    app.run(debug=True)
