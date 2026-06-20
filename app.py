"""
app.py
Flask application entry point.
"""

from flask import Flask, render_template, request, jsonify
from strength_checker import get_strength_score

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/check", methods=["POST"])
def check_password():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    result = get_strength_score(password)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)
