from flask import Flask, request, jsonify
import sqlite3
import subprocess
import bcrypt
import os
import re

app = Flask(__name__)

# Secret key stockée dans les variables d'environnement
SECRET_KEY = os.getenv("APP_SECRET_KEY", "fallback-secret")  


# ---------------------- LOGIN (Fix SQL Injection) ----------------------
@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # ❌ Ancien : SQL injection
    # query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

    # ✅ Fix : prepared statements
    query = "SELECT * FROM users WHERE username=?"
    cursor.execute(query, (username,))
    user = cursor.fetchone()

    if not user:
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    stored_hash = user[2].encode()

    if bcrypt.checkpw(password.encode(), stored_hash):
        return jsonify({"status": "success", "user": username})

    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


# ---------------------- PING (Fix Command Injection) ----------------------
@app.route("/ping", methods=["POST"])
def ping():
    host = request.json.get("host", "")

    # Filtre simple (évite ; && | etc.)
    if not re.match(r"^[a-zA-Z0-9\.\-]+$", host):
        return jsonify({"error": "Invalid hostname"}), 400

    # ❌ Ancien : shell=True => vulnérable
    # cmd = f"ping -c 1 {host}"
    # output = subprocess.check_output(cmd, shell=True)

    # ✅ Fix : sans shell
    try:
        output = subprocess.check_output(["ping", "-c", "1", host], text=True)
        return jsonify({"output": output})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e)}), 400


# ---------------------- COMPUTE (Fix eval) ----------------------
@app.route("/compute", methods=["POST"])
def compute():
    expression = request.json.get("expression", "1+1")

    # ❌ Ancien : eval(expression)
    # CRITIQUE – RCE

    # ✅ Fix : calcul limité aux nombres
    if not re.match(r"^[0-9\+\-\*\/\(\) ]+$", expression):
        return jsonify({"error": "Invalid expression"}), 400

    try:
        result = eval(expression, {"__builtins__": None}, {})
    except Exception:
        return jsonify({"error": "Computation error"}), 400

    return jsonify({"result": result})


# ---------------------- HASH PASSWORD (Fix MD5) ----------------------
@app.route("/hash", methods=["POST"])
def hash_password():
    pwd = request.json.get("password", "admin")

    # ❌ Ancien : hashlib.md5()
    # hashed = hashlib.md5(pwd.encode()).hexdigest()

    # ✅ Fix : bcrypt
    hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()

    return jsonify({"bcrypt": hashed})


# ---------------------- READ FILE (Fix Path Traversal) ----------------------
@app.route("/readfile", methods=["POST"])
def readfile():
    filename = request.json.get("filename", "test.txt")

    # Empêche ../../../etc/passwd
    if ".." in filename or filename.startswith("/"):
        return jsonify({"error": "Invalid filename"}), 400

    safe_path = os.path.join("files", filename)

    if not os.path.exists(safe_path):
        return jsonify({"error": "File not found"}), 404

    with open(safe_path, "r") as f:
        content = f.read()

    return jsonify({"content": content})


# ---------------------- DEBUG (No sensitive leak) ----------------------
@app.route("/debug", methods=["GET"])
def debug():
    return jsonify({
        "debug": False,
        "message": "Debug mode disabled for security"
    })


@app.route("/hello", methods=["GET"])
def hello():
    return {"message": "Welcome to the secure DevSecOps API"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
