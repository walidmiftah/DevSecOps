from flask import Flask, request, jsonify
import sqlite3
import hashlib

app = Flask(__name__)

# Fonction pour hasher le mot de passe
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")

    # Hash du mot de passe
    hashed_password = hash_password(password)

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # ✅ REQUÊTE SQL SÉCURISÉE (empêche SQL Injection)
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, hashed_password))

    result = cursor.fetchone()

    conn.close()

    if result:
        return jsonify({"status": "success", "user": username})
    else:
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
