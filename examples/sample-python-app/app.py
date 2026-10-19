from flask import Flask, jsonify
import os

app = Flask(__name__)

@app.route("/")
def index():
    return jsonify({
        "status": "online",
        "service": "SecureShip Validated Service",
        "message": "This container successfully passed all SecureShip security gate checks!",
        "version": "1.0.0"
    })

@app.route("/health")
def health():
    return jsonify({
        "status": "healthy",
        "checks": {
            "application": "ok",
            "security_verified": True
        }
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
