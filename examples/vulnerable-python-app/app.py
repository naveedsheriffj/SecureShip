from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/")
def index():
    return jsonify({
        "status": "online",
        "warning": "This app contains known vulnerabilities and should be BLOCKED by SecureShip",
        "version": "0.1.0-insecure"
    })

@app.route("/health")
def health():
    return jsonify({"status": "vulnerable"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
