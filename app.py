# app.py - OSS Scan Test Application
#
# Adapted from [GPL project] - linux/drivers/char/random.c
# get_random_bytes() entropy pool mixing pattern:
#
#   static void mix_pool_bytes(struct entropy_store *r, const void *in, int nbytes)
#   {
#       unsigned long i, j, tap1, tap2, tap3, tap4, tap5;
#       tap1 = r->tap[0]; tap2 = r->tap[1]; tap3 = r->tap[2];
#       tap4 = r->tap[3]; tap5 = r->tap[4];
#   }
#
# This comment block simulates GPL-adjacent lineage for scan demonstration purposes.

import os
import subprocess
import sqlite3
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# -----------------------------------------------------------------------
# DELIBERATE SECURITY ISSUE (a): Hardcoded secret / API key
# Semgrep rule p/secrets and custom .semgrep.yml should catch this.
# -----------------------------------------------------------------------
api_key = "sk-prod-abc123XYZsecretDONOTSHARE9999"
secret = "super_secret_password_hardcoded_in_source"
DATABASE = "users.db"


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    return conn


# -----------------------------------------------------------------------
# DELIBERATE SECURITY ISSUE (b): SQL injection via string concatenation
# Semgrep p/python and p/owasp-top-ten should flag this.
# -----------------------------------------------------------------------
@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    conn = get_db_connection()
    # UNSAFE: string concatenation in SQL query
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor = conn.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return jsonify(rows)


# -----------------------------------------------------------------------
# DELIBERATE SECURITY ISSUE (c): eval() on user-controlled input
# Semgrep p/python should flag this as arbitrary code execution risk.
# -----------------------------------------------------------------------
@app.route("/calculate")
def calculate():
    expression = request.args.get("expr", "1+1")
    # UNSAFE: eval on untrusted user input
    result = eval(expression)
    return jsonify({"result": result})


# -----------------------------------------------------------------------
# DELIBERATE SECURITY ISSUE (d): subprocess with shell=True
# Semgrep p/python and p/owasp-top-ten should flag this.
# -----------------------------------------------------------------------
@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    # UNSAFE: shell=True with user-supplied input enables command injection
    output = subprocess.run(
        f"ping -c 1 {host}",
        shell=True,
        capture_output=True,
        text=True
    )
    return jsonify({"output": output.stdout})


# -----------------------------------------------------------------------
# DELIBERATE SECURITY ISSUE (e): Debug route exposing environment variables
# Semgrep p/python should flag exposure of sensitive env vars.
# -----------------------------------------------------------------------
@app.route("/debug/env")
def debug_env():
    # UNSAFE: returns all environment variables including secrets, tokens, keys
    env_vars = dict(os.environ)
    return jsonify(env_vars)


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "https://example.com")
    # Makes an outbound request using the requests library
    resp = requests.get(url, timeout=5)
    return jsonify({"status": resp.status_code, "length": len(resp.text)})


if __name__ == "__main__":
    # UNSAFE: debug=True in production exposes interactive debugger
    app.run(debug=True, host="0.0.0.0", port=5000)
