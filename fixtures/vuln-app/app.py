"""Intentionally vulnerable demo app for PatchProof AI (DO NOT deploy)."""
import html
import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, request, render_template_string

app = Flask(__name__)

API_KEY = "sk-live-abcdef123456"  # PY-SECRET-001


def get_user(name):
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")  # PY-SQLI-001
    return cur.fetchall()


@app.route("/run")
def run():
    cmd = request.args.get("cmd", "ls")
    return subprocess.run(f"ls {cmd}", shell=True, capture_output=True, text=True).stdout  # PY-CMDI-001


@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    return render_template_string("<h1>hello " + name + "</h1>")  # PY-XSS-001


@app.route("/read")
def read():
    filename = request.args.get("file", "notes.txt")
    with open(f"/srv/data/{filename}") as fh:  # PY-PATHTRAV-001
        return fh.read()


@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))  # PY-DESER-001


@app.route("/yaml", methods=["POST"])
def load_yaml():
    return str(yaml.load(request.data))  # PY-DESER-001


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "https://example.com")
    return requests.get(f"{url}", timeout=5).text[:500]  # PY-SSRF-001


@app.route("/safe")
def safe():
    name = html.escape(request.args.get("name", "world"))
    return f"<h1>hello {name}</h1>"


if __name__ == "__main__":
    app.run()
