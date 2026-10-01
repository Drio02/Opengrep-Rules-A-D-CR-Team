import os
import pickle
import re
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, redirect, render_template_string, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
db = sqlite3.connect("app.db")


@app.route("/user")
def user():
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cur = db.cursor()
    # ruleid: py-taint-sqli
    cur.execute(query)
    # ok: py-taint-sqli
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    uid = int(request.args.get("id"))
    # ok: py-taint-sqli
    cur.execute("SELECT * FROM users WHERE id = %d" % uid)
    return "ok"


@app.route("/note/<note_id>")
def note(note_id):
    sql = f"SELECT body FROM notes WHERE id = {note_id}"
    # ruleid: py-taint-sqli
    db.execute(sql)
    return "ok"


@app.post("/login")
def login():
    creds = request.get_json()
    # ruleid: py-taint-nosqli
    user = mongo.db.users.find_one(creds)
    # ok: py-taint-nosqli
    user = mongo.db.users.find_one({"username": str(creds["username"])})
    return str(user)


@app.route("/ping")
def ping():
    host = request.args["host"]
    cmd = "ping -c 1 " + host
    # ruleid: py-taint-command-injection
    os.system(cmd)
    # ruleid: py-taint-command-injection
    subprocess.run(cmd, shell=True)
    # ok: py-taint-command-injection
    subprocess.run(["ping", "-c", "1", host])
    return "ok"


@app.route("/calc")
def calc():
    expr = request.form["expr"]
    # ruleid: py-taint-code-injection
    return str(eval(expr))


@app.route("/download")
def download():
    filename = request.args.get("file")
    path = os.path.join("/srv/uploads", filename)
    # ruleid: py-taint-path-traversal
    return send_file(path)


@app.route("/download2")
def download2():
    filename = secure_filename(request.args.get("file"))
    path = os.path.join("/srv/uploads", filename)
    # ok: py-taint-path-traversal
    return send_file(path)


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    # ruleid: py-taint-ssrf
    return requests.get(url, timeout=3).text


@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    tpl = "<h1>Hello " + name + "</h1>"
    # ruleid: py-taint-ssti
    html = render_template_string(tpl)
    # ok: py-taint-ssti
    html = render_template_string("<h1>Hello {{ n }}</h1>", n=name)
    return html


@app.route("/greet")
def greet():
    template = request.args.get("t")
    # ruleid: py-taint-format-string-injection
    return template.format(user=current_user)


@app.route("/import", methods=["POST"])
def import_data():
    blob = request.get_data()
    # ruleid: py-taint-deserialization
    obj = pickle.loads(blob)
    # ruleid: py-taint-deserialization
    cfg = yaml.load(blob, Loader=yaml.Loader)
    # ok: py-taint-deserialization
    cfg = yaml.load(blob, Loader=yaml.SafeLoader)
    return str(obj)


@app.route("/next")
def next_page():
    target = request.args.get("next")
    # ruleid: py-taint-open-redirect
    return redirect(target)


@app.route("/search")
def search():
    pattern = request.args.get("q")
    # ruleid: py-taint-regex-injection
    hits = [n for n in NOTES if re.search(pattern, n)]
    # ok: py-taint-regex-injection
    hits = [n for n in NOTES if re.search(re.escape(pattern), n)]
    return str(hits)
