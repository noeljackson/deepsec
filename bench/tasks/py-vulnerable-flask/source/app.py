from flask import Flask, request
import requests
import sqlite3
import ast

app = Flask(__name__)


@app.get("/proxy")
def proxy():
    response = requests.get(request.args.get("url"))
    return response.text


@app.get("/calculate")
def calculate():
    return str(eval(request.args.get("expr")))


@app.get("/users")
def users():
    db = sqlite3.connect("users.db")
    return str(db.execute(f"SELECT * FROM users WHERE name = '{request.args.get('name')}'").fetchall())


@app.get("/health")
def health():
    response = requests.get("https://status.example.com/health")
    return response.text


@app.get("/literal")
def literal():
    return str(ast.literal_eval(request.args.get("value", "{}")))


@app.get("/users-safe")
def users_safe():
    db = sqlite3.connect("users.db")
    return str(db.execute("SELECT * FROM users WHERE name = ?", (request.args.get("name"),)).fetchall())
