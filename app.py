import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash


from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    username = db.execute(
        "SELECT * FROM users WHERE id = ?", session["user_id"])
    data = db.execute("SELECT * FROM buy WHERE username = ? ",
                      username[0]["username"])
    for cash in username:
        diff = cash["cash"]

    return render_template("homepage.html", datas=data, diff=diff)
    # return apology("whose your daddy",401)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    username = db.execute(
        "SELECT username FROM users WHERE id = ?", session["user_id"])
    if request.method == "POST":
        total = 0
        shares = request.form.get("shares")
        symbol = request.form.get("symbol")
        symbol = symbol.upper()
        quote_Dict = lookup(symbol)
        if quote_Dict == None:
            return apology("This Quote Symbol Does not exist", 400)

        try:
            float(shares)
        except ValueError:
            # If the conversion fails, the value is non-numeric
            return apology("Input must be of numerical value", 400)

        try:
            int(shares)
        except ValueError:
            # If the conversion fails, the value is non-numeric
            return apology("Input must not be a fractional value", 400)

        if int(shares) <= 0:
            return apology("Must input a positive integer", 400)
        else:
            #username = db.execute("SELECT username FROM users WHERE id = ?",session["user_id"])
            shares = float(shares)

            symbol_found = False
            symbols = db.execute(
                "SELECT symbol from buy WHERE username = ?", username[0]["username"])
            for s in symbols:
                if s["Symbol"] == symbol:
                    the_total = db.execute(
                        "SELECT total FROM buy WHERE username = ? AND symbol = ?", username[0]["username"], symbol)
                    total = 0
                    for t in the_total:
                        total = total + t["total"]
                        print(t["total"], "FUCK")
                    total = total + float(quote_Dict["price"]) * shares
                    total = float(total)
                    the_shares = db.execute(
                        "SELECT NumberOfShares FROM buy WHERE username = ? AND symbol = ?", username[0]["username"], symbol)
                    for the_share in the_shares:
                        shares = shares + the_share["NumberOfShares"]
                    db.execute("UPDATE buy SET NumberOfShares=? ,Symbol = ?,price= ?,total=? WHERE username = ?",
                               shares, symbol, quote_Dict["price"], total, username[0]["username"])
                    symbol_found = True
                    break
            if not symbol_found:
                total = float(quote_Dict["price"]) * shares
                db.execute("INSERT INTO buy (NumberOfShares,Symbol,username,price,total) VALUES(?,?,?,?,?)",
                           shares, symbol, username[0]["username"], quote_Dict["price"], total)
            money = db.execute(
                "SELECT cash FROM users WHERE id = ? ", session["user_id"])
            for funds in money:
                cash = funds["cash"]

            cash = cash - total

            db.execute("UPDATE users SET cash = ? WHERE username = ?",
                       cash, username[0]["username"])
            return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        quote = request.form.get("symbol")
        quote = quote.upper()
        quote_Dict = lookup(quote)
        if quote_Dict == None:
            return apology("This Quote Symbol Does not exist", 400)
    else:
        return render_template("/quote.html")

    return render_template("/quoted.html", quote_Dict=quote_Dict)

    # return apology("TODO")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    check_username = db.execute("SELECT * FROM users")
    if request.method == "POST":
        userName = request.form.get("username")
        password = request.form.get("password")
        verify = request.form.get("confirmation")
        for check in check_username:
            if userName == check["username"]:
                return apology("Username already exists", 400)

        if(userName and password and verify):
            if verify == password:
                hash = generate_password_hash(password)
                db.execute(
                    "INSERT INTO users (username,hash) VALUES(?,?) ", userName, hash)
            else:
                return apology("You verification password does not match", 400)
        else:
            return apology("Please fill out all fields", 400)
    else:
        return render_template("register.html")
    return render_template("/login.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    username = db.execute(
        "SELECT * FROM users WHERE id = ?", session["user_id"])
    bought = db.execute(
        "SELECT * FROM buy WHERE username = ?", username[0]["username"])
    if request.method == "POST":
        shares = request.form.get("shares")
        selected_symbol = request.form.get("symbol")
        for buy in bought:
            if int(buy["NumberOfShares"]) == 0:
                db.execute("DELETE FROM buy WHERE NumberOfShares = 0")
            if buy["NumberOfShares"] == 0 and buy["Symbol"] == selected_symbol:
                return apology("I'm sorry but it seems that you dont have any shares in this stock", 400)
            elif int(buy["NumberOfShares"]) < int(shares) and buy["Symbol"] == selected_symbol:
                return apology("Insufficient shares", 400)
            elif buy["NumberOfShares"] != 0 and buy["Symbol"] == selected_symbol:
                new_Shares = int(buy["NumberOfShares"]) - int(shares)

            if selected_symbol not in buy["Symbol"]:
                return apology("You don't have shares in this stock", 400)

        db.execute("UPDATE buy SET NumberOfShares = ? WHERE username = ?",
                   new_Shares, username[0]["username"])

        check_shares = db.execute(
            "SELECT * FROM buy WHERE username = ?", username[0]["username"])
        for c in check_shares:
            if c["NumberOfShares"] == 0:
                db.execute("DELETE FROM buy WHERE Symbol = ?", c["Symbol"])
            total = c["NumberOfShares"] * c["price"]
            remainder = int(shares) * int(c["price"])
        db.execute("UPDATE buy SET total = ? WHERE username = ?",
                   total, username[0]["username"])

        for user in username:
            cash = user["cash"]
        cash = cash + remainder
        db.execute("UPDATE users SET cash = ? WHERE id = ?",
                   cash, session["user_id"])

        try:
            float(shares)
        except ValueError:
            # If the conversion fails, the value is non-numeric
            return apology("Input must be of numerical value", 400)

        try:
            int(shares)
        except ValueError:
            # If the conversion fails, the value is non-numeric
            return apology("Input must not be a fractional value", 400)

        if int(shares) <= 0:
            return apology("Must input a positive integer", 400)

        return redirect("/")

    else:
        return render_template("sell.html", bought=bought)
    # return apology("TODO")


@app.route("/password_change", methods=["GET", "POST"])
def change_password():
    proceed = False
    if request.method == "POST":
        user = request.form.get("username")
        old = request.form.get("old")
        new = request.form.get("new_password")
        confirmed = request.form.get("confirmation")
        the_hash = db.execute("SELECT * FROM users")
        for h in the_hash:
            if check_password_hash(h["hash"], old) == True and h["username"] == user:
                proceed = True
                break
        if proceed:
            if(confirmed and new):
                if new == confirmed:
                    new_hash = generate_password_hash(new)
                    db.execute(
                        "UPDATE users SET hash = ? WHERE username = ?", new_hash, user)
                    return redirect("/login")
                else:
                    return apology("You verification password does not match", 400)
            else:
                return apology("Please fill out all fields", 400)
        else:
            return apology("Old password is incorrect", 400)
    else:
        return render_template("/password_change.html")
# return render_template("/password_change.html")
