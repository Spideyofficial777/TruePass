from flask import Flask, render_template, request, redirect, session
import random, os, json

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Master password
MASTER_PASSWORD = "love123"

# OTP file
OTP_FILE = "otp.json"

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form["password"] == MASTER_PASSWORD:
            session["logged_in"] = True
            return redirect("/generate")
    return render_template("login.html")

@app.route("/generate", methods=["GET", "POST"])
def generate_otp():
    if not session.get("logged_in"):
        return redirect("/")
    otp = None
    if request.method == "POST":
        otp = str(random.randint(100000, 999999))
        with open(OTP_FILE, "w") as f:
            json.dump({"otp": otp}, f)
    else:
        otp = None
    return render_template("generate.html", otp=otp)

@app.route("/verify", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        password = request.form["password"]
        entered_otp = request.form["otp"]
        if password == MASTER_PASSWORD:
            try:
                with open(OTP_FILE) as f:
                    data = json.load(f)
                    if entered_otp == data["otp"]:
                        os.remove(OTP_FILE)
                        return render_template("success.html")
            except:
                pass
        return render_template("fail.html")
    return render_template("verify.html")

if __name__ == "__main__":
    app.run(debug=True)
