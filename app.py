# app.py (Enhanced with Beautiful Email Format)
import os
import ssl
import smtplib
import secrets
import logging
from datetime import datetime, timedelta
from email.message import EmailMessage

from flask import Flask, render_template, request, redirect, session, flash, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email
from email_validator import validate_email, EmailNotValidError
from threading import Lock

# === Configuration ===
app = Flask(__name__)
app.secret_key = os.urandom(32)

MASTER_PASSWORD = os.getenv("MASTER_PASSWORD", "love123")
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS", "gaminghatyar777@gmail.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "lebpoqtjsucwkbuk")
OTP_EXPIRY_MINUTES = 5
MAX_CHAT_MESSAGES = 50

# === Logging Setup ===
logger = logging.getLogger("SecureLogin")
logger.setLevel(logging.INFO)
handler = logging.FileHandler("login_attempts.log")
formatter = logging.Formatter('%(asctime)s - %(ip)s - %(user_agent)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# === In-Memory OTP Store ===
otp_store = {}
otp_lock = Lock()

# === Forms ===
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Master Password", validators=[DataRequired()])
    submit = SubmitField("🔐 Request OTP")

class VerifyForm(FlaskForm):
    password = PasswordField("Master Password", validators=[DataRequired()])
    otp = StringField("OTP", validators=[DataRequired()])
    submit = SubmitField("✅ Verify OTP")

class DynamicPassForm(FlaskForm):
    dyn_pass = StringField("Dynamic Password", validators=[DataRequired()])
    submit = SubmitField("🔑 Validate")

class ChatForm(FlaskForm):
    message = TextAreaField("Message", validators=[DataRequired()], render_kw={"rows": 3})
    submit = SubmitField("📤 Send")

# === Helper Functions ===
def log_attempt(ip, user_agent, message):
    logger.info(message, extra={"ip": ip, "user_agent": user_agent})

def send_otp_email(to_email, otp):
    subject = "🔐 Your Secure One-Time Password"
    html_content = f"""
    <html>
      <body style='font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;'>
        <div style='max-width: 600px; margin: auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);'>
          <h2 style='color: #2c3e50;'>🔐 Your One-Time Password</h2>
          <p>Hello,</p>
          <p>Your OTP for secure login is:</p>
          <h1 style='background-color: #2ecc71; color: white; padding: 15px; border-radius: 5px; text-align: center;'>{otp}</h1>
          <p style='font-size: 14px; color: #7f8c8d;'>This OTP will expire in {OTP_EXPIRY_MINUTES} minutes.</p>
          <p>Please do not share this OTP with anyone.</p>
          <hr style='margin: 20px 0;'>
          <p style='font-size: 12px; color: #95a5a6;'>If you did not request this code, please ignore this email.</p>
          <p style='font-size: 12px; color: #95a5a6;'>Powered by Secure Login System</p>
        </div>
      </body>
    </html>
    """

    msg = EmailMessage()
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content("Your email client does not support HTML.")
    msg.add_alternative(html_content, subtype='html')

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)

def generate_otp():
    return f"{secrets.randbelow(900000) + 100000}"

def generate_dynamic_pass():
    return secrets.token_urlsafe(8)

def store_otp(email, otp):
    with otp_lock:
        otp_store[email] = {
            "otp": otp,
            "expires_at": datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)
        }

def verify_otp(email, otp):
    with otp_lock:
        record = otp_store.get(email)
        if not record or datetime.utcnow() > record["expires_at"]:
            otp_store.pop(email, None)
            return False
        if record["otp"] == otp:
            otp_store.pop(email, None)
            return True
        return False

# === Routes ===
@app.route("/", methods=["GET", "POST"])
def login():
    form = LoginForm()
    ip = request.remote_addr
    user_agent = request.headers.get("User-Agent")

    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        password = form.password.data.strip()

        try:
            validate_email(email)
        except EmailNotValidError:
            flash("❌ Invalid email address.", "danger")
            return render_template("login.html", form=form)

        if password != MASTER_PASSWORD:
            flash("❌ Incorrect master password.", "danger")
            log_attempt(ip, user_agent, f"Login failed for {email}: wrong password")
            return render_template("login.html", form=form)

        otp = generate_otp()
        store_otp(email, otp)
        try:
            send_otp_email(email, otp)
        except Exception as e:
            flash("❌ Failed to send OTP.", "danger")
            log_attempt(ip, user_agent, f"Email error for {email}: {str(e)}")
            return render_template("login.html", form=form)

        session.clear()
        session["email"] = email
        flash("✅ OTP sent to your email.", "success")
        return redirect(url_for("verify"))

    return render_template("login.html", form=form)

@app.route("/verify", methods=["GET", "POST"])
def verify():
    form = VerifyForm()
    ip = request.remote_addr
    user_agent = request.headers.get("User-Agent")
    email = session.get("email")

    if not email:
        flash("❌ Session expired.", "danger")
        return redirect(url_for("login"))

    if form.validate_on_submit():
        password = form.password.data
        otp_input = form.otp.data

        if password != MASTER_PASSWORD:
            flash("❌ Incorrect master password.", "danger")
            return render_template("verify.html", form=form)

        if not verify_otp(email, otp_input):
            flash("❌ Invalid or expired OTP.", "danger")
            return render_template("verify.html", form=form)

        session["dynamic_password"] = generate_dynamic_pass()
        session["validated_otp"] = True
        return redirect(url_for("dynamic_password"))

    return render_template("verify.html", form=form)

@app.route("/dynamic_password")
def dynamic_password():
    if not session.get("validated_otp"):
        flash("❌ Unauthorized access.", "danger")
        return redirect(url_for("login"))

    return render_template("dynamic_password.html", dyn_pass=session.get("dynamic_password"))

@app.route("/validate_password", methods=["GET", "POST"])
def validate_password():
    form = DynamicPassForm()
    ip = request.remote_addr
    user_agent = request.headers.get("User-Agent")

    if form.validate_on_submit():
        entered = form.dyn_pass.data.strip()
        actual = session.get("dynamic_password")

        if entered == actual:
            session["validated_dynamic"] = True
            flash("✅ Access granted!", "success")
            return redirect(url_for("chat"))
        else:
            flash("❌ Incorrect dynamic password.", "danger")

    return render_template("validate_password.html", form=form)

@app.route("/chat", methods=["GET", "POST"])
def chat():
    if not session.get("validated_dynamic"):
        flash("❌ Unauthorized.", "danger")
        return redirect(url_for("login"))

    form = ChatForm()
    messages = session.get("messages", [])

    if form.validate_on_submit():
        msg = form.message.data.strip()
        if msg:
            messages.append(msg)
            session["messages"] = messages[-MAX_CHAT_MESSAGES:]
            flash("📤 Message sent!", "success")
            return redirect(url_for("chat"))

    chat_html = "".join(f"<div class='p-2 bg-light text-dark rounded mb-2'>{m}</div>" for m in messages[-10:])
    return render_template("chat.html", form=form, chat_html=chat_html)

@app.route("/logout")
def logout():
    session.clear()
    flash("🔒 Logged out.", "info")
    return redirect(url_for("login"))

# === Run the app ===
if __name__ == "__main__":
    app.run(debug=True, port=5000)
