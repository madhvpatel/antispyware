# auth.py with JWT + MongoDB + OTP + Google OAuth
import os
import random
import smtplib
import time
import jwt
import bcrypt
import streamlit as st
from datetime import datetime, timedelta
from email.message import EmailMessage
from authlib.integrations.requests_client import OAuth2Session
import webbrowser, http.server, socketserver, threading

from db import get_user, create_user

# === JWT Configuration ===
JWT_SECRET = os.getenv("JWT_SECRET", "your_super_secret_key")
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_SECONDS = 3600  # 1 hour

# === Constants ===
OTP_STORE = {}
GOOGLE_CLIENT_ID = "YOUR_GOOGLE_CLIENT_ID"
GOOGLE_CLIENT_SECRET = "YOUR_GOOGLE_CLIENT_SECRET"
REDIRECT_URI = "http://localhost:8080"

# === Security Utilities ===
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(hashed_password, password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def generate_jwt(email: str):
    payload = {
        "email": email,
        "exp": datetime.utcnow() + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_jwt(token: str):
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return decoded
    except jwt.ExpiredSignatureError:
        st.error("Session expired. Please login again.")
        return None
    except jwt.InvalidTokenError:
        st.error("Invalid token.")
        return None

# === Email OTP ===
def send_otp_email(receiver_email, otp):
    msg = EmailMessage()
    msg.set_content(f"Your OTP for registration is: {otp}")
    msg["Subject"] = "Your Signup OTP"
    msg["From"] = "mrudula.s@somaiya.edu"
    msg["To"] = receiver_email

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login("mrudula.s@somaiya.edu", "zqlvitolsfbhgiuy")
            server.send_message(msg)
        return True
    except Exception as e:
        st.error(f"Failed to send OTP: {e}")
        return False

# === MongoDB Authentication ===
def signup_user(first_name, last_name, email, password):
    if get_user(email):
        return False, "Email already registered."
    user_data = {
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "password": hash_password(password),
        "created_at": datetime.utcnow()
    }
    create_user(user_data)
    return True, "Account created successfully."

def authenticate_user(email, password):
    user = get_user(email)
    if user and verify_password(user["password"], password):
        return True, user
    return False, None

# === Google OAuth2 ===
def start_auth_server():
    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            if "code=" in self.path:
                query = self.path.split("?")[1]
                params = dict(qc.split("=") for qc in query.split("&"))
                self.server.auth_code = params.get("code")
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body><h1>Login successful. You can close this window.</h1></body></html>")
            else:
                self.send_error(404)
    PORT = 8080
    server = socketserver.TCPServer(("", PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server

def google_oauth_login():
    oauth = OAuth2Session(
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        scope="openid email profile",
        redirect_uri=REDIRECT_URI
    )
    authorization_url, state = oauth.create_authorization_url(
        "https://accounts.google.com/o/oauth2/auth"
    )
    st.markdown("[Click here to login with Google](%s)" % authorization_url)
    st.info("After logging in, return to this tab.")
    server = start_auth_server()
    webbrowser.open(authorization_url)
    st.warning("Waiting for Google login in browser...")
    while not hasattr(server, "auth_code"):
        pass
    token = oauth.fetch_token(
        "https://oauth2.googleapis.com/token",
        authorization_response=f"{REDIRECT_URI}?code={server.auth_code}",
        code=server.auth_code
    )
    resp = oauth.get("https://www.googleapis.com/oauth2/v1/userinfo")
    user_info = resp.json()
    # Create or update user
    if not get_user(user_info["email"]):
        create_user({
            "first_name": user_info.get("given_name", ""),
            "last_name": user_info.get("family_name", ""),
            "email": user_info["email"],
            "created_at": datetime.utcnow(),
            "google_auth": True
        })
    st.success(f"Welcome {user_info['email']}!")
    st.session_state.jwt = generate_jwt(user_info["email"])
    st.session_state.authenticated = True
    st.session_state.user = user_info["email"]
    server.shutdown()

# === Streamlit Auth Page ===
def login_signup_page():
    st.title("🔐 Login or Sign Up")
    auth_mode = st.radio("Select an option:", ["Login", "Sign Up"])

    if auth_mode == "Sign Up":
        with st.form("signup_form"):
            first_name = st.text_input("First Name")
            last_name = st.text_input("Last Name")
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            confirm = st.text_input("Confirm Password", type="password")
            otp_input = st.text_input("Enter OTP sent to email")
            send_otp_btn = st.form_submit_button("Send OTP to Email")
            submit = st.form_submit_button("Create Account")

            if send_otp_btn:
                if not email:
                    st.warning("Please enter your email above first.")
                else:
                    otp = str(random.randint(100000, 999999))
                    if send_otp_email(email, otp):
                        OTP_STORE[email] = otp
                        st.success("OTP sent to your email address.")

            if submit:
                if not all([first_name, last_name, email, password, confirm, otp_input]):
                    st.error("Please fill out all fields and enter OTP.")
                elif password != confirm:
                    st.error("Passwords do not match.")
                elif OTP_STORE.get(email) != otp_input:
                    st.error("Invalid or missing OTP.")
                else:
                    success, msg = signup_user(first_name, last_name, email, password)
                    if success:
                        st.success(msg)
                        st.session_state.jwt = generate_jwt(email)
                        st.session_state.authenticated = True
                        st.session_state.user = email
                        del OTP_STORE[email]
                    else:
                        st.error(msg)

    else:
        st.subheader("Login with Google")
        if st.button("Login via Google"):
            google_oauth_login()

        st.markdown("---")
        st.subheader("Or login with email")
        with st.form("login_form"):
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            login_btn = st.form_submit_button("Login")
            if login_btn:
                success, user_data = authenticate_user(email, password)
                if success:
                    st.success("Login successful.")
                    token = generate_jwt(email)
                    st.session_state.jwt = token
                    st.session_state.authenticated = True
                    st.session_state.user = email
                else:
                    st.error("Invalid email or password.")