import imp
import os
import json
import sqlite3
import requests
from oauthlib.oauth2 import WebApplicationClient
from flask import Flask, request, redirect, url_for
from flask_login import LoginManager, current_user, login_required, login_user, logout_user

from user import User
from db import init_db_command


AZURE_CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", None)
AZURE_CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET", None)
AZURE_DISCOVERY_URL = (
    "https://login.microsoftonline.com/7b92c877-5b08-4dde-b025-ae827f46bfed/v2.0/.well-known/openid-configuration"
)

azapp = Flask(__name__)
azapp.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

login_manager = LoginManager()
login_manager.init_app(azapp)

try:
    init_db_command()
except sqlite3.OperationalError:
    # Assume it's already been created
    pass

client = WebApplicationClient(AZURE_CLIENT_ID)

# Flask-Login helper to retrieve a user from our db
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@azapp.route("/")
def index():
    if current_user.is_authenticated:
        return (
            "<p>Hello, {}! You're logged in! Email: {}</p>"
            "<div><p>Azure Profile Picture:</p>"
            '<img src="{}" alt="Azure profile pic"></img></div>'
            '<a class="button" href="/logout">Logout</a>'.format(
                current_user.name, current_user.email, current_user.profile_pic
            )
        )
    else:
        return '<a class="button" href="/login">Azure Login</a>'

def get_azure_provider_cfg():
    return requests.get(AZURE_DISCOVERY_URL).json()

@azapp.route("/login")
def login():
    azure_provider_cfg = get_azure_provider_cfg()
    authorization_endpoint = azure_provider_cfg["authorization_endpoint"]

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri = request.base_url+"/callback",
        scope=["openid", "email", "profile"],
    )

    print(request_uri)

    return redirect(request_uri)

@azapp.route("/login/callback")
def callback():
    code = request.args.get("code")
    print("******* CODE *********")
    print(code)

    azure_provider_cfg = get_azure_provider_cfg()
    token_endpoint = azure_provider_cfg["token_endpoint"]

    print("******* request.url & request.base_url **********")
    print(request.url)
    print(request.base_url)

    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response = request.url,
        redirect_url = request.base_url,
        code = code
    )

    print("******* token_url **********")
    print(token_url)
    print("******* headers **********")
    print(headers)
    print("******* body **********")
    print(body)


    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
    )

    print("******* token_response **********")
    print(token_response)
    print(token_response.json())

    client.parse_request_body_response(json.dumps(token_response.json()))

    userinfo_endpoint = azure_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]

    else:
        return "User email not available or not verified by Azure.", 400
    
    user = User(
        id_=unique_id, name=users_name, email=users_email, profile_pic=picture
    )

    if not User.get(unique_id):
        User.create(unique_id, users_name, users_email, picture)

    login_user(user)

    return redirect(url_for("index"))

@azapp.route("/logout")
@login_required
def logout():
    logout_user()

    return redirect(url_for("index"))

if __name__ == "__main__":
    azapp.run(ssl_context="adhoc", debug=True, port=5001)