# compose_flask/app.py
from flask import Flask,request,jsonify
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from lib import *
from config import *
import os, errno, json, re, sys
from urllib.parse import urlparse


app = Flask(__name__)
auth = HTTPBasicAuth()


users = {
    "service_keystore": generate_password_hash(access_pwd)
}

class LazyDecoder(json.JSONDecoder):
    def decode(self, s, **kwargs):
        regex_replacements = [
            (re.compile(r'([^\\])\\([^\\])'), r'\1\\\\\2'),
            (re.compile(r',(\s*])'), r'\1')
        ]
        for regex, replacement in regex_replacements:
            s = regex.sub(replacement, s)
        return super().decode(s, **kwargs)


@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username


@app.route('/set_keyfile', methods=['POST'])
@auth.login_required
def set_keyfile():

    o = urlparse(request.base_url)
    host = o.hostname
    return_value="No json payload sent!"

    if request.data:
        data = request.get_json(force=True)

    if "host" in data:
        host = data["host"]

    try:
        os.mkdir("credentials/" + host)
    except OSError:
        return_value = {
            "success": "ko",
            "message": "Creation of the directory credentials/host failed"
        }
    try:
        return_value = write_key(host)
    except OSError:
        return_value = {
            "success": "ko",
            "message": "Error: write_key"
        }
        return return_value
    
    return jsonify(return_value)

@app.route('/set_password', methods=['POST'])
@auth.login_required
def set_password():

    o = urlparse(request.base_url)
    host = o.hostname
    return_value="No json payload sent!"

    if request.data:
        data = json.loads(request.data, cls=LazyDecoder)
        
        if "username" not in data or "password" not in data or "service" not in data or data["username"] == "" or data["password"] == "" or data["service"] == "":
            return_value={
                "message": "Parameters needed: username,password,service,host(not mandatory)"
            }
            return jsonify(return_value), 400

        if len(re.findall(r"\\+", data["password"])) or len(re.findall(r"\\+", data["username"])) or len(re.findall(r"\\+", data["service"])):
            return_value={
                "message": "Invalid character backslash"
            }
            return jsonify(return_value), 400

        if "host" in data:
            host = data["host"]
    
        return_value = write_password(data["username"],data["password"],data["service"],host)

        encrypt(host)

    return jsonify(return_value)

@app.route('/get_password', methods=['POST'])
@auth.login_required
def get_password():
    o = urlparse(request.base_url)
    host = o.hostname
    return_value="No json payload sent!"

    if request.data:
        data = request.get_json(force=True)

        if "username" not in data or "service" not in data or data["username"] == "" or data["service"] == "":
            return_value={
                "message": "Parameters needed: username,service,host(not mandatory)"
            }
            return jsonify(return_value), 400

        if "host" in data:
            host = data["host"]

        return_value = read_password(data["username"],data["service"],host)
    
        encrypt(host)
    
    return return_value

@app.route('/update_password', methods=['POST'])
@auth.login_required
def update_password():
    o = urlparse(request.base_url)
    host = o.hostname
    return_value="No json payload sent!"

    if request.data:
        data = request.get_json(force=True)

        if "username" not in data or "password" not in data or "service" not in data or data["username"] == "" or data["password"] == "" or data["service"] == "":
            return_value={
                "message": "Parameters needed: username,password,service,host(not mandatory)"
            }
            return jsonify(return_value), 400

        if "host"in data:
            host = data["host"]
    
        return_value = change_password(data["username"],data["password"],data["service"],host)

        encrypt(host)

    return jsonify(return_value)

@app.route('/delete_password', methods=['POST'])
@auth.login_required
def delete_password():
    o = urlparse(request.base_url)
    host = o.hostname
    return_value="No json payload sent!"
    
    if request.data:
        data = request.get_json(force=True)

        if "username" not in data or "service" not in data or data["username"] == "" or data["service"] == "":
            return_value={
                "message": "Parameters needed: username,service,host(not mandatory)"
            }
            return jsonify(return_value), 400

        if "host" in data:
            host = data["host"]

        return_value = del_password(data["username"],data["service"],host)

        encrypt(host)

    return jsonify(return_value)

@app.route('/get_users', methods=['POST'])
@auth.login_required
def get_users():
    o = urlparse(request.base_url)
    host = o.hostname
    return_value="No json payload sent!"

    if request.data:
        data = request.get_json(force=True)

        if "host" in data:
            host = data["host"]

    return_value = list_users(host)

    encrypt(host)

    return return_value
    

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
