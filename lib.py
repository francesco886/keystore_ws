from cryptography.fernet import Fernet
from pathlib import Path
from json.decoder import JSONDecodeError
import json, os


def write_key(file_name):
    """
    Generates a key and save it into a file inside credentials folder
    """
    secret_file = "credentials/" + file_name + "/" + file_name + ".key"
    secret_file_path = Path(secret_file)

    if secret_file_path.exists():
        return_value = {
            "success": "ko",
            "message": "Key file for " + file_name + " already exists!"
        }

        return return_value

    key = Fernet.generate_key()
    with open("credentials/" + file_name + "/" + file_name + ".key", "wb") as key_file:
        key_file.write(key)
    
    os.chmod("credentials/" + file_name + "/" + file_name + ".key", 0o600)

    return_value = {
        "success": "ok",
        "message": "Key file for " + file_name + " server created!"
    }
    return return_value


def write_password(username, password, host):
    """
    Add a credential record to credential store file
    """

    secret_file = "credentials/" + host + "/" + host + ".key"
    secret_file_path = Path(secret_file)
    credential_file = "credentials/" + host + "/" + host + ".txt"
    credential_file_path = Path(credential_file)

    # check if exists file.key
    if not secret_file_path.exists():
        return_value = {
            "success": "ko",
            "message": "Key file for " + host + " doesn't exists!"
        }

        return return_value

    # check if exists file.txt
    if not credential_file_path.exists():
        with open(credential_file, 'w'):
            try:
                f_credentials = open(credential_file, "w")
                f_credentials.write(username + ":" + password + "\n")
            except OSError:
                return_value = {
                    "success": "ko",
                    "message": "Error opening file " + credential_file + "!"
                }
                return return_value

            return_value = {
                "success": "ok",
                "message": "Added record for " + username + " in " + host + " file!"
            }
        
        return return_value

    # file .txt already present
    decrypt(host)

    # Check if is already present this record
    with open(credential_file, 'r+') as cf:
        for line in cf:
            if line.startswith(username):
                return_value = {
                    "success": "ko",
                    "message": "Record for " + username + " already exists in " + host + ".txt"
                }
                return return_value

    try:
        f_credentials = open(credential_file, "a+")
        f_credentials.write(username + ":" + password + "\n")
    except OSError:
        return_value = {
            "success": "ko",
            "message": "Error opening file " + credential_file + "!"
        }
        return return_value

    return_value = {
        "success": "ok",
        "message": "Added record for " + username + " in " + host + " file!"
    }

    return return_value

def read_password(username,host):
    """
    Read a credential record from credential store file
    """
    secret_file = "credentials/" + host + "/" + host + ".key"
    secret_file_path = Path(secret_file)
    credential_file = "credentials/" + host + "/" + host + ".txt"
    credential_file_path = Path(credential_file)

    if not credential_file_path.exists():
        return_value = {
            "success": "ko",
            "message": "No file present for host " + host + ".txt!"
        }
        return return_value
    
    decrypt(host)

    with open(credential_file, 'r+') as cf:
        for line in cf:
            if line.startswith(username):
                record_password_field = line.split(":")[-1].strip()
                return_value = {
                    "success" : "ok",
                    "message": record_password_field
                }

                return return_value
    return_value = {
        "success" : "ko",
        "message": "Record for " + username + " not found in " + host + ".txt file!"
    }

    return return_value


def change_password(username, password, host):
    """
    Change a credential record inside credential store file
    """
    secret_file = "credentials/" + host + "/" + host + ".key"
    secret_file_path = Path(secret_file)
    credential_file = "credentials/" + host + "/" + host + ".txt"
    credential_file_path = Path(credential_file)

    if not credential_file_path.exists():
        return_value = {
            "success": "ko",
            "message": "No file present for host " + host + "!"
        }
        return return_value
    
    decrypt(host)

    # Check if record exists
    with open(credential_file, 'r') as cf:
        lines = cf.readlines()
        record_exists = False
        for line in lines:
            if line.startswith(username):
                record_exists = True

        if not record_exists:
            return_value = {
                "success": "ko",
                "message": "No record present for user " + username + " in " + host + ".txt file!"
            }

            return return_value

    with open(credential_file, 'r+') as cf:
        lines = cf.readlines()
        output = []
        for line in lines:
            if not line.startswith(username):
                output.append(line)

    try:
        f_credentials = open(credential_file, "w")
        f_credentials.writelines(output)
        f_credentials.write(username + ":" + password + "\n")
        f_credentials.close()
    except OSError:
        return_value = {
            "success": "ko",
            "message": "Error opening file " + credential_file + "!"
        }
        return return_value

    
    return_value = {
        "success" : "ok",
        "message": "Password for " + username + " in " + host + ".txt updated correctly!"
    }

    return return_value

def del_password(username, host):
    """
    Delete a credential record from credential store file
    """
    secret_file = "credentials/" + host + "/" + host + ".key"
    secret_file_path = Path(secret_file)
    credential_file = "credentials/" + host + "/" + host + ".txt"
    credential_file_path = Path(credential_file)

    if not credential_file_path.exists():
        return_value = {
            "success": "ko",
            "message": "No file present for host " + host + "!"
        }
        return return_value
    
    decrypt(host)

    # Check if record exists
    with open(credential_file, 'r') as cf:
        lines = cf.readlines()
        record_exists = False
        for line in lines:
            if line.startswith(username):
                record_exists = True

        if not record_exists:
            return_value = {
                "success": "ko",
                "message": "No record present for user " + username + " in " + host + ".txt file!"
            }

            return return_value
    
    with open(credential_file, 'r+') as cf:
        output = []
        for line in cf:
            if not line.startswith(username):
                output.append(line)
    
    with open(credential_file, 'w') as cf:
        cf.writelines(output)
    
    return_value = {
        "success" : "ok",
        "message": "Removed record for user " + username + "!" 
    }

    return return_value


def encrypt(host):
    """
    Given a host name, it encrypts the file txt that matches the host and write it
    """
    key = load_key(host)

    if key == False:
        return_value={

            "message": "File " + host + "not present!"
        }
        return return_value
        
    f = Fernet(key)
    credential_file = "credentials/" + host + "/" + host + ".txt"

    with open(credential_file, "rb") as original_file:
        # read all file data
        original_data = original_file.read()

    # encrypt data
    encrypted_data = f.encrypt(original_data)

    # write the encrypted file
    with open(credential_file, "wb") as decrypted_file:
        decrypted_file.write(encrypted_data)


def decrypt(host):
    """
    Given a credential_file (str) and key (bytes), it decrypts the file and write it
    """
    key = load_key(host)

    if key == False:

        return_value={
            "message": "File " + host + "not present!"
        }
        return return_value
    
    f = Fernet(key)
    credential_file = "credentials/" + host + "/" + host + ".txt"
    
    with open(credential_file, "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()

    # decrypt data
    decrypted_data = f.decrypt(encrypted_data)
    
    # write the original file
    with open(credential_file, "wb") as enc_file:
        enc_file.write(decrypted_data)


def load_key(host):
    """
    Loads the key from the credentials/host directory named `host.key`
    """
    secret_file = "credentials/" + host + "/" + host + ".key"
    credential_file_path = Path(secret_file)
    
    if not credential_file_path.exists():
        return False

    return open(secret_file, "rb").read()

