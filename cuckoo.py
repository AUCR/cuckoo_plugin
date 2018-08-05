import os
import requests


def submit_file_to_cuckoo(file_hash):
    # Function to submit uploaded file to cuckoo for processing
    upload_path = os.environ.get('FILE_FOLDER')
    cuckoo_auth_user = os.environ.get('CUCKOO_API_USER')
    cuckoo_auth_password = os.environ.get('CUCKOO_API_PASSWORD')
    upload_server = os.environ.get('CUCKOO_API_URL')
    file_path = str(upload_path + file_hash.decode("utf-8"))
    r = requests.post(upload_server + "/tasks/create/submit", files=[
                     ("files", open(file_path, "rb"))
                     ], auth=(cuckoo_auth_user, cuckoo_auth_password))
    task_ids = r.json()["task_ids"]
    return task_ids


def submit_url_to_cuckoo(url):
    # Function to submit url file to cuckoo for processing
    upload_server = os.environ.get('CUCKOO_API_URL')
    cuckoo_auth_user = os.environ.get('CUCKOO_API_USER')
    cuckoo_auth_password = os.environ.get('CUCKOO_API_PASSWORD')
    api_cuckoo_url = "/tasks/create/url"
    data = {"url": url}
    r = requests.post(str(upload_server + api_cuckoo_url), data=data, auth=(cuckoo_auth_user, cuckoo_auth_password))
    task_ids = r.json()["task_ids"]
    return task_ids
