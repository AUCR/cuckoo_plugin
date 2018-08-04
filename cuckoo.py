import os
import requests


def submit_file_to_cuckoo(file_hash):
    # Function to submit uploaded file to AUCR to cuckoo for processing
    upload_path = os.environ.get('FILE_FOLDER')
    upload_server = os.environ.get('CUCKOO_API_URL')
    file_path = str(upload_path + file_hash.decode("utf-8"))
    r = requests.post(upload_server + "/tasks/create/submit", files=[
                     ("files", open(file_path, "rb"))
                     ])
    task_ids = r.json()["task_ids"]
    return task_ids
