"""AUCR Cuckoo plugin function library."""
# coding=utf-8
import os
import requests
import udatetime
import ujson
from logging import error
from aucr_app import db, create_app
from aucr_app.plugins.cuckoo_plugin.models import CuckooReports
from aucr_app.plugins.unum.models import UNUM
from aucr_app.plugins.auth.models import Message


def call_back(ch, method, properties, file_hash):
    """Cuckoo Processing call back function."""
    app = create_app()
    db.init_app(app)
    report = submit_file_to_cuckoo(file_hash)
    cuckoo_url = os.environ.get('CUCKOO_URL')
    report_list_ids = []
    url_list = []
    for items in report:
        url_list.append(str(cuckoo_url + "/analysis/" + str(items)))
        report_list_ids.append(str(items))
    with app.app_context():
        try:
            new_cuckoo = CuckooReports(url=str(url_list), md5_hash=file_hash.decode("utf-8"),
                                       modify_time=udatetime.utcnow(), report_ids=report_list_ids)
            db.session.add(new_cuckoo)
            db.session.commit()
            message_data = ujson.dumps(new_cuckoo.to_dict(), indent=2, sort_keys=True)
            match_known_item = UNUM.query.filter_by(md5_hash=file_hash.decode("utf-8")).first()
            if match_known_item:
                cuckoo_notification = \
                    Message(sender_id=1, recipient_id=match_known_item.created_by, body=message_data)
                db.session.add(cuckoo_notification)
                db.session.commit()
        except:
            error("Problem creating the cuckoo report")


def submit_file_to_cuckoo(file_hash):
    """Function to submit uploaded file to the cuckoo sandbox for processing"""
    upload_path = os.environ.get('FILE_FOLDER')
    cuckoo_auth_user = os.environ.get('CUCKOO_API_USER')
    cuckoo_auth_password = os.environ.get('CUCKOO_API_PASSWORD')
    upload_server = os.environ.get('CUCKOO_API_URL')
    file_path = str(upload_path + "/" + file_hash.decode("utf-8"))
    r = requests.post(upload_server + "/tasks/create/submit", files=[("files", open(file_path, "rb"))],
                      auth=(cuckoo_auth_user, cuckoo_auth_password), timeout=600)
    task_ids = r.json()["task_ids"]
    return task_ids


def submit_url_to_cuckoo(url):
    """Function to submit url file to the cuckoo sandbox for processing."""
    upload_server = os.environ.get('CUCKOO_API_URL')
    cuckoo_auth_user = os.environ.get('CUCKOO_API_USER')
    cuckoo_auth_password = os.environ.get('CUCKOO_API_PASSWORD')
    api_cuckoo_url = "/tasks/create/url"
    data = {"url": url}
    r = requests.post(str(upload_server + api_cuckoo_url), data=data, auth=(cuckoo_auth_user, cuckoo_auth_password))
    task_ids = r.json()["task_ids"]
    return task_ids
