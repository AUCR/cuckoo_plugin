"""AUCR Cuckoo plugin framework."""
# coding=utf-8
import os
from app.plugins.tasks.mq import get_a_task_mq
from app.plugins.cuckoo.cuckoo import submit_file_to_cuckoo
from app.plugins.cuckoo.routes import cuckoo_page
from multiprocessing import Process
from app.plugins.reports.storage.elastic_search import index_data_to_es


def call_back(ch, method, properties, file_hash):
    """File upload call back."""
    report = submit_file_to_cuckoo(file_hash)
    cuckoo_url = os.environ.get('CUCKOO_URL')
    for items in report:
        cuckoo_url_path = \
            {"cuckoo_url": str(cuckoo_url + "/analysis/" + str(items)), "file_hash": file_hash.decode('utf8')}
        index_data_to_es("cuckoo", cuckoo_url_path)


def load(app):
    """load overrides for Unum plugin to work properly"""
    # app.register_blueprint(cuckoo, url_prefix='/cuckoo')
    cuckoo_processor = os.environ.get('CUCKOO_API_URL')
    tasks = "cuckoo"
    rabbitmq_server = os.environ.get('RABBITMQ_SERVER')
    rabbitmq_username = os.environ.get('RABBITMQ_USERNAME')
    rabbitmq_password = os.environ.get('RABBITMQ_PASSWORD')
    app.register_blueprint(cuckoo_page, url_prefix='/cuckoo')
    if cuckoo_processor:
        p = Process(target=get_a_task_mq, args=(tasks, call_back, rabbitmq_server, rabbitmq_username,
                                                rabbitmq_password))
        p.start()
