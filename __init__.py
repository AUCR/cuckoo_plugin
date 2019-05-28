"""AUCR Cuckoo plugin framework."""
# coding=utf-8
import os
from aucr_app.plugins.tasks.mq import get_a_task_mq
from aucr_app.plugins.cuckoo_plugin.cuckoo_processor import submit_file_to_cuckoo, call_back
from aucr_app.plugins.cuckoo_plugin.routes import cuckoo_page
from multiprocessing import Process


def load(app):
    """load overrides for Unum plugin to work properly"""
    cuckoo_processor_url = os.environ.get('CUCKOO_API_URL')
    tasks = "cuckoo_plugin"
    rabbitmq_server = os.environ.get('RABBITMQ_SERVER')
    rabbitmq_username = os.environ.get('RABBITMQ_USERNAME')
    rabbitmq_password = os.environ.get('RABBITMQ_PASSWORD')
    app.register_blueprint(cuckoo_page, url_prefix='/cuckoo_plugin')
    if cuckoo_processor_url:
        p = Process(target=get_a_task_mq, args=(tasks, call_back, rabbitmq_server, rabbitmq_username,
                                                rabbitmq_password))
        p.start()
