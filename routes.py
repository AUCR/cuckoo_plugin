"""AUCR cuckoo plugin route page handler."""
# coding=utf-8
import ujson
import udatetime
from os import environ
from app import db
from flask import render_template, request, Blueprint
from flask_babel import _
# from dataparserlib.dictionary import flatten_dictionary
from flask_login import login_required, current_user

def flatten_dictionary(json_data):
    meta = {}
    meta["report"] = {}
    for item in json_data:
        if type(json_data[item]) is dict:
            for values in json_data[item]:
                if type(json_data[item][values]) is dict:
                    for second_values in json_data[item][values]:
                        if type(json_data[item][values][second_values]) is dict:
                            for third_values in json_data[item][values][second_values]:
                                if type(json_data[item][values][second_values][third_values])\
                                        is not list or dict or None:
                                    print(type(json_data[item][values][second_values][third_values]))
                                    debug_test = json_data[item][values][second_values][third_values]
                                    if debug_test:
                                        meta["report"][str(item + "." + values + "." + second_values + "." +
                                                           third_values)] = \
                                                str(json_data[item][values][second_values][third_values])
                        elif type(json_data[item][values][second_values]) is not list or None:
                            none_test = str(json_data[item][values][second_values])
                            if none_test:
                                meta["report"][str(item + "." + values + "." + second_values)] =\
                                    str(json_data[item][values][second_values])
                elif type(json_data[item][values]) is not list or None:
                    values_test = json_data[item][values]
                    if values_test and str(values_test) != "none":
                        meta["report"][str(item + "." + values)] = str(json_data[item][values])
        elif type(json_data[item]) is list:
            for list_items in json_data[item]:
                test_dict = list_items
                if type(test_dict) is str:
                    meta["report"][item] = test_dict
                else:
                    meta[item] = json_data[item]
        elif type(json_data[item]) is not list or None:
            test_item = json_data[item]
            if test_item and str(test_item) != "none":
                meta["report"][item] = json_data[item]
    return meta

cuckoo_page = Blueprint('cuckoo', __name__, static_folder='/cuckoo/', template_folder='templates')


@cuckoo_page.route('/cuckoo_report', methods=['GET', 'POST'])
@login_required
def cuckoo_report():
    """Return the Cuckoo the AUCR Team page."""
    submitted_report_id = str(request.args.get("id"))
    # submitted_report_id = str(894)
    cuckoo_path = environ['CUCKOO_STORAGE_PATH']
    with open(str(cuckoo_path + submitted_report_id + '/reports/report.json'), "rb") as reports_file:
        report = ujson.load(reports_file)
    virus_total_report = report["virustotal"]
    virus_total_scan = report["virustotal"]["scans"]
    machine_dict = flatten_dictionary(report["info"]["machine"])
    del report["info"]["git"]
    del report["info"]["machine"]
    data_report = flatten_dictionary(report["target"]["file"])
    info_report = flatten_dictionary(report["info"])
    info_dict = info_report["report"]
    summary_report = data_report["report"]
    del info_dict["options"]
    del info_dict["monitor"]
    del info_dict["id"]
    del info_dict["platform"]
    del info_dict["version"]
    del info_dict["added"]
    machine_dict = machine_dict["report"]
    machine_dict["started"] = f'{udatetime.fromtimestamp(info_dict["started"]):%B %d, %Y, %H:%M:%S}'
    machine_dict["ended"] = f'{udatetime.fromtimestamp(info_dict["ended"]):%B %d, %Y, %H:%M:%S}'
    del info_dict["started"]
    del info_dict["ended"]
    del machine_dict["started_on"]
    del machine_dict["status"]
    del machine_dict["shutdown_on"]
    del virus_total_report["scans"]
    del virus_total_report["summary"]
    virustotal_report = flatten_dictionary(virus_total_report)
    virustotal_report["report"]["detection"] = str(str(virustotal_report["report"]["positives"]) + "/" +
                                                   str(virustotal_report["report"]["total"]))
    del virustotal_report["report"]["scan_id"]
    del virustotal_report["report"]["sha1"]
    del virustotal_report["report"]["response_code"]
    del virustotal_report["report"]["sha256"]
    del virustotal_report["report"]["md5"]
    del virustotal_report["report"]["total"]
    del virustotal_report["report"]["positives"]
    del virustotal_report["report"]["verbose_msg"]

    list_value_strings = ""
    for list_value in report["strings"]:
        list_value_strings = list_value_strings + str(list_value + "\n")
    classification = flatten_dictionary(report["classification"])
    summary_report["Family"] = classification["report"]["family"]
    summary_report["Category"] = classification["report"]["category"]
    for values in virus_total_scan:
        del virus_total_scan[values]["update"]
    summary_report["File score"] = str(str(info_dict["score"]) + "/" + str(10))
    del info_dict["score"]
    extracted_files = report["extracted"]
    test_list = []
    for extracted_file in extracted_files:
        program_name = extracted_file["program"]
        del extracted_file["program"]
        extracted_file["First Seen"] = f'{udatetime.fromtimestamp(extracted_file["first_seen"]):%B %d, %Y, %H:%M:%S}'
        del extracted_file["first_seen"]
        extracted_file["Process Name"] = program_name
        test_list.append(extracted_file)
    del summary_report["path"]
    del summary_report["sha512"]
    screenshots = report["screenshots"]
    screenshots_list = []
    for screenshot in screenshots:
        screenshots_list.append(screenshot["path"][1:])
    debug_log = report["debug"]["log"]
    debug_cuckoo = report["debug"]["cuckoo"]
    log_value_strings = ""
    for log_value in debug_log:
        log_value_strings = log_value_strings + str(log_value)

    cuckoo_value_strings = ""
    for cuckoo_value in debug_cuckoo:
        cuckoo_value_strings = cuckoo_value_strings + str(cuckoo_value)
    if "b64" in report:
        hex_list = report["b64"]
    else:
        hex_list = None
    macro_list = []
    if "static" in report:
        if "office" in report["static"]:
            macro_list = report["static"]["office"]
    return render_template('cuckoo.html', summary_dict=summary_report, info_dict=info_dict, vm_dict=machine_dict,
                           virus_total_dict=virustotal_report["report"], file_strings=list_value_strings,
                           clasification_dict=classification["report"], virus_total_scan=virus_total_scan,
                           extracted_files=test_list, screenshot_files=screenshots_list, log_list=log_value_strings,
                           log_cuckoo=cuckoo_value_strings, hex_report=hex_list, macro_list=macro_list)
