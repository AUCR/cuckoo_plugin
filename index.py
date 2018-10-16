import ujson
# from app.plugins.reports.storage.elastic_search import index_data_to_es

with open("/home/vtriple/CLionProjects/yara/report2.json", "rb") as reports_file:
    report = ujson.load(reports_file)
# coding=utf-8


def parse_list(list_item, report_dict):
    list_dict = {}
    if list_item in report_dict:
        list_values = report_dict[str(list_item)]
        list_values_data = []
        if len(list_values) > 0:
            for each_entry in list_values:
                list_dict[str(list_item)] = {}
                if len(each_entry) > 0:
                    list_values_data.append(str(each_entry))
            if len(list_values_data) > 0:
                list_dict[str(list_item)] = list_values_data
        return list_dict[str(list_item)]
    else:
        return None


def falten_dict(test):
    meta = {}
    meta["test"] = {}
    for item in test:
        if type(test[item]) is dict:
            for values in test[item]:
                if type(test[item][values]) is dict:
                    for second_values in test[item][values]:
                        if type(test[item][values][second_values]) is dict:
                            for third_values in test[item][values][second_values]:
                                if type(test[item][values][second_values][third_values]) is not list or dict or None:
                                    print(type(test[item][values][second_values][third_values]))
                                    debug_test =  test[item][values][second_values][third_values]
                                    if debug_test:
                                        meta["test"][str(item + "." + values + "." + second_values + "." + third_values)] = \
                                                str(test[item][values][second_values][third_values])
                        elif type(test[item][values][second_values]) is not list or None:
                            none_test = str(test[item][values][second_values])
                            if none_test:
                                meta["test"][str(item + "." + values + "." + second_values)] = str(test[item][values][second_values])
                elif type(test[item][values]) is not list or None:
                    values_test = test[item][values]
                    if values_test and str(values_test) != "none":
                        meta["test"][str(item + "." + values)] = str(test[item][values])
        elif type(test[item]) is list:
            for list_items in test[item]:
                test_dict = list_items
                if type(test_dict) is str:
                    meta["test"][item] = test_dict
                else:
                    meta[item] = test[item]
        elif type(test[item]) is not list or None:
            test_item = test[item]
            if test_item is not "none":
                meta[item] = test[item]
    return meta

test = report["behavior"]
test_meta = falten_dict(report)
count = 0
test_meta_new = {}
for new_items in test_meta:
    if type(test_meta[new_items]) is list:
        for list_values in test_meta[new_items]:
            try:
                test_meta_new_value = falten_dict(test_meta[new_items][count])
                if type(test_meta[new_items][list_values]) is list:
                    test_meta_new_value = falten_dict(test_meta[new_items][count])
                    test_meta_new[new_items][list_values] = test_meta_new_value
                count += 1
            except:
                print("dontcare" + str(test_meta[new_items]) + str(count))
stupid_test = test_meta["procmemory"]
print(test_meta)
meta = {}
report_file = parse_list("log", report["debug"])
if report_file:
    meta["log"] = {}
    meta["log"] = report_file

meta["test"] = {}
for item in test:
    if type(test[item]) is dict:
        for values in test[item]:
            meta["test"][str(item + "." + values)] = str(test[item][values])
    else:
        meta["test"][item] = test[item]
meta["info"] = report["info"]


