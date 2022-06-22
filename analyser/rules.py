import os
from typing import Any, Callable
import yaml
from yaml.loader import SafeLoader
from windows_engine.models import *

CONDITIONS = {}


def condition(func: Callable) -> Callable:
    CONDITIONS[func.__name__] = func
    return func


def run_rules(directory: str = "analyser/rules/") -> dict:
    output = []
    for root, dirs, files in os.walk(directory):
        for filename in files:
            path = os.path.join(root, filename)
            print(path)
            output.append(parse_rule(path))
    return output


def parse_rule(path: str) -> tuple:
    result = "Unable to find known condition"
    with open(path) as f:
        data = yaml.load(f, Loader=SafeLoader)
    print(data)
    condition = data['condition']
    print(CONDITIONS)
    for cond in CONDITIONS:
        if cond in condition:
            if len((result := CONDITIONS[cond](condition[cond]))) > 0:
                pass
            else:
                result = "Nothing found"

    return(data['title'], result)


@condition
def intersect(params) -> list:
    if isinstance(params[0], dict) and isinstance(params[1], dict):
        print(params[2]["not"])
        print(type(params[2]["not"]))
        if params[2]["not"]:
            return [x for x in module_to_list(params[0]["module"]) if {'PID': x['PID'], 'ImageFileName':x['ImageFileName']} not in [{'PID': y['PID'], 'ImageFileName':y['ImageFileName']} for y in module_to_list(params[1]["module"])]]
        else:
            return [x for x in module_to_list(params[0]["module"]) if {'PID': x['PID'], 'ImageFileName':x['ImageFileName']} in [{'PID': y['PID'], 'ImageFileName':y['ImageFileName']} for y in module_to_list(params[1]["module"])]]
    else:
        return "Intersect not supported operand types"


@condition
def equals(params) -> list:
    if isinstance(params[0], dict) and isinstance(params[1], str):
        if "module" in params[0]:
            records = module_to_list(params[0]["module"])
            filtered_records = list(
                filter(lambda record: record[params[0]["attribute"]] == params[1], records))
            return filtered_records

    return "Unimplemented yaml syntax"


def module_to_list(module: str):
    return list(eval(module).objects.filter(investigation_id=2).values())
