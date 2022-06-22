import os
from typing import Any, Callable
from unittest import result
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
        print(module_to_list(params[0]["module"]))
        # set1 = set(module_to_list(params[0]["module"]))
        # set2 = set(module_to_list(params[1]["module"]))
        # print(set1)
        # print(set2)
        # return set1.intersection(set2)
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
    return list(eval(module).objects.filter(investigation_id=1).values())
