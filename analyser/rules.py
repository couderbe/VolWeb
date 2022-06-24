import os
from typing import Any, Callable
import yaml
from yaml.loader import SafeLoader
from windows_engine.models import *
from analyser.models import *

CONDITIONS = {}


def condition(func: Callable) -> Callable:
    CONDITIONS[func.__name__] = func
    return func


def run_rules(invest_id: int, directory: str = "analyser/rules/") -> dict:
    output = []
    for root, dirs, files in os.walk(directory):
        for filename in files:
            path = os.path.join(root, filename)
            print(path)
            output.append(parse_rule(invest_id, path))
    return output


def parse_rule(invest_id: int, path: str) -> tuple:
    result = "Unable to find known condition"
    with open(path) as f:
        data = yaml.load(f, Loader=SafeLoader)
    print(data)
    condition = data['condition']
    for cond in CONDITIONS:
        if cond in condition:
            if len((result := CONDITIONS[cond](invest_id, condition[cond]))) > 0:
                pass
            else:
                result = "Nothing found"

    return({"Title": data['title'], "Result": result})


@condition
def intersect(invest_id: int, params) -> list:
    if isinstance(params[0], dict) and isinstance(params[1], dict):
        lists = []
        comparaison_attributes = {}
        not_in = False
        for param in params:
            if "module" in param:
                lists.append(module_to_list(invest_id, param["module"]))
            elif "condition" in param:
                condition = param["condition"]
                for cond in CONDITIONS:
                    if cond in condition:
                        lists.append(CONDITIONS[cond](
                            invest_id, condition[cond]))
            elif "attributes" in param:
                comparaison_attributes = param["attributes"]
            elif "not" in param:
                not_in = param["not"]
            if len(lists) > 2:
                return "Intersect support only two operands"
        if not_in:
            return [x for x in lists[0] if [x[key] for (key, value) in comparaison_attributes.items()]
                    not in [[y[value] for (key, value) in comparaison_attributes.items()] for y in lists[1]]]
        else:
            return [x for x in lists[0] if [x[key] for (key, value) in comparaison_attributes.items()]
                    in [[y[value] for (key, value) in comparaison_attributes.items()] for y in lists[1]]]
    else:
        return "Intersect not supported operand types"


@condition
def equals(invest_id: int, params) -> list:
    if isinstance(params[0], dict) and isinstance(params[1], str):
        if "module" in params[0]:
            records = module_to_list(invest_id, params[0]["module"])
            filtered_records = list(
                filter(lambda record: record[params[0]["attribute"]] == params[1], records))
            return filtered_records

    return "Unimplemented yaml syntax"


def module_to_list(invest_id: int, module: str):
    return list(eval(module).objects.filter(investigation_id=invest_id).values())
