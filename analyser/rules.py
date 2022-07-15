from typing import Callable
import yaml
from yaml.loader import SafeLoader
from windows_engine.models import *
from analyser.models import *
import re
from django.db.models.query import QuerySet
from django.db.models import Q
from windows_engine.tasks import dlllist_task, handles_task

CONDITIONS = {}
KEYWORD_TO_FUNCTION = {}
FILTER_TO_FUNCTION = {}
FILTER_PATTERN = re.compile(r'^filter[0-9]*$')

def keyword(func: Callable) -> Callable:
    KEYWORD_TO_FUNCTION[func.__name__] = func
    return func

def filter(func: Callable) -> Callable:
    FILTER_TO_FUNCTION[func.__name__] = func
    return func

def fields_to_query(request :'list[dict[str,str]]') -> Q:
    query = Q()
    for elt in request:
        sub_query = Q()
        for text in list(elt.values())[0].split("|"):
            if (field := list(elt.keys())[0]).startswith("~"):
                sub_query &= ~Q(**{field[1:]: text})
            else:
                sub_query |= Q(**{field: text})
        query &= sub_query
    return query

@keyword
def selection(data: dict,invest_id: int):
    module = ""
    filters = []
    query = Q(investigation_id=invest_id)
    for key,value in data.items():
        if key == "module":
            module = value
        elif key == "fields":
            query &= fields_to_query(value)
        elif FILTER_PATTERN.match(key):
            filters.append(value)

    unfiltered = eval(module).objects.filter(query)
    result = unfiltered
    for filter in filters:
        result = FILTER_TO_FUNCTION[list(filter.keys())[0]](result,list(filter.values())[0],invest_id)
    return result

@keyword
def intersect(data: dict,invest_id: int):
    query_set_1 = selection(data["selection1"],invest_id)
    query_set_2 = selection(data["selection2"],invest_id)
    if data["not"]:
        result = query_set_1.difference(query_set_2)
    else:
        result = query_set_1.intersection(query_set_2)
    print(result)
    return result

@filter
def parent(data, args: 'list[dict[str,str]]', case_id: int) -> QuerySet:
    query = fields_to_query(args)
    for process in data:
        # Find parents in PsScan
        parents = PsScan.objects.filter(investigation= case_id, PID=process.PPID)
        # Filter with the conditions in args and exclude the result if empty
        parents = parents.filter(query)
        if len(parents) == 0:
            data = data.exclude(pk=process.pk)
    return data

@filter
def dll(data, args: 'list[dict[str,str]]',case_id: int) -> QuerySet:
    query = fields_to_query(args)
    for process in data:
        # If the dllList has never been computed , do it
        dll_list = DllList.objects.filter(process__pk=process.pk)
        if len(dll_list) == 0:
            dlllist_task(case_id, process.pk)
            dll_list = DllList.objects.filter(process__pk=process.pk)
        # Filter with the conditions in args and exclude the result if empty
        dll_list = dll_list.filter(query)
        if len(dll_list) == 0:
            data = data.exclude(pk=process.pk)
    return data

@filter
def handles(data, args: 'list[dict[str,str]]',case_id: int) -> QuerySet:
    query = fields_to_query(args)
    for process in data:
        # If the handles has never been computed , do it
        handles = Handles.objects.filter(process__pk=process.pk)
        if len(handles) == 0:
            handles_task(case_id, process.pk)
            handles = Handles.objects.filter(process__pk=process.pk)
        # Filter with the conditions in args and exclude the result if empty
        handles = handles.filter(query)
        if len(handles) == 0:
            data = data.exclude(pk=process.pk)
    return data

def condition(func: Callable) -> Callable:
    CONDITIONS[func.__name__] = func
    return func


def run_rules(invest_id: int) -> dict:
    output = []
    rules = Rule.objects.filter(enabled=True)
    for rule in rules:
        output.append(parse_rule(invest_id, str(rule.file)))
    return output

def parse_rule(invest_id: int, path: str) -> tuple:
    with open(path) as f:
        data = yaml.load(f, Loader=SafeLoader)
    print(data)
    result = ""
    for key,value in data.items():
        if key == "title":
            title = value
        else:
            try:
                result = list(KEYWORD_TO_FUNCTION[key](value, invest_id).values())
            except Exception as e:
                print(f"Error: {e}")
    return ({"Title": ''.join(ch for ch in title if ch.isalnum()), "Result": result})

def parse_rule_old(invest_id: int, path: str) -> tuple:
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
    return({"Title": ''.join(ch for ch in data['title'] if ch.isalnum()), "Result": result})


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
