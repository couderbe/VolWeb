import json
from typing import Any, Callable
import yaml
from yaml.loader import SafeLoader
from windows_engine.models import *
from analyser.models import *
import re
from django.db.models.query import QuerySet
from django.db.models import Q,Count
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


def fields_to_query(request: 'list[dict[str,Any]]') -> Q:
    query = Q()
    for elt in request:
        sub_query = Q()
        field_value = list(elt.values())[0]
        field_name = list(elt.keys())[0]
        if isinstance(field_value,str):
            for text in field_value.split("|"):
                if field_name.startswith("~"):
                    sub_query &= ~Q(**{field_name[1:]: text})
                else:
                    sub_query |= Q(**{field_name: text})
        elif isinstance(field_value,int):
            if field_name.startswith("~"):
                sub_query &= ~Q(**{field_name[1:]: field_value})
            else:
                sub_query |= Q(**{field_name: field_value})
        else:
            print("Not supported field value type")
            raise Exception
        query &= sub_query
    return query

def difference(q1: QuerySet, q2: QuerySet, fields: 'list[dict]') -> QuerySet:
    result = q1
    for elt in q2:
        # Generate arguments from desired comparaison fields
        args = {}
        for field in fields:
            for key,val in field.items():
                args.update({key:getattr(elt,val)})
        result = result.exclude(**args)
    return result

#TODO Test me
def intersection(q1: QuerySet, q2: QuerySet, fields: 'list[dict]') -> QuerySet:
    result = q1
    for elt in q1:
        # Generate arguments from desired comparaison fields
        args = {}
        for field in fields:
            for key,val in field.items():
                args.update({key:getattr(elt,val)})

        if len(q2.filter(**args)) == 0:
            result = result.exclude(**args)
    return result


@keyword
def selection(data: dict, invest_id: int) -> 'tuple(QuerySet, dict)':
    module = ""
    filters = []
    artefacts = {}
    query = Q(investigation_id=invest_id)
    for key, value in data.items():
        if key == "module":
            module = value
        elif key == "fields":
            query &= fields_to_query(value)
        elif FILTER_PATTERN.match(key):
            filters.append(value)

    unfiltered = eval(module).objects.filter(query)
    result = unfiltered
    for filter in filters:
        filter_name = list(filter.keys())[0]
        result, detected_artefacts = FILTER_TO_FUNCTION[filter_name](
            result, list(filter.values())[0], invest_id)
        artefacts.update({filter_name: detected_artefacts})
    return result, artefacts


@keyword
def intersect(data: dict, invest_id: int) -> 'tuple(QuerySet, dict)':
    query_set_1, _ = selection(data["selection1"], invest_id)
    query_set_2, _ = selection(data["selection2"], invest_id)
    if data["not"]:
        result = difference(query_set_1,query_set_2,data['fields'])
    else:
        result = intersection(query_set_1,query_set_2,data['fields'])
    return result, {}


@filter
def parent(data, args: 'list[dict[str,str]]', case_id: int) -> 'tuple(QuerySet, dict)':
    query = fields_to_query(args)
    detection_artefacts = {}
    for process in data:
        # Find parents in PsScan
        parents = PsScan.objects.filter(
            investigation=case_id, PID=process.PPID)
        # Filter with the conditions in args and exclude the result if empty
        parents = parents.filter(query)
        if len(parents) == 0:
            data = data.exclude(pk=process.pk)
        else:
            detection_artefacts.update({process.pk: list(parents.values())})
    return data, detection_artefacts


@filter
def dll(data, args: 'list[dict[str,str]]', case_id: int) -> 'tuple(QuerySet, dict)':
    query = fields_to_query(args)
    detection_artefacts = {}
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
        else:
            detection_artefacts.update({process.pk: list(dll_list.values())})
    return data, detection_artefacts


@filter
def handles(data, args: 'list[dict[str,str]]', case_id: int) -> 'tuple(QuerySet, dict)':
    query = fields_to_query(args)
    detection_artefacts = {}
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
        else:
            detection_artefacts.update({process.pk: list(handles.values())})
    return data, detection_artefacts

@filter
def count(data, args: 'list[dict[str,int]]', case_id: int) -> 'tuple(QuerySet, dict)':
    comparaison_symbols = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<=", "eq": "=="}
    count = data.count()
    for arg in args:
        comparaison_symbol = list(arg.keys())[0]
        if comparaison_symbol.startswith("~"):
            if eval(f"count {comparaison_symbols[comparaison_symbol[1:]]} list(arg.values())[0]"):
                data = data.none()
        else:
            if not(eval(f"count {comparaison_symbols[comparaison_symbol]} list(arg.values())[0]")):
                data = data.none()
    return data,{}

def run_rules(invest_id: int) -> dict:
    output = []
    rules = Rule.objects.filter(enabled=True)
    for rule in rules:
        output.append(parse_rule(invest_id, str(rule.file)))
    return json.dumps(output)


def parse_rule(invest_id: int, path: str) -> tuple:
    with open(path) as f:
        data = yaml.load(f, Loader=SafeLoader)
    print(data)
    result = ""
    artefacts = ""
    for key, value in data.items():
        if key == "title":
            title = value
        elif key == "description":
            pass
        else:
            try:
                result, artefacts = KEYWORD_TO_FUNCTION[key](
                    value, invest_id)
            except Exception as e:
                print(f"Error: {e}")
    return {"Title": ''.join(ch for ch in title if ch.isalnum()), "Result": list(result.values()), "Artefacts": artefacts}
