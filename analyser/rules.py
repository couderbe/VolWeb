import json
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


def fields_to_query(request: 'list[dict[str,str]]') -> Q:
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
        result = query_set_1.difference(query_set_2)
    else:
        result = query_set_1.intersection(query_set_2)
    print(result)
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
        else:
            try:
                result, artefacts = KEYWORD_TO_FUNCTION[key](
                    value, invest_id)
            except Exception as e:
                print(f"Error: {e}")
    return {"Title": ''.join(ch for ch in title if ch.isalnum()), "Result": list(result.values()), "Artefacts": artefacts}
