from hashlib import sha1
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

class RuleFieldUnsupportedType(Exception):
    pass

def keyword(func: Callable) -> Callable:
    """Decorator adding keyword function to dict

    Args:
        func (Callable): Function handling keyword

    Returns:
        Callable: Unmodified input function
    """
    KEYWORD_TO_FUNCTION[func.__name__] = func
    return func


def filter(func: Callable) -> Callable:
    """Decorator adding filter function to dict

    Args:
        func (Callable): Function handling filter

    Returns:
        Callable: Unmodified input function
    """
    FILTER_TO_FUNCTION[func.__name__] = func
    return func


def fields_to_query(request: 'list[dict[str,Any]]') -> Q:
    """Convert fields parameters to django query

    Args:
        request (list[dict[str,Any]]): fields parameters

    Raises:
        RuleFieldUnsupportedType: Raised in case of unsupported field value type

    Returns:
        Q: Generated query
    """
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
            raise RuleFieldUnsupportedType
        query &= sub_query
    return query

def difference(q1: QuerySet, q2: QuerySet, fields: 'list[dict]') -> QuerySet:
    """Compute the difference between two querysets where equality is defined by fields

    Args:
        q1 (QuerySet): First Queryset
        q2 (QuerySet): Second Queryset
        fields (list[dict]): Fields used for equality check

    Returns:
        QuerySet: Difference Queryset
    """
    result = q1
    for elt in q2:
        # Generate arguments from desired comparaison fields
        args = {}
        for field in fields:
            for key,val in field.items():
                args.update({key:getattr(elt,val)})
        result = result.exclude(**args)
    return result

def intersection(q1: QuerySet, q2: QuerySet, fields: 'list[dict]') -> QuerySet:
    """Compute the intersection between two querysets where equality is defined by fields

    Args:
        q1 (QuerySet): First Queryset
        q2 (QuerySet): Second Queryset
        fields (list[dict]): Fields used for equality check

    Returns:
        QuerySet: Intersection Queryset
    """
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
    """Function handling selection keyword

    Args:
        data (dict): Selection parameters
        invest_id (int): Investigation id

    Returns:
        tuple(QuerySet, dict): Tuple composed of resulting queryset and detection artefacts as dict
    """
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
    """Function handling intersect keyword

    Args:
        data (dict): Intersection parameters
        invest_id (int): Investigation id

    Returns:
        tuple(QuerySet, dict): Tuple composed of resulting queryset and detection artefacts as dict
    """
    query_set_1, _ = selection(data["selection1"], invest_id)
    query_set_2, _ = selection(data["selection2"], invest_id)
    if data["not"]:
        result = difference(query_set_1,query_set_2,data['fields'])
    else:
        result = intersection(query_set_1,query_set_2,data['fields'])
    return result, {}


@filter
def parent(data: QuerySet, args: 'list[dict[str,str]]', case_id: int) -> 'tuple(QuerySet, dict)':
    """Compute parents and filter data Queryset

    Args:
        data (QuerySet): unfiltered data
        args (list[dict[str,str]]): filtering arguments
        case_id (int): case id

    Returns:
        tuple(QuerySet, dict): Tuple with filtered data and detection artefacts
    """
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
def dll(data: QuerySet, args: 'list[dict[str,str]]', case_id: int) -> 'tuple(QuerySet, dict)':
    """Compute dlls and filter data Queryset

    Args:
        data (QuerySet): unfiltered data
        args (list[dict[str,str]]): filtering arguments
        case_id (int): case id

    Returns:
        tuple(QuerySet, dict): Tuple with filtered data and detection artefacts
    """
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
def handles(data: QuerySet, args: 'list[dict[str,str]]', case_id: int) -> 'tuple(QuerySet, dict)':
    """Compute handles and filter data Queryset

    Args:
        data (QuerySet): unfiltered data
        args (list[dict[str,str]]): filtering arguments
        case_id (int): case id

    Returns:
        tuple(QuerySet, dict): Tuple with filtered data and detection artefacts
    """
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
def count(data: QuerySet, args: 'list[dict[str,int]]', case_id: int) -> 'tuple(QuerySet, dict)':
    """Compute count and filter data Queryset

    Args:
        data (QuerySet): unfiltered data
        args (list[dict[str,str]]): filtering arguments
        case_id (int): case id

    Returns:
        tuple(QuerySet, dict): Tuple with filtered data and detection artefacts
    """
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

def run_rules(invest_id: int) -> str:
    """Run all the rules on the given investigation

    Args:
        invest_id (int): ID of the investigation to run the rules on

    Returns:
        str: json formatted string containing the results
    """
    output = []
    rules = Rule.objects.filter(enabled=True)
    for rule in rules:
        output.append(parse_rule(invest_id, str(rule.file)))
    return json.dumps(output)


def parse_rule(invest_id: int, path: str) -> dict:
    """Parse a rule

    Args:
        invest_id (int): Investigation id
        path (str): Path to the rule

    Returns:
        dict: Rules results, metadata and dectection artefacts
    """
    with open(path) as f:
        data = yaml.load(f, Loader=SafeLoader)
    print(data)
    title = ""
    description = ""
    result = ""
    artefacts = ""
    for key, value in data.items():
        if key == "title":
            title = value
        elif key == "description":
            description = value
        else:
            try:
                result, artefacts = KEYWORD_TO_FUNCTION[key](
                    value, invest_id)
            except Exception as e:
                print(f"Error: {e}")
    return {"Title": title, "Description": description, "Result": list(result.values()), "Artefacts": artefacts, "Id": str(sha1(title.encode()).hexdigest())}
