from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from analyser.rules import parse_rule


@login_required
def analyser(request):
    if request.method == 'GET':
        return JsonResponse({'Unimplemented': 'Unimplemented'}, status=200)


@login_required
def detection(request):
    if request.method == 'GET':
        return JsonResponse({'Result': parse_rule("analyser/rules/test_rule.yml")}, status=200)
