from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from analyser.rules import run_rules


@login_required
def analyser(request):
    if request.method == 'GET':
        return JsonResponse({'Unimplemented': 'Unimplemented'}, status=200)

#TODO use investigation id
@login_required
def detection(request):
    if request.method == 'GET':
        return JsonResponse({'Result': run_rules()}, status=200)
