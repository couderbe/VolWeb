from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from analyser.rules import run_rules
from investigations.forms import ManageInvestigation


@login_required
def analyser(request):
    if request.method == 'GET':
        return JsonResponse({'Unimplemented': 'Unimplemented'}, status=200)

#TODO use investigation id
@login_required
def detection(request):
    if request.method == 'GET':
        form = ManageInvestigation(request.GET)
        if form.is_valid():
            case = form.cleaned_data['sa_case_id']
            id = case.id
        return JsonResponse({'Result': run_rules(id)}, status=200)
