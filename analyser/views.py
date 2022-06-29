from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import redirect, render
from analyser.rules import run_rules
from investigations.forms import ManageInvestigation
from analyser.forms import *


@login_required
def analyser(request):
    if request.method == 'GET':
        form = ManageInvestigation(request.GET)
        if form.is_valid():
            case = form.cleaned_data['sa_case_id']
            id = case.id
        return JsonResponse({'Detection': run_rules(id)}, status=200)

@login_required
def rules_management(request):
    return render(request,'analyser/rules.html',{'rules':Rule.objects.all()})


@login_required
def add_rule(request):
    if request.method == 'POST':
        form = NewRuleForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('/analyser/rules/')
    form = NewRuleForm(initial={"os":"Windows"})
    return render(request, "analyser/add_rule.html", {'form':form})