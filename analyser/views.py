from django.contrib.auth.decorators import login_required
from django.http import FileResponse, JsonResponse
from django.shortcuts import redirect, render
from django.contrib import messages
from analyser.rules import run_rules
from investigations.forms import ManageInvestigation
from analyser.forms import *
import os


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
    return render(request, 'analyser/rules.html', {'rules': Rule.objects.all()})


@login_required
def add_rule(request):
    if request.method == 'POST':
        form = NewRuleForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('/analyser/rules/')
    form = NewRuleForm(initial={"os": "Windows"})
    return render(request, "analyser/add_rule.html", {'form': form})


@login_required
def delete_rule(request):
    """Delete a rule

        Arguments:
        request : http request object

        Comments:
        Delete the Rule selected by the user.
        """
    if request.method == "POST":
        form = ManageRuleForm(request.POST)
        if form.is_valid():
            id = form.cleaned_data['rule_id']
            rule = Rule.objects.get(pk=id)
            # Delete rule file
            if os.path.exists(rule.file.path):
                os.remove(rule.file.path)
            else:
                print("The file does not exist")
            # Delete rule from model
            rule.delete()
            return redirect('/analyser/rules/')
        else:
            print("invalid")
            # TODO Show error on toast
            return redirect('/analyser/rules/')

@login_required
def toggle_rule(request):
    """Toggle a rule

        Arguments:
        request : http request object

        Comments:
        Toggle the Rule selected by the user.
        """
    if request.method == "POST":
        form = ManageRuleForm(request.POST)
        if form.is_valid():
            id = form.cleaned_data['rule_id']
            rule = Rule.objects.get(pk=id)
            print(rule)
            # Toggle rule from model
            rule.enabled = not(rule.enabled)
            print(rule.enabled)
            rule.save()
            # rule.update(enabled = not(rule.enabled))
            return redirect('/analyser/rules/')
        else:
            print("invalid")
            # TODO Show error on toast
            return redirect('/analyser/rules/')

@login_required
def download_rule(request):
    """Download a rule

        Arguments:
        request : http request object

        Comment:
        The user requested to download a rule.
        Get the file and return it.
        """
    if request.method == 'POST':
        form = DownloadRuleForm(request.POST)
        if form.is_valid():
            id = form.cleaned_data['id']
            rule = Rule.objects.get(pk = id)
            file_path = rule.file.path
            try:
                response = FileResponse(open(file_path, 'rb'))
                response['content_type'] = "application/octet-stream"
                response['Content-Disposition'] = 'attachment; filename=' + os.path.basename(file_path)
                return response
            except:
                messages.add_message(request,messages.ERROR,'Failed to fetch the requested file')

        else:
            return JsonResponse({'message': "error"})

