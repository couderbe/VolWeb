from datetime import datetime
from fileinput import filename
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, JsonResponse
from django.shortcuts import redirect, render
from django.contrib import messages
from analyser.models import VirustotalAnalysis, VirustotalAnalysisFile, VirustotalAnalysisProcess
from analyser.rules import run_rules
from analyser.tasks import get_file_related_to_analysis, get_widget_url, is_filescan_done, virustotal_filescan
from investigations.forms import ManageInvestigation
from analyser.forms import *
import os
from investigations.models import UploadInvestigation
from investigations.tasks import dump_memory_file, dump_memory_pid
from windows_engine.models import FileDump, FileScan, ProcessDump, PsScan


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
            # Toggle rule from model
            rule.enabled = not(rule.enabled)
            rule.save()
            return redirect('/analyser/rules/')
        else:
            print("invalid")
            # TODO Show error on toast
            return redirect('/analyser/rules/')


@login_required
def virustotal_file(request):
    """Virustotal analysis

        Arguments:
        request : http request object

        Comments:
        Start analysis with virustotal for a file
        If the analysis is already running show status.
        If the analysis is done show results
        """
    if request.method == "POST":
        form = VirustotalForm(request.POST)
        if form.is_valid():
            id = form.cleaned_data['id']
            file = FileScan.objects.get(pk=id)
            virustotal_analysis = VirustotalAnalysisFile.objects.filter(
                filescan__pk=id)
            filedump = FileDump.objects.filter(
                    offset=file.Offset, case_id=file.investigation.id)
            if len(virustotal_analysis) == 0:
                if len(filedump) == 0:
                    task_res = dump_memory_file.delay(
                        str(file.investigation.id), file.Offset)
                    filename = task_res.get()
                    if filename == "ERROR":
                        return JsonResponse({'message': "failed to dump file"})
                    FileDump.objects.create(case_id=UploadInvestigation.objects.filter(
                        id=file.investigation.id)[0], offset=file.Offset, filename=filename)
                    filedump = FileDump.objects.filter(
                        offset=file.Offset, case_id=file.investigation.id)
                # Do the analysis
                case_path = 'Cases/Results/file_dump_' + \
                    str(file.investigation.id)
                scan_res = virustotal_filescan.delay(
                    case_path+"/"+filedump[0].filename)
                result = scan_res.get()

                # Save results
                ongoing = (result["data"]["type"] == "analysis")
                virustotal_analysis = VirustotalAnalysisFile.objects.create(filescan=file, result=result,analysisId=result["data"]["id"],ongoing=ongoing)
            else:
                virustotal_analysis = virustotal_analysis[0]
                if virustotal_analysis.ongoing:
                    result = virustotal_analysis.manageOngoing()
                else:
                    result = virustotal_analysis.result
            widget_url = ""
            if not(virustotal_analysis.ongoing):
                widget_url = virustotal_analysis.manageDone()
            return JsonResponse({'message': result,'url':widget_url})
        else:
            return JsonResponse({'message': "error"})


@login_required
def virustotal_process(request):
    """Virustotal analysis

        Arguments:
        request : http request object

        Comments:
        Start analysis with virustotal for a file
        If the analysis is already running show status.
        If the analysis is done show results
        """
    if request.method == "POST":
        form = VirustotalForm(request.POST)
        if form.is_valid():
            id = form.cleaned_data['id']
            ps = PsScan.objects.get(pk=id)
            virustotal_analysis = VirustotalAnalysisProcess.objects.filter(
                processScan__pk=id)
            process_dump = ProcessDump.objects.filter(
                    pid=ps.PID, case_id=ps.investigation.id)
            if len(virustotal_analysis) == 0:
                if len(process_dump) == 0:
                    task_res = dump_memory_pid.delay(
                        str(ps.investigation.id), ps.PID)
                    filename = task_res.get()
                    if filename == "ERROR":
                        return JsonResponse({'message': "failed to dump file"})
                    ProcessDump.objects.create(case_id=UploadInvestigation.objects.filter(
                        id=ps.investigation.id)[0], pid=ps.PID, filename=filename)
                    process_dump = ProcessDump.objects.filter(
                        pid=ps.PID, case_id=ps.investigation.id)
                # Do the analysis
                case_path = 'Cases/Results/file_dump_' + \
                    str(ps.investigation.id)
                scan_res = virustotal_filescan.delay(
                    case_path+"/"+process_dump[0].filename)
                result = scan_res.get()

                # Save results
                ongoing = (result["data"]["type"] == "analysis")
                virustotal_analysis = VirustotalAnalysisProcess.objects.create(processScan=ps, result=result,analysisId=result["data"]["id"],ongoing=ongoing)
            else:
                virustotal_analysis = virustotal_analysis[0]
                if virustotal_analysis.ongoing:
                    result = virustotal_analysis.manageOngoing()
                else:
                    result = virustotal_analysis.result
            widget_url = ""
            if not(virustotal_analysis.ongoing):
                widget_url = virustotal_analysis.manageDone()
            return JsonResponse({'message': result,'url':widget_url})
        else:
            return JsonResponse({'message': "error"})

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
            rule = Rule.objects.get(pk=id)
            file_path = rule.file.path
            try:
                response = FileResponse(open(file_path, 'rb'))
                response['content_type'] = "application/octet-stream"
                response['Content-Disposition'] = 'attachment; filename=' + \
                    os.path.basename(file_path)
                return response
            except:
                messages.add_message(
                    request, messages.ERROR, 'Failed to fetch the requested file')

        else:
            return JsonResponse({'message': "error"})
