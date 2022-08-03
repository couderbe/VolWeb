from json import dumps
import json
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from analyser.elements.dump import Dump
from analyser.elements.process import Process
from analyser.elements.analysis import Analysis

from investigations.models import UploadInvestigation
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, JsonResponse
from django.shortcuts import redirect, render
from django.contrib import messages
from analyser.models import VirustotalAnalysisDll, VirustotalAnalysisFile, VirustotalAnalysisProcess
from analyser.tasks import clamav_file, virustotal_filescan
from analyser.forms import *
import os
from investigations.models import UploadInvestigation
from investigations.tasks import dump_memory_file, dump_memory_pid
from windows_engine.models import DllList, FileDump, FileScan, ProcessDump, PsScan


@login_required
def analyser(request):
    with open('Cases/Results/'+'12'+'.json') as f:
        investData = json.load(f)
    dmp = Dump("Example Memory Dump")
    processes = [Process(name=elt['ImageFileName'],
                         pid=elt['PID'], ppid=elt['PPID'], sessionId=elt['SessionId'], wow64=elt['Wow64'], createTime=elt['CreateTime'], exitTime=elt['ExitTime']) for elt in investData['psscan']]
    dmp.children.extend(processes)
    analysis = Analysis("Analyse")
    analysis.loadDump(investData)
    print([analysis.toDict()])
    dataJSON = dumps([analysis.toDict()])
    return render(request, 'analyser/analyser.html', {'data': dataJSON})


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
                virustotal_analysis = VirustotalAnalysisFile.objects.create(
                    filescan=file, result=result, analysisId=result["data"]["id"], ongoing=ongoing)
            else:
                virustotal_analysis = virustotal_analysis[0]
                if virustotal_analysis.ongoing:
                    result = virustotal_analysis.manageOngoing()
                else:
                    result = virustotal_analysis.result
            widget_url = ""
            if not(virustotal_analysis.ongoing):
                widget_url = virustotal_analysis.manageDone()
            return JsonResponse({'message': result, 'url': widget_url})
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
                case_path = 'Cases/Results/process_dump_' + \
                    str(ps.investigation.id)
                scan_res = virustotal_filescan.delay(
                    case_path+"/"+process_dump[0].filename)
                result = scan_res.get()

                # Save results
                ongoing = (result["data"]["type"] == "analysis")
                virustotal_analysis = VirustotalAnalysisProcess.objects.create(
                    processScan=ps, result=result, analysisId=result["data"]["id"], ongoing=ongoing)
            else:
                virustotal_analysis = virustotal_analysis[0]
                if virustotal_analysis.ongoing:
                    result = virustotal_analysis.manageOngoing()
                else:
                    result = virustotal_analysis.result
            widget_url = ""
            if not(virustotal_analysis.ongoing):
                widget_url = virustotal_analysis.manageDone()
            return JsonResponse({'message': result, 'url': widget_url})
        else:
            return JsonResponse({'message': "error"})


@login_required
def virustotal_dll(request):
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
            dll = DllList.objects.get(pk=id)
            virustotal_analysis = VirustotalAnalysisDll.objects.filter(
                dllList__pk=id)
            if len(virustotal_analysis) == 0:
                # Do the analysis
                dll_path = f'Cases/Results/dll_dump_{str(dll.process.investigation.id)}/{dll.File_output}'
                scan_res = virustotal_filescan.delay(dll_path)
                result = scan_res.get()

                # Save results
                ongoing = (result["data"]["type"] == "analysis")
                virustotal_analysis = VirustotalAnalysisDll.objects.create(
                    dllList=dll, result=result, analysisId=result["data"]["id"], ongoing=ongoing)
            else:
                virustotal_analysis = virustotal_analysis[0]
                if virustotal_analysis.ongoing:
                    result = virustotal_analysis.manageOngoing()
                else:
                    result = virustotal_analysis.result
            widget_url = ""
            if not(virustotal_analysis.ongoing):
                widget_url = virustotal_analysis.manageDone()
            return JsonResponse({'message': result, 'url': widget_url})
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


@login_required
def clamAV(request):
    """ClamAV analysis

        Arguments:
        request : http request object

        Comments:
        Start analysis with clamAV for a file and show results
        """
    if request.method == "POST":
        form = ClamAVForm(request.POST)
        if form.is_valid():
            id = form.cleaned_data['id']
            model = form.cleaned_data['model']
            if model == "DllList":
                dll = DllList.objects.get(pk=id)
                # Do the analysis
                dll_path = f'Cases/Results/dll_dump_{str(dll.process.investigation.id)}/{dll.File_output}'
                scan_res = clamav_file.delay(dll_path)
                result = scan_res.get()
            else:
                MODELS = {"PsScan": (PsScan, ProcessDump, "PID", "pid", dump_memory_pid, 'Cases/Results/process_dump_'),
                          "FileScan": (FileScan, FileDump, "Offset", "offset", dump_memory_file, 'Cases/Results/file_dump_')}
                scan_model, dump_model, comparaison_field_name_scan, comparaison_field_name_dump, dump_function, dump_path = MODELS[
                    model]
                scan_object = scan_model.objects.get(pk=id)
                filter_dict = {"case_id": scan_object.investigation,
                               comparaison_field_name_dump: getattr(scan_object, comparaison_field_name_scan)}
                dump_object = dump_model.objects.filter(**filter_dict)
                if len(dump_object) == 0:
                    dump_res = dump_function.delay(
                        str(scan_object.investigation.id), getattr(scan_object, comparaison_field_name_scan))
                    filename = dump_res.get()
                    filter_dict["filename"] = filename
                    dump_model.objects.create(**filter_dict)
                    dump_object = dump_model.objects.filter(**filter_dict)
                # Do the analysis
                case_path = dump_path + str(scan_object.investigation.id)
                scan_res = clamav_file.delay(
                    case_path+"/"+dump_object[0].filename)
                result = scan_res.get()
            print(result)
            return JsonResponse({'message': result})
        else:
            return JsonResponse({'message': "error"})
