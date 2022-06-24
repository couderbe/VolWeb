from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from analyser.rules import run_rules
from investigations.forms import ManageInvestigation
from investigations.models import ImageSignature
import windows_engine.models as windows_engine
import linux_engine.models as linux_engine
from investigations.forms import *


@login_required
def analyser(request):
    if request.method == 'GET':
        form = ManageInvestigation(request.GET)
        if form.is_valid():
            case = form.cleaned_data['sa_case_id']
            id = case.id
        return JsonResponse({'Detection': run_rules(id)}, status=200)

@login_required
def detection(request):
    if request.method == 'GET':
        form = ManageInvestigation(request.GET)
        if form.is_valid():
            case = form.cleaned_data['sa_case_id']
            id = case.id
            context = {}
            context['case'] = case

            if case.os_version == "Windows":
                #Forms
                forms ={
                    'dl_hive_form':DownloadHive(),
                    'dl_dump_form': DownloadDump(),
                    'dump_file_form': DumpFile(),
                    'download_file_form': DownloadFile(),
                    'form': DumpMemory(),
                }
                #Models
                models = {
                    'dumps': windows_engine.ProcessDump.objects.filter(case_id = id),
                    'files': windows_engine.FileDump.objects.filter(case_id = id),
                    'ImageSignature' : ImageSignature.objects.get(investigation_id = id),
                    'PsScan': windows_engine.PsScan.objects.filter(investigation_id = id),
                    'PsList': windows_engine.PsList.objects.filter(investigation_id = id),
                    'PsTree': windows_engine.PsTree.objects.get(investigation_id = id),
                    'CmdLine': windows_engine.CmdLine.objects.filter(investigation_id = id),
                    'Privs': windows_engine.Privs.objects.filter(investigation_id = id),
                    'Envars': windows_engine.Envars.objects.filter(investigation_id = id),
                    'NetScan': windows_engine.NetScan.objects.filter(investigation_id = id),
                    'NetStat': windows_engine.NetStat.objects.filter(investigation_id = id),
                    'NetGraph' : windows_engine.NetGraph.objects.get(investigation_id = id),
                    'Hashdump': windows_engine.Hashdump.objects.filter(investigation_id = id),
                    'Lsadump':windows_engine.Lsadump.objects.filter(investigation_id = id),
                    'Cachedump': windows_engine.Cachedump.objects.filter(investigation_id = id),
                    'HiveList': windows_engine.HiveList.objects.filter(investigation_id = id),
                    'Timeliner': windows_engine.Timeliner.objects.filter(investigation_id = id),
                    'TimeLineChart': windows_engine.TimeLineChart.objects.get(investigation_id = id),
                    'SkeletonKeyCheck' : windows_engine.SkeletonKeyCheck.objects.filter(investigation_id = id),
                    'Malfind' : windows_engine.Malfind.objects.filter(investigation_id = id),
                    'FileScan' : windows_engine.FileScan.objects.filter(investigation_id = id),
                    'Strings' : windows_engine.Strings.objects.filter(investigation_id = id),
                    'Detection': run_rules(id),
                }
                context.update(forms)
                context.update(models)
            else:
                models = {
                    'ImageSignature' : ImageSignature.objects.get(investigation_id = id),
                    'PsList':linux_engine.PsList.objects.filter(investigation_id = id),
                    'PsTree': linux_engine.PsTree.objects.get(investigation_id = id),
                    'Bash': linux_engine.Bash.objects.filter(investigation_id = id),
                    'ProcMaps': linux_engine.ProcMaps.objects.filter(investigation_id = id),
                    'Lsof': linux_engine.Lsof.objects.filter(investigation_id = id),
                    'TtyCheck': linux_engine.TtyCheck.objects.filter(investigation_id = id),
                    'Elfs': linux_engine.Elfs.objects.filter(investigation_id = id),
                }
                context.update(models)
            return render(request, 'investigations/reviewinvest.html',context)
        else:
            form = ManageInvestigation()
            return render(request,'investigations/invest.html',{'investigations': UploadInvestigation.objects.all(), 'form': form})

