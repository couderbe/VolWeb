from json import dumps
import json
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from analyser.elements.command import Command
from analyser.elements.dump import Dump
from analyser.elements.process import Process
from analyser.elements.analysis import Analysis

from investigations.models import UploadInvestigation


@login_required
def analyser(request):
    with open('Cases/Results/'+'12'+'.json') as f:
        investData = json.load(f)
    # caseData = UploadInvestigation.objects.get(pk=1)
    # print(caseData)
    # print(type(caseData))
    dmp = Dump("Example Memory Dump")
    processes = [Process(name=elt['ImageFileName'],
                         pid=elt['PID'], ppid=elt['PPID'], sessionId=elt['SessionId'], wow64=elt['Wow64'], createTime=elt['CreateTime'], exitTime=elt['ExitTime']) for elt in investData['psscan']]
    dmp.children.extend(processes)
    context = [{"name": "Analysis", "children": [{"name": dmp.name, "uid": 25, "children": [
        {"name": "Process 1", "uid": 13, "template": {"tooltipText": 'PID: {uid}'},
         "userData": {"string": "Une chaîne de test", "integer": 1999}},
        {"name": "Process 2", "uid": 14, "pid": 6666, "template":
         {"tooltipText": "PID: {pid}"}}]}, ]}]
    analysis = Analysis("Analyse")
    analysis.loadDump(investData)
    print([analysis.toDict()])
    dataJSON = dumps([analysis.toDict()])
    #dataJSON = dumps(context)
    return render(request, 'analyser/analyser.html', {'data': dataJSON})
