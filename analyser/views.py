from json import dumps
import json
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from analyser.elements.command import Command
from analyser.elements.dump import Dump
from analyser.elements.node import Node
from analyser.elements.process import Process
from analyser.elements.analysis import Analysis
from investigations.forms import DownloadDump, ManageInvestigation

from investigations.models import UploadInvestigation


@login_required
def analyser(request):
    if request.method == 'GET':
        form = ManageInvestigation(request.GET)
        if form.is_valid():
            id = form.cleaned_data['sa_case_id']
            with open('Cases/Results/'+str(id)+'.json') as f:
                investData = json.load(f)
            analysis = Analysis("Analyse")
            analysis.loadDump(investData)
            dataJSON = dumps(analysis.toDict())
            groups = dumps([sub.__name__ for sub in Node.__subclasses__()])
            return render(request, 'analyser/analyser.html', {'data': dataJSON,'groups':groups})

@login_required
def get_process_info(request):
    form = DownloadDump(request.POST)
    if form.is_valid():
        id = form.cleaned_data['id']
        return JsonResponse({'Unimplemented': 'Unimplemented'},status=200)