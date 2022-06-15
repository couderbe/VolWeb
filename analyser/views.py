from hashlib import sha1
from json import dumps
import json
from django.core import serializers
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from django.apps import apps
from investigations.forms import *

from analyser.models import *
from investigations.models import ImageSignature

@login_required
def analyser_old(request):
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
def analyser(request):
    if request.method == 'GET':
        form = ManageInvestigation(request.GET)
        if form.is_valid():
            
            id = form.cleaned_data['sa_case_id']
            case = UploadInvestigation.objects.get(pk=id)
            context = {}
            context['case'] = case

            #Models
            models = {
                'Analysis':serializers.serialize("json",Analysis.objects.filter(investigation_id = id)),
                'Dump':serializers.serialize("json",Dump.objects.filter(investigation_id = id)),
                'Process' : serializers.serialize("json",Process.objects.filter(investigation_id = id)),
                'Command': serializers.serialize("json",Command.objects.filter(investigation_id = id)),
                'Connection': serializers.serialize("json",Connection.objects.filter(investigation_id = id)),
                'File': serializers.serialize("json",File.objects.filter(investigation_id = id)),
            }
            
            context.update(models)
            context = json.dumps(models)
            return render(request, 'analyser/analyser.html',models)

@login_required
def get_process_info(request):
    form = DownloadDump(request.POST)
    if form.is_valid():
        id = form.cleaned_data['id']
        return JsonResponse({'Unimplemented': 'Unimplemented'},status=200)