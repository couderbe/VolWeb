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

    def load_dump(id: int):
        analysis = Analysis(name=str(id),investigation_id=id)
        analysis.save()
        imageSignature = ImageSignature.objects.get(investigation_id = id)
        dump = Dump(analysis=analysis,md5=imageSignature.md5,sha1=imageSignature.sha1,sha256=imageSignature.sha256,investigation_id=id)
        dump.save()
        analysis.children = json.dumps({'children': [str(dump.id)]})
        analysis.save()


    if request.method == 'GET':
        form = ManageInvestigation(request.GET)
        if form.is_valid():
            
            id = form.cleaned_data['sa_case_id']
            print("----------------------------------")
            load_dump(id)
            print("----------------------------------")
            case = UploadInvestigation.objects.get(pk=id)
            context = {}
            context['case'] = case

            #Models
            models = {
                'Analysis':serializers.serialize("json",Analysis.objects.filter(investigation_id = id)),
                'Dump':serializers.serialize("json",Dump.objects.filter(investigation_id = id)),
                # 'Process' : Process.objects.get(investigation_id = id),
                # 'Command': Command.objects.filter(investigation_id = id),
                # 'Connection': Connection.objects.get(investigation_id = id),
                # 'File': File.objects.filter(investigation_id = id),
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