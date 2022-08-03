import json
from django.core import serializers
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from investigations.forms import *

from analyser.models import *

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