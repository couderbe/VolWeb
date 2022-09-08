from datetime import datetime
import json
from celery import uuid
from django.db import models
import uuid
import os
from analyser.tasks import get_file_related_to_analysis, get_widget_url, is_filescan_done

from windows_engine.models import CmdLine, DllList, FileScan, NetScan, PsList, PsScan
from django.conf import settings
from django.core.files.storage import FileSystemStorage

CHOICES = (
    ('Windows', 'Windows'),
)


class Node(models.Model):
    """Abstract class for all graph Nodes
    """
    id = models.UUIDField(primary_key=True,
                          default=uuid.uuid4,
                          editable=False)
    children = models.JSONField(null=True, blank=True, default=json.dumps({'children': []}))
    investigation_id = models.IntegerField(null=True)

    class Meta:
        abstract = True


class Analysis(Node):
    name = models.CharField(max_length=255, default="Undefined name")

class Dump(Node):
    analysis = models.ForeignKey(Analysis, on_delete=models.CASCADE)
    md5 = models.CharField(max_length=32, null=True)
    sha1 = models.CharField(max_length=40, null=True)
    sha256 = models.CharField(max_length=64, null=True)


class Process(Node):
    dump = models.ForeignKey(Dump, on_delete=models.CASCADE)
    ps_list = models.ForeignKey(PsList, on_delete=models.CASCADE, null=True)

class Command(Node):
    process = models.ForeignKey(Process, on_delete=models.CASCADE)
    cmdline = models.ForeignKey(CmdLine, on_delete=models.CASCADE)


class Connection(Node):
    netscan = models.ForeignKey(NetScan, on_delete=models.CASCADE)
    process = models.ForeignKey(Process, on_delete=models.CASCADE, blank=True)


class File(Node):
    file = models.ForeignKey(FileScan, on_delete=models.CASCADE)

class Dll(Node):
    dll = models.ForeignKey(DllList, on_delete=models.CASCADE)
    process = models.ForeignKey(Process, on_delete=models.CASCADE, blank=True)

class RulesStorage(FileSystemStorage):
    """Custom FileSystemStorage for Analysis Rules
    """
    def get_available_name(self, name, max_length=None):
        if self.exists(name):
            os.remove(os.path.join(settings.MEDIA_ROOT, name))
        return name


class Rule(models.Model):
    id = models.AutoField(primary_key=True)
    title = models.TextField()
    enabled = models.BooleanField(default=True)
    file = models.FileField(storage=RulesStorage(), upload_to="analyser/rules")
    os = models.CharField(max_length=50, choices=CHOICES)


class VirustotalAnalysis(models.Model):
    ongoing = models.BooleanField(default=True)
    analysisId = models.CharField(max_length=256)
    widgetUrl = models.CharField(max_length=500, default="")
    widgetDate = models.DateTimeField(default=datetime.now)
    result = models.JSONField()

    class Meta:
        abstract = True

    def manageOngoing(self) -> dict:
        res = is_filescan_done.delay(self.analysisId)
        is_done = res.get()
        if is_done:
            self.ongoing = False
            file_res = get_file_related_to_analysis.delay(
                self.analysisId)
            result = file_res.get()
            self.result = result
            self.analysisId = result["data"]["id"]
            self.save(update_fields=["result", "ongoing"])
        else:
            result = self.result
        return result

    def manageDone(self) -> str:
        delta = (datetime.now().timestamp() - self.widgetDate.timestamp())/3600
        if delta > 70 or self.widgetUrl == "":
            widget_res = get_widget_url.delay(self.analysisId)
            widget_url = widget_res.get()
            self.widgetDate = datetime.now()
            self.widgetUrl = widget_url
            self.save(update_fields=["widgetDate", "widgetUrl"])
        else:
            widget_url = self.widgetUrl
        return widget_url


class VirustotalAnalysisFile(VirustotalAnalysis):
    filescan = models.ForeignKey(FileScan, on_delete=models.CASCADE)


class VirustotalAnalysisProcess(VirustotalAnalysis):
    processScan = models.ForeignKey(PsScan, on_delete=models.CASCADE)


class VirustotalAnalysisDll(VirustotalAnalysis):
    dllList = models.ForeignKey(DllList, on_delete=models.CASCADE)
