from celery import uuid
from django.db import models
import uuid

from windows_engine.models import CmdLine, FileScan, NetScan, NetStat, PsScan

CHOICES = (
    ('Windows', 'Windows'),
)


class Node(models.Model):
    id = models.UUIDField(primary_key=True,
                          default=uuid.uuid4,
                          editable=False)
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
    ps_scan = models.ForeignKey(PsScan, on_delete=models.CASCADE)
    is_malicious = models.BooleanField(default=False)
    threat = models.CharField(max_length=500, default="")


class Command(Node):
    process = models.ForeignKey(Process, on_delete=models.CASCADE)
    cmdline = models.ForeignKey(CmdLine, on_delete=models.CASCADE)


class Connection(Node):
    netscan = models.ForeignKey(NetScan, on_delete=models.CASCADE)
    process = models.ForeignKey(Process, on_delete=models.CASCADE, blank=True)


class File(Node):
    file = models.ForeignKey(FileScan, on_delete=models.CASCADE)


class Rule(models.Model):
    id = models.AutoField(primary_key=True)
    title = models.TextField()
    enabled = models.BooleanField(default=True)
    file = models.FileField(upload_to="analyser/rules")
    os = models.CharField(max_length=50, choices=CHOICES)


class VirustotalAnalysis(models.Model):
    ongoing = models.BooleanField(default=True)
    analysisId = models.CharField(max_length=256)
    filescan = models.ForeignKey(FileScan, on_delete=models.CASCADE)
    result = models.JSONField()
