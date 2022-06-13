from celery import uuid
from django.db import models
import uuid

from investigations.models import PsScan

CHOICES = (
    ('Windows', 'Windows'),
)


class Node(models.Model):
    id = models.UUIDField(primary_key=True,
                          default=uuid.uuid4,
                          editable=False)
    children = models.JSONField(null=True,blank=True)
    investigation_id = models.IntegerField(null=True)
    class Meta:
        abstract = True


class Analysis(Node):
    name = models.CharField(max_length=255, default="Undefined name")


class Command(Node):
    args = models.CharField(max_length=255, default="")

class Dump(Node):
    analysis = models.ForeignKey(Analysis, on_delete=models.CASCADE)
    md5 = models.CharField(max_length = 32,null = True)
    sha1 = models.CharField(max_length = 40,null = True)
    sha256 = models.CharField(max_length = 64,null = True)
class Process(Node):
    dump = models.ForeignKey(Dump, on_delete=models.CASCADE)
    # pid = models.IntegerField(null=True)
    # ppid = models.IntegerField(null=True)
    # session_id = models.IntegerField(null=True)
    # wow64 = models.BooleanField()
    # create_time = models.DateField()
    # exit_time = models.DateField()
    ps_scan = models.ForeignKey(PsScan, on_delete=models.CASCADE)
    is_malicious = models.BooleanField(default=False)
    threat = models.CharField(max_length=500, default="")

class Connection(Node):
    foreign_addr = models.CharField(max_length=255, default="")
    local_addr = models.CharField(max_length=255, default="")
    foreign_port = models.IntegerField(null=True)
    local_port = models.IntegerField(null=True)
    offset = models.IntegerField(null=True)
    pid = models.IntegerField(null=True)
    owner = models.CharField(max_length=255, default="")
    protocol = models.CharField(max_length=255, default="")
    state = models.CharField(max_length=255, default="")
    process = models.ForeignKey(Process, on_delete=models.CASCADE,blank=True)

class File(Node):
    offset = models.BigIntegerField(null=True)
    size = models.BigIntegerField(null=True)