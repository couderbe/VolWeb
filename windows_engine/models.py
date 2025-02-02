import base64
from django.db import models
from investigations.models import *

class ClamAVFields(models.Model):
    is_clamav_suspicious = models.BooleanField(default=False)
    clamav_details = models.CharField(max_length=1024, default="Never analysed")

    class Meta:
        abstract = True

class ProcessDump(models.Model):
    process_dump_id = models.AutoField(primary_key=True)
    case_id = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="windows_processdump_investigation"
    )
    pid = models.BigIntegerField()
    filename = models.CharField(max_length = 255)

class FileDump(models.Model):
    file_dump_id = models.AutoField(primary_key=True)
    case_id = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="windows_filedump_investigation"

    )
    offset = models.BigIntegerField(null = True)
    filename = models.CharField(max_length = 255)


class PsTree(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="windows_pstree_investigation"

        )
    graph = models.JSONField(null = True)

class NetGraph(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="windows_netgraph_investigation"

        )
    graph = models.JSONField(null = True)

class TimeLineChart(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="windows_timeline_investigation"
        )
    graph = models.JSONField(null = True)

class PsScan(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="windows_psscan_investigation"
        )
    PID = models.BigIntegerField(null = True)
    PPID = models.BigIntegerField(null = True)
    ImageFileName = models.CharField(max_length = 255,null = True)
    Offset = models.BigIntegerField(null = True)
    Threads = models.BigIntegerField(null = True)
    Handles = models.BigIntegerField(null = True)
    SessionId = models.BigIntegerField(null = True)
    Wow64 = models.BooleanField()
    CreateTime = models.CharField(max_length = 255,null = True)
    ExitTime = models.CharField(max_length = 255,null = True)
    Fileoutput = models.CharField(max_length = 255,null = True)

class PsList(ClamAVFields):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="windows_pslist_investigation"
        )
    PID = models.BigIntegerField(null = True)
    PPID = models.BigIntegerField(null = True)
    ImageFileName = models.CharField(max_length = 255,null = True)
    Offset = models.BigIntegerField(null = True)
    Threads = models.BigIntegerField(null = True)
    Handles = models.BigIntegerField(null = True)
    SessionId = models.BigIntegerField(null = True)
    Wow64 = models.BooleanField()
    CreateTime = models.CharField(max_length = 255,null = True)
    ExitTime = models.CharField(max_length = 255,null = True)
    Fileoutput = models.CharField(max_length = 255,null = True)

class CmdLine(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="windows_cmdline_investigation"
        )
    PID = models.BigIntegerField(null = True)
    Process = models.TextField(null = True)
    Args = models.TextField(null = True)


class Privs(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="windows_privs_investigation"
        )
    PID = models.BigIntegerField(null = True)
    Process = models.TextField(null = True)
    Value = models.BigIntegerField(null = True)
    Privilege = models.TextField(null = True)
    Attributes = models.TextField(null = True)
    Description = models.TextField(null = True)

class Envars(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="windows_envars_investigation"
        )
    PID = models.BigIntegerField(null = True)
    Process = models.TextField(null = True)
    Block = models.TextField(null = True)
    Variable = models.TextField(null = True)
    Value = models.TextField(null = True)
    Description = models.TextField(null = True)


class NetScan(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="windows_netscan_investigation"
        )
    Offset = models.BigIntegerField(null = True)
    Proto = models.TextField(null = True)
    LocalAddr = models.TextField(null = True)
    LocalPort = models.TextField(null = True)
    ForeignAddr = models.TextField(null = True)
    ForeignPort = models.TextField(null = True)
    State = models.TextField(null = True)
    PID = models.BigIntegerField(null = True)
    Owner = models.TextField(null = True)
    Created = models.TextField(null = True)

class NetStat(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="windows_netstat_investigation"
        )
    Offset = models.BigIntegerField(null = True)
    Proto = models.TextField(null = True)
    LocalAddr = models.TextField(null = True)
    LocalPort = models.TextField(null = True)
    ForeignAddr = models.TextField(null = True)
    ForeignPort = models.TextField(null = True)
    State = models.TextField(null = True)
    PID = models.BigIntegerField(null = True)
    Owner = models.TextField(null = True)
    Created = models.TextField(null = True)

class Hashdump(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="windows_hashdump_investigation"
        )
    User = models.TextField(null = True)
    rid = models.BigIntegerField(null = True)
    lmhash = models.TextField(null = True)
    nthash = models.TextField(null = True)


class Lsadump(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="windows_lsadump_investigation"
        )
    Key = models.TextField(null = True)
    Secret = models.TextField(null = True)
    Hex = models.TextField(null = True)
    def save(self, *args, **kwargs):
        self.Secret = base64.b64encode(bytes(self.Secret, 'utf-8'))
        super().save(*args, **kwargs)

class Cachedump(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="windows_cachedump_investigation"
        )
    Domain = models.TextField(null = True)
    Domainname = models.TextField(null = True)
    Hash = models.TextField(null = True)
    Username = models.TextField(null = True)


class HiveList(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="windows_hivelist_investigation"
        )
    FileFullPath = models.TextField(null = True)
    Offset = models.BigIntegerField(null = True)
    Fileoutput = models.TextField(null = True)

class Timeliner(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="windows_timeliner_investigation"
        )
    Plugin = models.TextField(null = True)
    Description = models.TextField(null = True)
    AccessedDate = models.TextField(null = True)
    ChangedDate = models.TextField(null = True)
    CreatedDate = models.TextField(null = True)
    ModifiedDate = models.TextField(null = True)

class SkeletonKeyCheck(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="windows_skc_investigation"
        )
    PID = models.BigIntegerField(null = True)
    Process = models.TextField(null = True)
    SkeletonKeyFound = models.TextField(null = True)
    rc4HmacInitialize = models.TextField(null = True)
    rc4HmacDecrypt = models.TextField(null = True)

class Malfind(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="windows_malfind_investigation"
        )

    PID = models.BigIntegerField(null = True)
    Process = models.TextField(null = True)
    StartVPN = models.BigIntegerField(null = True)
    EndVPN = models.BigIntegerField(null = True)
    Tag = models.TextField(null = True)
    Protection = models.TextField(null = True)
    CommitCharge = models.BigIntegerField(null = True)
    PrivateMemory = models.BigIntegerField(null = True)
    Fileoutput = models.TextField(null = True)
    Hexdump  = models.TextField(null = True)
    Disasm = models.TextField(null = True)

class FileScan(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="windows_filescan_investigation"
        )
    Offset = models.BigIntegerField(null = True)
    Name = models.TextField(null = True)
    Size = models.BigIntegerField(null = True)

class Strings(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="windows_strings_investigation"
        )
    String = models.TextField(null = True)
    PhysicalAddress = models.BigIntegerField(null = True)
    Result = models.TextField(null = True)

class RulesResult(models.Model):
    investigation = models.ForeignKey(
            UploadInvestigation,
            on_delete=models.CASCADE,
            related_name="windows_rules_investigation"
        )
    result = models.JSONField()

class DllList(ClamAVFields):
    process = models.ForeignKey(
            PsScan,
            on_delete=models.CASCADE,
        )
    PID = models.IntegerField()
    Base = models.BigIntegerField()
    Name = models.TextField()
    Path = models.TextField()
    Size = models.BigIntegerField()
    LoadTime = models.CharField(max_length=255,null=True)
    File_output = models.CharField(max_length=500)

    def natural_key(self):
        return (self.is_clamav_suspicious, self.clamav_details)

class Handles(models.Model):
    process = models.ForeignKey(
            PsScan,
            on_delete=models.CASCADE,
        )
    PID = models.IntegerField()
    Offset = models.BigIntegerField()
    Name = models.TextField(null=True)
    HandleValue = models.IntegerField()
    GrantedAccess = models.BigIntegerField()
    Type = models.CharField(max_length=255)