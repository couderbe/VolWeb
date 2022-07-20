from analyser.models import Analysis, Command, Connection, Dump, File, Process
from analyser.rules import run_rules
from investigations.models import *
from iocs.models import IOC
from investigations.celery import app
from windows_engine.vol_windows import *
from linux_engine.vol_linux import *
import windows_engine

"""Process dump task"""
@app.task(name="dump_memory_pid")
def dump_memory_pid(case_id,pid):
    case = UploadInvestigation.objects.get(pk=case_id)
    dump_path = "Cases/" + case.name
    output_path = 'Cases/Results/process_dump_'+case_id
    try:
        subprocess.check_output(['mkdir', output_path])
    except:
        pass
    try:
        result = dump_process(dump_path, pid, output_path)
        return result
    except:
        print("Error processing memory dump ")
        return "ERROR"

"""Dumpfile (single file)"""
@app.task(name="dump_memory_file")
def dump_memory_file(case_id, offset):
    case = UploadInvestigation.objects.get(pk=case_id)
    dump_path = "Cases/" + case.name
    data = []
    output_path = 'Cases/Results/file_dump_'+case_id
    try:
        subprocess.check_output(['mkdir', output_path])
    except:
        pass
    result = dump_file(dump_path, offset, output_path)
    logger.info(f"Result : {result}")
    return result

"""Windows automatic analysis"""
def windows_memory_analysis(dump_path,case):
    PARTIAL_RESULTS = run_volweb_routine_windows(dump_path,case.id,case)
    case.percentage = "100"
    if PARTIAL_RESULTS:
        case.status = "4"
    else:
        case.status = "2"
    case.save()

    # Run rules detection
    logger.info("Running detection rules")
    
    windows_engine.models.RulesResult.objects.create(investigation_id=case.id, result=run_rules(case.id))    

    # Generate model for analyser
    #TODO Handle all cases
    id = case.id
    analysis = Analysis(name=str(id),investigation_id=id)
    analysis.save()
    imageSignature = ImageSignature.objects.get(investigation_id = id)
    dump = Dump(analysis=analysis,md5=imageSignature.md5,sha1=imageSignature.sha1,sha256=imageSignature.sha256,investigation_id=id)
    dump.save()
    analysis.children = json.dumps({'children': [str(dump.id)]})
    analysis.save()
    psscan = PsScan.objects.filter(investigation_id = id)
    for ps in psscan:
        proc = Process(dump=dump,ps_scan=ps,investigation_id=id)
        proc.save()
    commands = CmdLine.objects.filter(investigation_id  = id)
    for command in commands:
        proc = Process.objects.filter(investigation_id = id, ps_scan__PID = command.PID,ps_scan__ImageFileName=command.Process)
        if len(proc) > 1:
            print(command.Process)
            print(len(proc))
            for p in proc:
                try:
                    print(p.ps_scan.ImageFileName)
                except Exception as e:
                    print(e)
        if len(proc) == 0:
            print("No proc found")
        cmd = Command(process=proc[0],cmdline=command,investigation_id=id)
        cmd.save()
    files = FileScan.objects.filter(investigation_id = id)
    for file in files:
        f = File(file=file,investigation_id = id)
        f.save()
    connections = NetScan.objects.filter(investigation_id=id)
    for connection in connections:
        proc = Process.objects.filter(investigation_id = id, ps_scan__PID = connection.PID)
        if len(proc) == 0:
            print(connection.PID)
            print(connection.Owner)
            print(connection.Proto)
            # con = Connection(netscan=connection,investigation_id=id)
            # con.save()
        elif len(proc) == 1:
            con = Connection(netscan=connection,process=proc[0],investigation_id=id)
            con.save()
        else:
            print("More than 1")
            print(connection)
            print(len(proc))
            for p in proc:
                print(p)
    return

"""Linux Memory Analysis (Not implemented yet)"""
def linux_memory_analysis(dump_path, case):
    PARTIAL_RESULTS = run_volweb_routine_linux(dump_path,case.id,case)
    case.percentage = "100"
    if PARTIAL_RESULTS:
        case.status = "4"
    else:
        case.status = "2"
    case.save()
    return

"""Main Task"""
@app.task(name="start_memory_analysis")
def start_memory_analysis(dump_path,id):
    case = UploadInvestigation.objects.get(pk=id)
    if case.os_version == "Windows":
        windows_memory_analysis(dump_path,case)
    else:
        linux_memory_analysis(dump_path,case)
