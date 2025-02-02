import subprocess
from analyser.tasks import clamav_file
from investigations.celery import app
import volatility3
import os
from investigations.models import UploadInvestigation
import windows_engine
from VolWeb.voltools import DictRenderer, file_handler


def init_volatility():
    volatility3.framework.require_interface_version(2, 0, 0)
    failures = volatility3.framework.import_files(volatility3.plugins, True)
    plugin_list = volatility3.framework.list_plugins()
    context = volatility3.framework.contexts.Context()
    return plugin_list, context


def construct_plugin(context, plugin, dump_path, output_path="Cases/files"):
    available_automagics = volatility3.framework.automagic.available(context)
    automagics = volatility3.framework.automagic.choose_automagic(
        available_automagics, plugin)
    context.config['automagic.LayerStacker.stackers'] = volatility3.framework.automagic.stacker.choose_os_stackers(
        plugin)
    context.config['automagic.LayerStacker.single_location'] = "file://" + \
        os.getcwd() + "/" + dump_path
    return volatility3.framework.plugins.construct_plugin(context, automagics, plugin, "plugins", None, file_handler(output_path))


@app.task(name="dlllist_task")
def dlllist_task(case_id: int, id: int) -> None:
    process = windows_engine.models.PsScan.objects.filter(investigation_id = case_id, pk=id)[0]
    case = UploadInvestigation.objects.get(pk=case_id)
    path = 'Cases/' + case.existingPath
    plugin_list, context = init_volatility()
    plugin = plugin_list["windows.dlllist.DllList"]
    # Dump the dlls for future download
    context.config["plugins.DllList.dump"] = True
    context.config["plugins.DllList.pid"] = [process.PID]
    output_path = f"Cases/Results/dll_dump_{case.id}"
    try:
        subprocess.check_output(['mkdir', output_path])
    except:
        pass
    constructed = construct_plugin(context, plugin, path, output_path)
    result = DictRenderer().render(constructed.run())
    for res in result:
        del res['__children']
        del res['Process']
        res['File_output'] = res['File output']
        del res['File output']
        is_clamav_suspicious, clamav_details = clamav_file(output_path+"/"+res['File_output'])
        res['is_clamav_suspicious'] = is_clamav_suspicious
        res['clamav_details'] = clamav_details
        windows_engine.models.DllList.objects.create(process=process, **res)


@app.task(name="handles_task")
def handles_task(case_id: int, id: int):
    process = windows_engine.models.PsScan.objects.filter(investigation_id = case_id, pk=id)[0]
    case = UploadInvestigation.objects.get(pk=case_id)
    path = 'Cases/' + case.existingPath
    plugin_list, context = init_volatility()
    plugin = plugin_list["windows.handles.Handles"]
    context.config["plugins.Handles.pid"] = [process.PID]
    constructed = construct_plugin(context, plugin, path)
    result = DictRenderer().render(constructed.run())
    for res in result:
        del res['__children']
        del res['Process']
        windows_engine.models.Handles.objects.create(process=process, **res)
