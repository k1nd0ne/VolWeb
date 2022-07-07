from investigations.celery import app
import volatility3
import os
from investigations.models import UploadInvestigation
from VolWeb.voltools import DictRenderer, file_handler


def init_volatility():
    volatility3.framework.require_interface_version(2,0,0)
    #TODO Try to load only dlllist
    failures = volatility3.framework.import_files(volatility3.plugins, True)
    plugin_list = volatility3.framework.list_plugins()
    context = volatility3.framework.contexts.Context()
    return plugin_list,context

def construct_plugin(context,plugin,path):
    available_automagics = volatility3.framework.automagic.available(context)
    automagics = volatility3.framework.automagic.choose_automagic(available_automagics, plugin)
    context.config['automagic.LayerStacker.stackers'] = volatility3.framework.automagic.stacker.choose_os_stackers(plugin)
    context.config['automagic.LayerStacker.single_location'] = "file://" + os.getcwd() + "/" + path
    return volatility3.framework.plugins.construct_plugin(context, automagics, plugin, "plugins", None, file_handler("Cases/files"))

@app.task(name="dlllist")
def dlllist(id: int,pid: int) -> list:
    case = UploadInvestigation.objects.get(pk=id)
    path = 'Cases/' + case.existingPath
    plugin_list,context = init_volatility()
    plugin = plugin_list["windows.dlllist.DllList"]
    context.config["plugins.DllList.dump"] = False
    context.config["plugins.DllList.pid"] = [pid]
    constructed = construct_plugin(context,plugin,path)
    return DictRenderer().render(constructed.run())

@app.task(name="handles")
def handles(id: int,pid: int) -> list:
    case = UploadInvestigation.objects.get(pk=id)
    path = 'Cases/' + case.existingPath
    plugin_list,context = init_volatility()
    plugin = plugin_list["windows.handles.Handles"]
    context.config["plugins.Handles.pid"] = [pid]
    constructed = construct_plugin(context,plugin,path)
    return DictRenderer().render(constructed.run())