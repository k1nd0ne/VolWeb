from django.shortcuts import render
from django.contrib.auth.decorators import login_required

# Create your views here.
def get_bash(request):
    return({'message': "error"})


def check_syscall(request):
    return({'message': "error"})


def check_trap_table(request):
    return({'message': "error"})


def check_sysctl(request):
    return({'message': "error"})


def get_ifconfig(request):
    return({'message': "error"})


def get_kauth_listeners(request):
    return({'message': "error"})


def get_kauth_scopes(request):
    return({'message': "error"})


def get_kevents(request):
    return({'message': "error"})


def get_list_files(request):
    return({'message': "error"})


def get_lsmod(request):
    return({'message': "error"})


def get_lsof(request):
    return({'message': "error"})


def get_malfind(request):
    return({'message': "error"})


def get_handles(request):
    return({'message': "error"})


def get_netstat(request):
    return({'message': "error"})


def proc_maps(request):
    return({'message': "error"})


def get_psaux(request):
    return({'message': "error"})


def get_pslist(request):
    return({'message': "error"})


def get_pstree(request):
    return({'message': "error"})


def get_socket_filters(request):
    return({'message': "error"})


def check_timers(request):
    return({'message': "error"})


def get_trustedbsd(request):
    return({'message': "error"})


def get_vfsevents(request):
    return({'message': "error"})


@login_required
def mac_report(request):
    """
    Generate the mac report
    """
    form = ReportForm(request.POST)
    if form.is_valid():
        case = form.cleaned_data['case_id']
        html, text = report(case)
        return JsonResponse({'message': "success", 'html': html, 'text': text})
    else:
        return JsonResponse({'message': "error"})


@login_required
def mac_tag(request):
    """
    Tag a MacOs artifact
    """
    if request.method == 'POST':
        form = Tag(request.POST)
        if form.is_valid():
            item = apps.get_model("macos_engine", form.cleaned_data['plugin_name']).objects.get(
                id=form.cleaned_data['artifact_id'])
            if form.cleaned_data['status'] == "Evidence":
                item.Tag = "Evidence"
            elif form.cleaned_data['status'] == "Suspicious":
                item.Tag = "Suspicious"
            else:
                item.Tag = None
            item.save()
            return JsonResponse({'message': "success"})
        else:
            return JsonResponse({'message': "error"})


@login_required
def get_mac_artifacts(request):
    """Get artifacts related to all process related volatility3 plugins

    Arguments:
    request : http request object

    Comment:
    The user requested to watch the artifacts linked the process.
    """
    if request.method == 'GET':
        form = GetArtifacts(request.GET)
        if form.is_valid():
            case = form.cleaned_data['case']
            pid = form.cleaned_data['pid']
            id = case.id
            json_serializer = json.Serializer()
            # Request the appropriate artifacts
            artifacts = {
                #'Bash': json_serializer.serialize(Bash.objects.filter(investigation_id=id, PID=pid)),
                #'Elfs': json_serializer.serialize(Elfs.objects.filter(investigation_id=id, PID=pid)),
                #'Lsof': json_serializer.serialize(Lsof.objects.filter(investigation_id=id, PID=pid)),
                #'ProcMaps': json_serializer.serialize(ProcMaps.objects.filter(investigation_id=id, PID=pid)),
                #'PsAux': json_serializer.serialize(PsAux.objects.filter(investigation_id=id, PID=pid)),
                #'Sockstat': json_serializer.serialize(Sockstat.objects.filter(investigation_id=id, Pid=pid)),
                #'Envars': json_serializer.serialize(Envars.objects.filter(investigation_id=id, PID=pid)),
            }
            return JsonResponse({'message': "success", 'artifacts': artifacts})
    return JsonResponse({'message': "error"})
