import markdown
from windows_engine.models import *
from investigations.models import ImageSignature

def report(case):
    #FILTERING STEP#
    signatures = ImageSignature.objects.get(investigation=case)

    cmdline_suspicious = CmdLine.objects.filter(investigation=case, Tag="Suspicious")
    cmdline_evidence = CmdLine.objects.filter(investigation=case, Tag="Evidence")

    privs_suspicious = Privs.objects.filter(investigation=case, Tag="Suspicious")
    privs_evidence = Privs.objects.filter(investigation=case, Tag="Evidence")

    envars_suspicious = Envars.objects.filter(investigation=case, Tag="Suspicious")
    envars_evidence = Envars.objects.filter(investigation=case, Tag="Evidence")

    dlllist_suspicious = DllList.objects.filter(investigation=case, Tag="Suspicious")
    dlllist_evidence = DllList.objects.filter(investigation=case, Tag="Evidence")


    handles_suspicious = Handles.objects.filter(investigation=case, Tag="Suspicious")
    handles_evidence = Handles.objects.filter(investigation=case, Tag="Evidence")


    netscan_suspicious = NetScan.objects.filter(investigation=case, Tag="Suspicious")
    netscan_evidence = NetScan.objects.filter(investigation=case, Tag="Evidence")

    netstat_suspicious = NetStat.objects.filter(investigation=case, Tag="Suspicious")
    netstat_evidence = NetStat.objects.filter(investigation=case, Tag="Evidence")

    timeline_suspicious = Timeliner.objects.filter(investigation=case, Tag="Suspicious")
    timeline_evidence = Timeliner.objects.filter(investigation=case, Tag="Evidence")


    userassist_suspicious = UserAssist.objects.filter(investigation=case, Tag="Suspicious")
    userassist_evidence = UserAssist.objects.filter(investigation=case, Tag="Evidence")


    #BEGIN HEADER#
    html = markdown.markdown("# 📄 Investigation report : "+case.title)
    text = "# 📄 Investigation report : "+case.title + "\n"

    html += markdown.markdown(case.description)
    text += case.description

    html += markdown.markdown("## 🧬 Case metadata ")
    text += "## 🧬 Case metadata \n"

    html += markdown.markdown("**Report date** : DATE")
    text += "**Report date** : DATE \n"

    html += markdown.markdown("**Memory image signatures :**")
    text += "**Memory image signatures :** \n"

    html += markdown.markdown("* MD5 : " + signatures.md5 + "\n * SHA1 : " + signatures.sha1 + "\n * SHA256 : " + signatures.sha256, extensions=['sane_lists'])
    text += "* MD5 : " + signatures.md5 + "\n * SHA1 : " + signatures.sha1 + "\n * SHA256 : ""* MD5 : " + signatures.md5 + "\n * SHA1 : " + signatures.sha1 + "\n * SHA256 : "

    html += markdown.markdown("**Investigator(s) on the case :** " + case.investigators )
    text += "**Investigator(s) on the case :** " + case.investigators + " \n"

    html += markdown.markdown("***This report was automatically generated with VolWeb.***")
    text += "***This report was automatically generated with VolWeb.*** \n"
    # END HEADER #

    # BEGIN EVIDENCE ITEMS #

    html += markdown.markdown("## 🟥 Evidence")
    text += "## 🟥 Evidence"

    html += markdown.markdown("The following artifacts were marked as **evidence** and should be considered as proof that is relevant to the investigation.")
    text += "The following artifacts were marked as **evidence** and should be considered as proof that is relevant to the investigation. \n"

    if cmdline_evidence:
        table = "PID  | Process | Arguments | Source | \n ------------- | ------------- | ------------- | -------------\n"
        for process in cmdline_evidence:
            table += f" {process.PID} | {process.Process} | {process.Args} | Command line arguments \n"
            text += f" {process.PID} | {process.Process} | {process.Args} | Command line arguments \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if privs_evidence:
        table = "PID  | Process Value | Privilege |  Attributes | Description | Value | Source | \n ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | -------------\n"

        for process in privs_evidence:
            table += f"{process.PID} | {process.Process} | {process.Privilege} | {process.Attributes} | {process.Description} | {process.Value} | Privileges \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if envars_evidence:
        table = "Block  | PID | Process |  Variable | Value | Source |\n ------------- | ------------- | ------------- | ------------- | ------------- | -------------\n"
        for process in envars_evidence:
            table += f" {process.Block} | {process.PID} | {process.Process} | {process.Variable} | {process.Value} |  Environment variables\n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if dlllist_evidence:
        table = "Process  | PID | Base | Name | Path | Size | Source \n ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | -------------\n"
        for process in dlllist_evidence:
            table += f"{process.Process} | {process.PID} | {process.Base} | {process.Name} | {process.Path} | {process.Size} | {process.LoadTime} | Dynamic link libraries \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if handles_evidence:
        table = "Process  | PID | Offset | Name | Handle Value | Granted Access | Type | Source \n ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | -------------\n"
        for process in handles_evidence:
            table += f"{process.Process} | {process.PID} | {process.Offset} | {process.Name} | {process.HandleValue} | {process.GrantedAccess} | {process.Type} | Handles \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if netscan_evidence:
        table = "Created  | Offset | Owner | Protocol | LocalAddr| ForeignAddr | State | PID | Source \n ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | -------------\n"
        for process in netscan_evidence:
            table += f"{process.Created} | {process.Offset} | {process.Owner} | {process.Proto} | {process.LocalAddr} | {process.ForeignAddr} | {process.State} | {process.PID} | NetScan \n"
        for process in netstat_evidence:
            table += f"{process.Created} | {process.Offset} | {process.Owner} | {process.Proto} | {process.LocalAddr} | {process.ForeignAddr} | {process.State} | {process.PID} | NetStat \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if userassist_evidence:
        table = "HiveOffset  | HiveName | Path | LastWriteTime | Type | Name | ID | Count | TimeFocused | LastUpdated | Source \n ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | -------------  | -------------\n"
        for process in userassist_evidence:
            table += f"{process.HiveOffset} | {process.HiveName} | {process.Path} | {process.LastWriteTime} | {process.Type} | {process.Name} | {process.ID} | {process.Count} | {process.TimeFocused} | {process.LastUpdated} | User Assist \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table


    if timeline_evidence:
        table = "AccessedDate  | ChangedDate | CreatedDate | Description | ModifiedDate | Plugin \n ------------- | ------------- | ------------- | ------------- | ------------- | -------------\n"
        for process in timeline_evidence:
            table += f"{process.AccessedDate} | {process.ChangedDate} | {process.CreatedDate} | {process.Description} | {process.ModifiedDate} | {process.Plugin} |  \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    # END EVIDENCE ITEMS #


    # BEGIN SUSPICIOUS ITEMS #
    html += markdown.markdown("## 🟨 Suspicious items")
    text += "## 🟨 Suspicious items"

    html += markdown.markdown("The following artifacts were marked as **suspicious** and should be considered by the reader for further investigation.")
    text += "The following artifacts were marked as **suspicious** and should be considered by the reader for further investigation. \n"

    if cmdline_suspicious:
        table = "PID  | Process | Arguments | Source | \n ------------- | ------------- | ------------- | -------------\n"
        for process in cmdline_suspicious:
            table += f" {process.PID} | {process.Process} | {process.Args} | Command line arguments \n"
            text += f" {process.PID} | {process.Process} | {process.Args} | Command line arguments \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if privs_suspicious:
        table = "PID  | Process Value | Privilege |  Attributes | Description | Value | Source | \n ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | -------------\n"

        for process in privs_suspicious:
            table += f"{process.PID} | {process.Process} | {process.Privilege} | {process.Attributes} | {process.Description} | {process.Value} | Privileges \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if envars_suspicious:
        table = "Block  | PID | Process |  Variable | Value | Source |\n ------------- | ------------- | ------------- | ------------- | ------------- | -------------\n"
        for process in envars_suspicious:
            table += f" {process.Block} | {process.PID} | {process.Process} | {process.Variable} | {process.Value} |  Environment variables\n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if dlllist_suspicious:
        table = "Process  | PID | Base | Name | Path | Size | Source \n ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | -------------\n"
        for process in dlllist_suspicious:
            table += f"{process.Process} | {process.PID} | {process.Base} | {process.Name} | {process.Path} | {process.Size} | {process.LoadTime} | Dynamic link libraries \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if handles_suspicious:
        table = "Process  | PID | Offset | Name | Handle Value | Granted Access | Type | Source \n ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | -------------\n"
        for process in handles_suspicious:
            table += f"{process.Process} | {process.PID} | {process.Offset} | {process.Name} | {process.HandleValue} | {process.GrantedAccess} | {process.Type} | Handles \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if netscan_suspicious:
        table = "Created  | Offset | Owner | Protocol | LocalAddr| ForeignAddr | State | PID | Source \n ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | -------------\n"
        for process in netscan_suspicious:
            table += f"{process.Created} | {process.Offset} | {process.Owner} | {process.Proto} | {process.LocalAddr} | {process.ForeignAddr} | {process.State} | {process.PID} | NetScan \n"
        for process in netstat_suspicious:
            table += f"{process.Created} | {process.Offset} | {process.Owner} | {process.Proto} | {process.LocalAddr} | {process.ForeignAddr} | {process.State} | {process.PID} | NetStat \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if userassist_suspicious:
        table = "HiveOffset  | HiveName | Path | LastWriteTime | Type | Name | ID | Count | TimeFocused | LastUpdated | Source \n ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | -------------  | -------------\n"
        for process in userassist_suspicious:
            table += f"{process.HiveOffset} | {process.HiveName} | {process.Path} | {process.LastWriteTime} | {process.Type} | {process.Name} | {process.ID} | {process.Count} | {process.TimeFocused} | {process.LastUpdated} | User Assist \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table


    if timeline_suspicious:
        table = "AccessedDate  | ChangedDate | CreatedDate | Description | ModifiedDate | Plugin \n ------------- | ------------- | ------------- | ------------- | ------------- | -------------\n"
        for process in timeline_suspicious:
            table += f"{process.AccessedDate} | {process.ChangedDate} | {process.CreatedDate} | {process.Description} | {process.ModifiedDate} | {process.Plugin} |  \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    # END SUSPICIOUS ITEMS #





    return html, text
