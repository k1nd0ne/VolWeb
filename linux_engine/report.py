import markdown, datetime
from linux_engine.models import *
from investigations.models import ImageSignature


def report(case):
    # FILTERING STEP#
    signatures = ImageSignature.objects.get(investigation=case)

    ttycheck_suspicious = TtyCheck.objects.filter(investigation=case, Tag="Suspicious")
    ttycheck_evidence = TtyCheck.objects.filter(investigation=case, Tag="Evidence")

    bash_suspicious = Bash.objects.filter(investigation=case, Tag="Suspicious")
    bash_evidence = Bash.objects.filter(investigation=case, Tag="Evidence")

    elfs_suspicious = Elfs.objects.filter(investigation=case, Tag="Suspicious")
    elfs_evidence = Elfs.objects.filter(investigation=case, Tag="Evidence")

    lsof_suspicious = Lsof.objects.filter(investigation=case, Tag="Suspicious")
    lsof_evidence = Lsof.objects.filter(investigation=case, Tag="Evidence")

    procmaps_suspicious = ProcMaps.objects.filter(investigation=case, Tag="Suspicious")
    procmaps_evidence = ProcMaps.objects.filter(investigation=case, Tag="Evidence")

    psaux_suspicious = PsAux.objects.filter(investigation=case, Tag="Suspicious")
    psaux_evidence = PsAux.objects.filter(investigation=case, Tag="Evidence")

    sockstat_suspicious = Sockstat.objects.filter(investigation=case, Tag="Suspicious")
    sockstat_evidence = Sockstat.objects.filter(investigation=case, Tag="Evidence")

    envars_suspicious = Envars.objects.filter(investigation=case, Tag="Suspicious")
    envars_evidence = Envars.objects.filter(investigation=case, Tag="Evidence")

    mountinfo_suspicious = MountInfo.objects.filter(investigation=case, Tag="Suspicious")
    mountinfo_evidence = MountInfo.objects.filter(investigation=case, Tag="Evidence")


    # BEGIN HEADER#
    html = markdown.markdown("# 📄 Investigation report : " + case.title)
    text = "# 📄 Investigation report : " + case.title + "\n"

    html += markdown.markdown(case.description)
    text += case.description

    html += markdown.markdown("## 🧬 Case metadata ")
    text += "## 🧬 Case metadata \n"

    html += markdown.markdown("**Report date** : " + str(datetime.datetime.now()))
    text += "**Report date** : " + str(datetime.datetime.now()) + " \n"

    html += markdown.markdown("**Memory image signatures :**")
    text += "**Memory image signatures :** \n"

    html += markdown.markdown(
        "* MD5 : " + signatures.md5 + "\n * SHA1 : " + signatures.sha1 + "\n * SHA256 : " + signatures.sha256,
        extensions=['sane_lists'])
    text += "* MD5 : " + signatures.md5 + "\n * SHA1 : " + signatures.sha1 + "\n * SHA256 : ""* MD5 : " + signatures.md5 + "\n * SHA1 : " + signatures.sha1 + "\n * SHA256 : "

    html += markdown.markdown("**Investigator(s) on the case :** " + case.investigators)
    text += "**Investigator(s) on the case :** " + case.investigators + " \n"

    html += markdown.markdown("***This report was automatically generated with VolWeb.***")
    text += "***This report was automatically generated with VolWeb.*** \n"
    # END HEADER #

    # BEGIN EVIDENCE ITEMS #

    html += markdown.markdown("## 🟥 Evidence")
    text += "## 🟥 Evidence"

    html += markdown.markdown(
        "The following artifacts were marked as **evidence** and should be considered as proof that is relevant to the investigation.")
    text += "The following artifacts were marked as **evidence** and should be considered as proof that is relevant to the investigation. \n"

    if ttycheck_evidence:
        table = "PhysicalAddress  | Module | Name | Symbol | \n ------------- | ------------- | ------------- | -------------\n"
        for process in ttycheck_evidence:
            table += f" {process.Address} | {process.Module} | {process.Name} | {process.Symbol} | \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if bash_evidence:
        table = "PID  | Process | CommmandTime | Command | \n ------------- | ------------- | ------------- | -------------\n"
        for process in bash_evidence:
            table += f" {process.PID} | {process.Process} | {process.CommandTime} | {process.Command} | \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if elfs_evidence:
        table = "Start  | End | FilePath | Process | PID | \n ------------- | ------------- | ------------- | ------------- | -------------\n"
        for process in elfs_evidence:
            table += f" {process.Start} | {process.End} | {process.FilePath} | {process.Process} |  {process.PID} | \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if psaux_evidence:
        table = "PID  | PPID | COMM | Args | \n ------------- | ------------- | ------------- | -------------\n"
        for process in psaux_evidence:
            table += f" {process.PID} | {process.PPID} | {process.COMM} | {process.ARGS} | \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if envars_evidence:
        table = "COMM  | KEY | PPID | VALUE | \n ------------- | ------------- | ------------- | -------------\n"
        for process in envars_evidence:
            table += f" {process.COMM} | {process.KEY} | {process.PPID} | {process.VALUE} | \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if lsof_evidence:
        table = "FD  | PID | Path | Process | \n ------------- | ------------- | ------------- | -------------\n"
        for process in lsof_evidence:
            table += f" {process.FD} | {process.PID} | {process.Path} | {process.Process} | \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if procmaps_evidence:
        table = "Start  | End | FilePath | Flags |  Inode |  Major |  Minor |  PID |  PgOff |  Process | \n ------------- | ------------- | ------------- | ------------- | -------------| -------------| -------------| -------------| ------------- | -------------\n"
        for process in procmaps_evidence:
            table += f" {process.Start} | {process.End} | {process.FilePath} | {process.Flags} | {process.Inode} | {process.Major} | {process.PID} | {process.Minor} | {process.PgOff} | {process.Process} | \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if mountinfo_evidence:
        table = "FIELDS  | FSTYPE | MAJOR_MINOR | MNT_NS_ID |  MOUNTID |  MOUNT_OPTIONS |  MOUNT_POINT |  MOUNT_SRC |  PARENT_ID |  ROOT | SB_OPTIONS | \n ------------- | ------------- | ------------- | ------------- | -------------| -------------| -------------| -------------| ------------- | ------------- | -------------\n"
        for process in mountinfo_evidence:
            table += f" {process.FIELDS} | {process.FSTYPE} | {process.MAJOR_MINOR} | {process.MNT_NS_ID} | {process.MOUNTID} | {process.MOUNT_OPTIONS} | {process.MOUNT_POINT} | {process.MOUNT_SRC} | {process.PARENT_ID} | {process.ROOT} | SB_OPTIONS | \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if sockstat_evidence:
        table = "DestAddr  | DestPort | FD | Family |  Filter |  NetNs |  Proto |  SockOffset |  SrcAddr |  SrcPort | State | Type | \n ------------- | ------------- | ------------- | ------------- | -------------| -------------| -------------| -------------| ------------- | ------------- | ------------- | -------------\n"
        for process in sockstat_evidence:
            table += f" {process.DestinationAddr} | {process.DestinationPort} | {process.FD} | {process.Family} | {process.Filter} | {process.NetNS} | {process.Proto} | {process.SockOffset} | {process.SourceAddr} | {process.SourcePort} | {process.State} |  {process.Type} | \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    # END EVIDENCE ITEMS #

    # BEGIN SUSPICIOUS ITEMS #
    html += markdown.markdown("## 🟨 Suspicious items")
    text += "## 🟨 Suspicious items"

    html += markdown.markdown(
        "The following artifacts were marked as **suspicious** and should be considered by the reader for further investigation.")
    text += "The following artifacts were marked as **suspicious** and should be considered by the reader for further investigation. \n"

    if ttycheck_suspicious:
        table = "PhysicalAddress  | Module | Name | Symbol | \n ------------- | ------------- | ------------- | -------------\n"
        for process in ttycheck_suspicious:
            table += f" {process.Address} | {process.Module} | {process.Name} | {process.Symbol} | \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if bash_suspicious:
        table = "PID  | Process | CommmandTime | Command | \n ------------- | ------------- | ------------- | -------------\n"
        for process in bash_suspicious:
            table += f" {process.PID} | {process.Process} | {process.CommandTime} | {process.Command} | \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if elfs_suspicious:
        table = "Start  | End | FilePath | Process | PID | \n ------------- | ------------- | ------------- | ------------- | -------------\n"
        for process in elfs_suspicious:
            table += f" {process.Start} | {process.End} | {process.FilePath} | {process.Process} |  {process.PID} | \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if psaux_suspicious:
        table = "PID  | PPID | COMM | Args | \n ------------- | ------------- | ------------- | -------------\n"
        for process in psaux_suspicious:
            table += f" {process.PID} | {process.PPID} | {process.COMM} | {process.ARGS} | \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if envars_suspicious:
        table = "COMM  | KEY | PPID | VALUE | \n ------------- | ------------- | ------------- | -------------\n"
        for process in envars_suspicious:
            table += f" {process.COMM} | {process.KEY} | {process.PPID} | {process.VALUE} | \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table


    if lsof_suspicious:
        table = "FD  | PID | Path | Process | \n ------------- | ------------- | ------------- | -------------\n"
        for process in lsof_suspicious:
            table += f" {process.FD} | {process.PID} | {process.Path} | {process.Process} | \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if procmaps_suspicious:
        table = "Start  | End | FilePath | Flags |  Inode |  Major |  Minor |  PID |  PgOff |  Process | \n ------------- | ------------- | ------------- | ------------- | -------------| -------------| -------------| -------------| ------------- | -------------\n"
        for process in procmaps_suspicious:
            table += f" {process.Start} | {process.End} | {process.FilePath} | {process.Flags} | {process.Inode} | {process.Major} | {process.PID} | {process.Minor} | {process.PgOff} | {process.Process} | \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if mountinfo_suspicious:
        table = "FIELDS  | FSTYPE | MAJOR_MINOR | MNT_NS_ID |  MOUNTID |  MOUNT_OPTIONS |  MOUNT_POINT |  MOUNT_SRC |  PARENT_ID |  ROOT | SB_OPTIONS | \n ------------- | ------------- | ------------- | ------------- | -------------| -------------| -------------| -------------| ------------- | ------------- | -------------\n"
        for process in mountinfo_suspicious:
            table += f" {process.FIELDS} | {process.FSTYPE} | {process.MAJOR_MINOR} | {process.MNT_NS_ID} | {process.MOUNTID} | {process.MOUNT_OPTIONS} | {process.MOUNT_POINT} | {process.MOUNT_SRC} | {process.PARENT_ID} | {process.ROOT} | SB_OPTIONS | \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table

    if sockstat_suspicious:
        table = "DestAddr  | DestPort | FD | Family |  Filter |  NetNs |  Proto |  SockOffset |  SrcAddr |  SrcPort | State | Type | \n ------------- | ------------- | ------------- | ------------- | -------------| -------------| -------------| -------------| ------------- | ------------- | ------------- | -------------\n"
        for process in sockstat_suspicious:
            table += f" {process.DestinationAddr} | {process.DestinationPort} | {process.FD} | {process.Family} | {process.Filter} | {process.NetNS} | {process.Proto} | {process.SockOffset} | {process.SourceAddr} | {process.SourcePort} | {process.State} |  {process.Type} | \n"
        html += markdown.markdown(table, extensions=['tables'])
        text += table
    # END SUSPICIOUS ITEMS #

    return html, text
