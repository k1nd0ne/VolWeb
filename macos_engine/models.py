from django.db import models
from investigations.models import *

TAGS = (
    ('Evidence', 'Evidence'),
    ('Suspicious', 'Suspicious'),
)


class PsTree(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="macos_pstree_investigation"
    )
    graph = models.JSONField(null=True)


class PsList(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="macos_pslist_investigation"
    )
    COMM = models.TextField(null=True)
    #Offset = models.BigIntegerField(null=True) #EMPTY
    PID = models.BigIntegerField(null=True)
    PPID = models.BigIntegerField(null=True)
    #TID = models.BigIntegerField(null=True) #EMPTY

class Bash(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="macos_bash_investigation"
    )
    PID = models.BigIntegerField(null=True)
    Process = models.TextField(null=True)
    CommandTime = models.TextField(null=True)
    Command = models.CharField(max_length=500, null=True)
    Tag = models.CharField(null=True, max_length=11, choices=TAGS) #EMPTY
    
class Check_syscall(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="macos_check_syscall_investigation"
    )
    TableAddress = models.TextField(null=True)
    TableName = models.TextField(null=True)
    Index = models.BigIntegerField(null=True)
    HandlerAddress = models.TextField(null=True)
    HandlerModule = models.TextField(null=True)
    HandlerSymbol = models.TextField(null=True)
    
class Check_sysctl(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="macos_check_sysctl_investigation"
    )
    Name = models.TextField(null=True)
    Number = models.BigIntegerField(null=True)
    Perms = models.TextField(null=True)
    HandlerAddress = models.TextField(null=True)
    Value = models.TextField(null=True)
    HandlerModule = models.TextField(null=True)
    HandlerSymbol = models.TextField(null=True)

class Check_trap_table(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="macos_check_trap_table_investigation"
    )
    TableAddress = models.TextField(null=True)
    TableName = models.TextField(null=True)
    Index = models.BigIntegerField(null=True)
    HandlerAddress = models.TextField(null=True)
    HandlerModule = models.TextField(null=True)
    HandlerSymbol = models.TextField(null=True)
    
class Ifconfig(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="macos_ifconfig_investigation"
    )
    Interface = models.TextField(null=True)
    IPAddress = models.TextField(null=True)
    MacAddress = models.TextField(null=True)
    Promiscuous = models.TextField(null=True)
    
class List_Files(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="macos_list_files_investigation"
    )
    Address = models.TextField(null=True)
    FilePath = models.TextField(null=True)

class Lsof(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="macos_lsof_investigation"
    )
    PID = models.BigIntegerField(null=True)
    FileDescriptor = models.TextField(null=True)
    FilePath = models.TextField(null=True)

class Lsmod(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="macos_lsmod_investigation"
    )
    Offset = models.TextField(null=True)
    Name = models.TextField(null=True)
    Size = models.BigIntegerField(null=True)

class Malfind(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="macos_malfind_investigation"
    )

    PID = models.BigIntegerField(null=True)
    Process = models.TextField(null=True)
    Start = models.TextField(null=True)
    End = models.TextField(null=True)
    Protection = models.TextField(null=True)
    Hexdump = models.TextField(null=True)
    Disasm = models.TextField(null=True)

class Mount(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="macos_mount_investigation"
    )

    Device = models.TextField(null=True)
    MountPoint = models.TextField(null=True)
    Type = models.TextField(null=True)
    
class Netstat(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="macos_netstat_investigation"
    )

    Offset = models.TextField(null=True)
    Proto = models.TextField(null=True)
    LocalIP = models.TextField(null=True)
    LocalPort = models.BigIntegerField(null=True)
    RemoteIP = models.TextField(null=True)
    RemotePort = models.BigIntegerField(null=True)
    State = models.TextField(null=True)
    Process = models.TextField(null=True)

class Psaux(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="macos_psaux_investigation"
    )

    PID = models.BigIntegerField(null=True)
    Process = models.TextField(null=True)
    Argc = models.BigIntegerField(null=True)
    Arguments = models.BigIntegerField(null=True)
    
class VFSevents(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="macos_vfsevents_investigation"
    )
    
    Name = models.TextField(null=True)
    PID = models.BigIntegerField(null=True)
    Events = models.TextField(null=True)

class Socket_filters(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="macos_socket_filters_investigation"
    )
    
    Filter = models.TextField(null=True)
    Name = models.TextField(null=True)
    Member = models.TextField(null=True)
    Socket = models.TextField(null=True)
    Handler = models.TextField(null=True)
    Module = models.TextField(null=True)
    Symbol = models.TextField(null=True)

class Maps(models.Model):
    investigation = models.ForeignKey(
        UploadInvestigation,
        on_delete=models.CASCADE,
        related_name="macos_proc_maps_investigation"
    )
    
    PID = models.BigIntegerField(null=True)
    Process = models.TextField(null=True)
    Start = models.TextField(null=True)
    End = models.TextField(null=True)
    Protection = models.TextField(null=True)
    MapName = models.TextField(null=True)