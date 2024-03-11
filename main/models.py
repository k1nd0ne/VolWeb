from django.db import models
from django.contrib.auth.models import User
from evidences.models import Evidence

TYPES = (
    ("artifact-sha1", "Artifact - SHA-1"),
    ("artifact-sha256", "Artifact - SHA-256"),
    ("artifact-md5", "Artifact - MD5"),
    ("artifact-url", "Artifact - URL"),
    ("autonomous-system", "Autonomous System"),
    ("directory", "Directory"),
    ("domain-name", "Domain Name"),
    ("email-addr", "Email Address"),
    ("file-path", "File Path"),
    ("file-sha256", "File SHA-256"),
    ("file-sha1", "File SHA-1"),
    ("file-md5", "File MD5"),
    ("ipv4-addr", "IPv4 Address"),
    ("ipv6-addr", "IPv6 Address"),
    ("mac-addr", "MAC Address"),
    ("mutex", "Mutex"),
    ("network-traffic", "Network Traffic"),
    ("process-name", "Process - Name"),
    ("process-pid", "Process - PID"),
    ("process-created", "Process - Created date"),
    ("process-cwd", "Process - CWD"),
    ("process-cmdline", "Process - Command Line"),
    ("software", "Software"),
    ("url", "URL"),
    ("user-account", "User Account"),
    ("windows-registry-key", "Windows Registry Key"),
    ("x509-certificate", "X.509 Certificate"),
)


class Indicator(models.Model):
    id = models.AutoField(primary_key=True)
    evidence = models.ForeignKey(
        Evidence, on_delete=models.CASCADE
    )
    name = models.TextField()
    type = models.CharField(max_length=100, choices=TYPES)
    description = models.TextField()
    value = models.TextField()
