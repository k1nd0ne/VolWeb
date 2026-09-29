# yararule/models.py
from django.db import models
from yararulesets.models import YaraRuleSet
from yararules.utils import compute_content_hash

RULE_SOURCES = (
    ("custom", "manual"),
    ("github", "github"),
)


class YaraRule(models.Model):
    """
    YaraRule Model
    Holds the important metadata about the YARA rule.
    """

    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=250)
    etag = models.CharField(max_length=256, unique=True)
    rule_content = models.TextField()
    # SHA-256 of rule_content, for content-based de-duplication.
    content_hash = models.CharField(max_length=64, db_index=True, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    linked_yararuleset = models.ForeignKey(YaraRuleSet, on_delete=models.CASCADE, null=True)
    status = models.IntegerField(default=0)
    url = models.TextField(null=True)
    source = models.CharField(max_length=10, choices=RULE_SOURCES, null=True)
    is_active = models.BooleanField(default=True)

    def save(self, *args, **kwargs):
        # Keep content_hash in sync; add it to update_fields only when content changes.
        self.content_hash = compute_content_hash(self.rule_content)
        update_fields = kwargs.get("update_fields")
        if update_fields is not None:
            update_fields = set(update_fields)
            if "rule_content" in update_fields:
                update_fields.add("content_hash")
            kwargs["update_fields"] = update_fields
        super().save(*args, **kwargs)

    def __str__(self):
        return str(self.name)