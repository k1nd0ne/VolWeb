# backend/yararules/utils.py
"""
Utilities for YARA rule operations, including batch upload optimization
"""
from contextlib import contextmanager
from threading import local
import logging
import os
import hashlib
import logging
from django.conf import settings

logger = logging.getLogger(__name__)

# Thread-local storage for batch operation state
_local = local()


def compute_content_hash(rule_content):
    """SHA-256 of the rule content, normalized for line endings and whitespace."""
    if not rule_content:
        rule_content = ""
    text = rule_content.replace("\r\n", "\n").replace("\r", "\n")
    normalized = "\n".join(line.rstrip() for line in text.split("\n")).strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def backfill_content_hashes():
    """Populate content_hash for legacy rows where it is still NULL (idempotent)."""
    # local import: models imports this module
    from yararules.models import YaraRule

    missing = YaraRule.objects.filter(content_hash__isnull=True).only("id", "rule_content")
    for rule in missing.iterator():
        YaraRule.objects.filter(id=rule.id).update(
            content_hash=compute_content_hash(rule.rule_content)
        )


def get_existing_content_hashes():
    """Return the set of content hashes of all existing rules (backfilling legacy rows)."""
    # local import: models imports this module
    from yararules.models import YaraRule

    backfill_content_hashes()

    return set(
        YaraRule.objects.exclude(content_hash__isnull=True)
        .values_list("content_hash", flat=True)
    )

def create_yara_rule_file(rule):
    """
    Create a physical .yar file for a YARA rule.
    
    Args:
        rule: YaraRule instance
        
    Returns:
        str: Path to the created file or None if creation failed
    """
    try:
        # Define base directory for YARA rules
        yara_rules_dir = os.path.join(settings.MEDIA_ROOT, 'yara_rules')
        
        # Create directory structure based on ruleset if linked
        if rule.linked_yararuleset:
            ruleset_dir = os.path.join(yara_rules_dir, f'ruleset_{rule.linked_yararuleset.id}')
        else:
            ruleset_dir = os.path.join(yara_rules_dir, 'standalone')
        
        # Ensure directory exists
        os.makedirs(ruleset_dir, exist_ok=True)
        
        # Generate filename
        filename = f"{rule.name}.yar"
        filepath = os.path.join(ruleset_dir, filename)
        
        # Handle duplicate filenames
        counter = 1
        while os.path.exists(filepath):
            filename = f"{rule.name}_{counter}.yar"
            filepath = os.path.join(ruleset_dir, filename)
            counter += 1
        
        # Write rule content to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(rule.rule_content)
        
        logger.info(f"Created YARA rule file: {filepath}")
        
        # Store relative path in the rule object
        relative_path = os.path.relpath(filepath, settings.MEDIA_ROOT)
        return relative_path
        
    except Exception as e:
        logger.error(f"Failed to create YARA rule file for {rule.name}: {e}")
        return None


def update_yara_rule_file(rule, old_content=None):
    """
    Update the physical file when a YARA rule is modified.
    
    Args:
        rule: YaraRule instance
        old_content: Previous content (optional, for rollback)
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        if not rule.file_path:
            # No existing file, create new one
            file_path = create_yara_rule_file(rule)
            if file_path:
                rule.file_path = file_path
                rule.save(update_fields=['file_path'])
            return bool(file_path)
        
        # Update existing file
        full_path = os.path.join(settings.MEDIA_ROOT, rule.file_path)
        
        # Backup old content if provided
        if old_content and os.path.exists(full_path):
            backup_path = f"{full_path}.backup"
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.write(old_content)
        
        # Write new content
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(rule.rule_content)
        
        logger.info(f"Updated YARA rule file: {full_path}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to update YARA rule file for {rule.name}: {e}")
        
        # Attempt rollback if we have old content
        if old_content and rule.file_path:
            try:
                full_path = os.path.join(settings.MEDIA_ROOT, rule.file_path)
                with open(full_path, 'w', encoding='utf-8') as f:
                    f.write(old_content)
                logger.info("Rolled back file content after update failure")
            except:
                pass
        
        return False

@contextmanager
def batch_upload_context():
    """
    Context manager to disable ruleset validation during batch upload operations.
    
    Usage:
        with batch_upload_context():
            # Create multiple rules without triggering ruleset validation
            rule1 = YaraRule.objects.create(...)
            rule2 = YaraRule.objects.create(...)
            # ...
        # Ruleset validation will be triggered manually after this block
    """
    logger.info("Starting batch upload context - disabling automatic ruleset validation")
    _local.batch_upload_active = True
    try:
        yield
    finally:
        _local.batch_upload_active = False
        logger.info("Ending batch upload context - re-enabling automatic ruleset validation")


def is_batch_upload_active():
    """
    Check if we are currently in a batch upload operation.
    
    Returns:
        bool: True if batch upload is active, False otherwise
    """
    return getattr(_local, 'batch_upload_active', False)


def trigger_delayed_ruleset_validation(ruleset_id, delay=5, skip_rule_validation=False):
    """
    Trigger ruleset validation with a delay to ensure all rules are processed.
    skip_rule_validation: skip per-rule revalidation (pass True after deletion).
    """
    if not ruleset_id:
        return

    logger.info(f"Scheduling delayed ruleset validation for ruleset {ruleset_id} with {delay}s delay")

    from volatility_engine.tasks import start_ruleset_validation

    start_ruleset_validation.apply_async(
        args=[ruleset_id],
        kwargs={"skip_rule_validation": skip_rule_validation},
        countdown=delay
    )


class BatchUploadManager:
    """
    Manager class for handling batch upload operations with proper cleanup.
    
    Usage:
        manager = BatchUploadManager()
        with manager.batch_context():
            # Batch operations
            pass
        # Automatic cleanup and validation
    """
    
    def __init__(self, ruleset_id=None):
        self.ruleset_id = ruleset_id
        self.rules_created = []
        
    @contextmanager
    def batch_context(self):
        """Context manager with automatic ruleset validation at the end"""
        with batch_upload_context():
            yield self
        
        # Trigger validation if we have a ruleset
        if self.ruleset_id:
            trigger_delayed_ruleset_validation(self.ruleset_id)
    
    def add_created_rule(self, rule):
        """Track a rule that was created during the batch operation"""
        self.rules_created.append(rule)
        
    def get_created_count(self):
        """Get the number of rules created during this batch"""
        return len(self.rules_created)