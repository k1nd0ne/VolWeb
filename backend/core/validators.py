import os

from django.conf import settings
from rest_framework import serializers


def is_safe_upload_filename(value: str) -> bool:
    """
    Return True only if ``value`` is a plain filename that cannot escape its
    directory: no path separators (POSIX or Windows), no parent-directory
    references, no null bytes, and equal to its own basename.
    """
    if not value or value in (".", ".."):
        return False
    if "/" in value or "\\" in value or "\x00" in value:
        return False
    return value == os.path.basename(value)


def validate_upload_filename(value: str) -> str:
    """DRF field validator wrapper around :func:`is_safe_upload_filename`."""
    if not is_safe_upload_filename(value):
        raise serializers.ValidationError("Invalid filename.")
    return value


def safe_media_path(subdir: str, filename: str) -> str:
    """
    Resolve ``MEDIA_ROOT/<subdir>/<filename>`` and guarantee the result stays
    inside ``MEDIA_ROOT/<subdir>``. Raises ``ValueError`` on any unsafe filename
    or escape attempt.

    The filename is validated here so callers cannot forget to; this is the
    single safe sink for assembling user-named uploads. ``subdir`` MUST be a
    trusted, hardcoded value (never user-controlled) — the guarantee only covers
    the filename, not the subdir.
    """
    if not is_safe_upload_filename(filename):
        raise ValueError("Invalid upload filename.")
    base_dir = os.path.realpath(os.path.join(settings.MEDIA_ROOT, subdir))
    target = os.path.realpath(os.path.join(base_dir, filename))
    if target == base_dir or os.path.commonpath([base_dir, target]) != base_dir:
        raise ValueError("Resolved upload path escapes the target directory.")
    return target
