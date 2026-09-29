from celery import shared_task
from evidences.models import Evidence
from yararules.models import YaraRule
from yararulesets.models import YaraRuleSet
from volatility_engine.engine import VolatilityEngine
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from yararules.utils import is_batch_upload_active
from django.conf import settings
import os
import logging

logger = logging.getLogger(__name__)

@shared_task(name="VolWeb.SelectiveEngine")
def start_selective_extraction(evidence_id, selected_plugins=None, pid_filter=None, skip_completed=False, plugin_timeout=None):
    """
    Extract artefacts using only the selected plugins.
    If skip_completed=True, skip plugins that already have successful results.
    If plugin_timeout is set, each individual plugin will be killed after that many seconds.
    """
    instance = Evidence.objects.get(id=evidence_id)
    engine = VolatilityEngine(instance)
    instance.status = 0
    instance.extraction_control = "running"
    instance.save()

    logger.info(f"Starting selective extraction for evidence {evidence_id} — plugins: {len(selected_plugins) if selected_plugins else 'all'}, timeout: {f'{plugin_timeout}s' if plugin_timeout else 'none'}")

    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f"volatility_tasks_{evidence_id}",
        {
            "type": "send_notification",
            "message": {
                "name": "selective_extraction",
                "status": "started",
                "result": None,
            },
        },
    )

    try:
        engine.start_selective_extraction(selected_plugins, pid_filter, skip_completed=skip_completed, plugin_timeout=plugin_timeout)

        if instance.status != -1:
            instance.refresh_from_db()
            instance.status = 100
            instance.save(update_fields=["status"])
    finally:
        instance.refresh_from_db()
        instance.extraction_control = "idle"
        instance.celery_task_id = ""
        instance.save(update_fields=["extraction_control", "celery_task_id"])

    async_to_sync(channel_layer.group_send)(
        f"volatility_tasks_{evidence_id}",
        {
            "type": "send_notification",
            "message": {
                "name": "selective_extraction",
                "status": "finished",
                "result": str(instance.status != -1).lower(),
            },
        },
    )


@shared_task
def start_timeliner(evidence_id):
    """
    This task is dedicated to generate the timeline.
    We seperate this because this could take a very long time depending on the memory dump.
    """
    instance = Evidence.objects.get(id=evidence_id)
    channel_layer = get_channel_layer()
    engine = VolatilityEngine(instance)
    result = engine.start_timeliner()
    if result:
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "timeliner",
                    "status": "finished",
                    "result": "true",
                },
            },
        )
    else:
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "timeliner",
                    "status": "finished",
                    "result": "false",
                },
            },
        )


@shared_task
def dump_process(evidence_id, pid):
    """
    This task is dedicated to performing a pslist dump.
    """
    channel_layer = get_channel_layer()
    instance = Evidence.objects.get(id=evidence_id)
    engine = VolatilityEngine(instance)
    result = engine.dump_process(pid)
    async_to_sync(channel_layer.group_send)(
        f"volatility_tasks_{evidence_id}",
        {
            "type": "send_notification",
            "message": {
                "name": "dump",
                "pid": pid,
                "status": "finished",
                "result": result,
            },
        },
    )


@shared_task
def dump_windows_handles(evidence_id, pid):
    """
    This task is dedicated to compute the handles for a specific process.
    """
    instance = Evidence.objects.get(id=evidence_id)
    channel_layer = get_channel_layer()
    engine = VolatilityEngine(instance)
    engine.compute_handles(pid)
    async_to_sync(channel_layer.group_send)(
        f"volatility_tasks_{evidence_id}",
        {
            "type": "send_notification",
            "message": {
                "name": "handles",
                "pid": pid,
                "status": "finished",
                "msg": "Message",
            },
        },
    )


@shared_task
def dump_file(evidence_id, offset):
    """
    This task is dedicated for trying to dump a file at a specific memory offset.
    """
    instance = Evidence.objects.get(id=evidence_id)
    channel_layer = get_channel_layer()
    engine = VolatilityEngine(instance)
    if instance.os == "windows":
        result = engine.dump_file_windows(offset)
    else:
        result = engine.dump_file_linux(offset)
    async_to_sync(channel_layer.group_send)(
        f"volatility_tasks_{evidence_id}",
        {
            "type": "send_notification",
            "message": {
                "name": "file_dump",
                "status": "finished",
                "result": result,
            },
        },
    )


@shared_task
def dump_maps(evidence_id, pid):
    """
    This task is dedicated to compute the maps for a specific process.
    """
    instance = Evidence.objects.get(id=evidence_id)
    channel_layer = get_channel_layer()
    engine = VolatilityEngine(instance)
    result = engine.dump_process_maps(pid)
    async_to_sync(channel_layer.group_send)(
        f"volatility_tasks_{evidence_id}",
        {
            "type": "send_notification",
            "message": {
                "name": "maps",
                "pid": pid,
                "status": "finished",
                "result": result,
            },
        },
    )

@shared_task
def start_yararule_validation(yara_rule_id):
    """
    This task will validate the YARA rule and optionally trigger ruleset validation.
    
    Modified to respect batch upload context:
    - Individual rule validation always happens
    - Ruleset validation only happens if NOT in batch upload mode
    """
    instance = YaraRule.objects.get(id=yara_rule_id)
    
    logger.info(f"Starting validation for YARA rule: {instance.name} (ID: {yara_rule_id})")
    
    channel_layer = get_channel_layer()
    
    engine = VolatilityEngine(instance)
    
    # Set status to in-progress
    instance.status = 0
    instance.save()
    
    # Perform the actual validation
    engine.start_yararule_validation()
    instance.refresh_from_db()

    # Send individual rule validation notification
    from yararules.serializers import YaraRuleSerializer
    serializer = YaraRuleSerializer(instance)
    
    async_to_sync(channel_layer.group_send)(
        "yararules",
        {
            "type": "send_notification",
            "status": "created",  
            "message": serializer.data 
        }
    )
    logger.info(f"Completed validation for YARA rule: {instance.name}")


@shared_task
def start_ruleset_validation(yara_ruleset_id, skip_rule_validation=False):
    """
    Recompile a YARA ruleset.
    skip_rule_validation: skip per-rule revalidation (use after deletion —
                          remaining rules are already compiled).
    """
    instance = YaraRuleSet.objects.get(id=yara_ruleset_id)

    logger.info(f"Starting validation for YARA ruleset: {instance.name} (ID: {yara_ruleset_id})")

    channel_layer = get_channel_layer()

    engine = VolatilityEngine(instance)

    # Set status to in-progress
    instance.status = 0
    instance.save()

    # Perform the actual validation
    validation_result = engine.start_ruleset_validation(skip_rule_validation=skip_rule_validation)
    
    # Save the result
    instance.status = validation_result
    instance.save()
        
    from yararulesets.serializers import YaraRuleSetSerializer
    serializer = YaraRuleSetSerializer(instance)
    
    async_to_sync(channel_layer.group_send)(
        "yararulesets",
        {
            "type": "send_notification",
            "status": "updated",  # Status al livello principale!
            "message": serializer.data  # Dati serializzati
        }
    )
    logger.info(f"Completed validation for YARA ruleset: {instance.name} with status {instance.status}")


@shared_task
def start_yarascan(evidence_id, rulesets=None, rules=None, scan_scope="vad"):
    """
    Run YARA scan on evidence with selected rulesets and/or individual rules.

    Args:
        evidence_id: ID of the evidence to scan
        rulesets: List of ruleset IDs to use
        rules: List of individual rule IDs to use
        scan_scope: "vad" (per-process memory, default) or "kernel"
                    (kernel layer). Selects which Volatility plugin
                    drives the scan; see VolatilityEngine.run_yara_scan.
    """
    import traceback
    from datetime import datetime
    
    try:
        instance = Evidence.objects.get(id=evidence_id)
        channel_layer = get_channel_layer()
        engine = VolatilityEngine(instance)
        
        logger.info(f"Starting YARA scan for evidence {evidence_id} with rulesets: {rulesets}, rules: {rules}")
        
        # Send start notification
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "yarascan",
                    "status": "started",
                    "result": None,
                },
            },
        )
        
        # run_yara_scan: True=matches, False=no matches, None=could not run; raises on failure.
        scan_result = None
        scan_executed = False

        # If specific rulesets are selected, combine them in a single scan
        if rulesets:
            from yararulesets.models import YaraRuleSet
            selected_rulesets = []

            for ruleset_id in rulesets:
                try:
                    # Try to fetch the ruleset regardless of its status. We will
                    # only include it in the scan if it has compiled rules.
                    ruleset = YaraRuleSet.objects.get(id=ruleset_id)

                    if getattr(ruleset, 'compiled_rules', None):
                        selected_rulesets.append(ruleset)
                        logger.info(f"Added ruleset '{ruleset.name}' to scan")
                    else:
                        logger.warning(f"Ruleset {ruleset_id} found but not compiled yet; skipping")
                except YaraRuleSet.DoesNotExist:
                    logger.warning(f"Ruleset {ruleset_id} not found")

            if not selected_rulesets:
                raise RuntimeError(
                    "None of the selected rulesets are compiled and ready to scan."
                )

            logger.info(f"Running YARA scan with {len(selected_rulesets)} rulesets combined (scope={scan_scope})")
            scan_result = engine.run_yara_scan(yara_rulesets=selected_rulesets, scan_scope=scan_scope)
            scan_executed = True

        # If specific rules are selected (without ruleset)
        elif rules:
            logger.info(f"Running YARA scan with individual rules: {rules} (scope={scan_scope})")
            scan_result = engine.run_yara_scan(yara_rules=rules, scan_scope=scan_scope)
            scan_executed = True

        # If no specific selections, run with all active rules
        else:
            logger.info(f"Running YARA scan with all active rules (scope={scan_scope})")
            scan_result = engine.run_yara_scan(scan_scope=scan_scope)
            scan_executed = True

        # None means nothing was scanned (inactive/uncompiled rules): treat as failure.
        if not scan_executed or scan_result is None:
            raise RuntimeError(
                "YARA scan did not run: no compiled, active rules were available "
                "for the selected rulesets/rules."
            )

        matches_found = bool(scan_result)
        result = matches_found

        # Generate a unique scan ID with timestamp for logging
        scan_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_id = f"scan_{scan_timestamp}"

        logger.info(f"YARA scan completed for evidence {evidence_id}. Matches found: {matches_found}. Scan ID: {scan_id}")

        # result="true" => matches found; "false" => completed with no matches.
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "yarascan",
                    "status": "finished",
                    "result": str(matches_found).lower(),
                    "scan_id": scan_id,
                },
            },
        )
        
    except Evidence.DoesNotExist:
        logger.error(f"Evidence with ID {evidence_id} not found")
        result = False
        
        # Send error notification
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "yarascan",
                    "status": "error",
                    "result": "false",
                    "error": "Evidence not found",
                },
            },
        )
        
    except Exception as e:
        logger.error(f"Error during YARA scan: {str(e)}")
        logger.error(traceback.format_exc())
        result = False
        
        # Send error notification
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "yarascan",
                    "status": "error",
                    "result": "false",
                    "error": str(e),
                },
            },
        )

    return result


@shared_task
def generate_linux_symbols(evidence_id):
    """
    Auto-resolve the Linux kernel ISF for a Linux evidence: detect the banner,
    download a matching ISF from the community remote index, verify it against
    the image, and register it as a Symbol. Gates Linux plugin execution until
    status == "ready". On failure, records guidance for building it manually.
    """
    from volatility_engine.models import LinuxSymbolResolution
    from volatility_engine import isf as isf_mod
    from symbols.models import Symbol

    instance = Evidence.objects.get(id=evidence_id)
    if instance.os != "linux":
        return

    channel_layer = get_channel_layer()
    resolution, _ = LinuxSymbolResolution.objects.get_or_create(evidence=instance)

    def _set(status, **fields):
        resolution.status = status
        for key, value in fields.items():
            setattr(resolution, key, value)
        resolution.save()
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "isf",
                    "status": resolution.status,
                    "banner": resolution.banner,
                    "method": resolution.method,
                    "message": resolution.message,
                    "guidance": resolution.guidance,
                },
            },
        )

    engine = VolatilityEngine(instance)

    # Reset any stale banner/guidance from a previous run so intermediate
    # states don't carry the old "manual build" guidance.
    _set("detecting", banner=None, method=None, guidance=None,
         message="Detecting kernel banner…")
    try:
        banner = engine.detect_linux_banner()
    except Exception as e:
        logger.error(f"Banner detection failed for evidence {evidence_id}: {e}")
        banner = None

    if not banner:
        _set("failed_banner", message="Could not find a Linux kernel banner in the image.")
        return

    _set("resolving", banner=banner, message="Looking up matching ISF…")
    try:
        isf_rel = isf_mod.resolve_isf_remote(banner)
    except Exception as e:
        logger.error(f"Remote ISF resolution failed for evidence {evidence_id}: {e}")
        isf_rel = None

    if not isf_rel:
        _set(
            "failed_isf",
            method="remote",
            guidance=isf_mod.build_manual_guidance(banner),
            message="No matching ISF in the remote index. Build it manually and upload it.",
        )
        return

    _set("verifying", method="remote", message="Verifying ISF against the image…")
    if not engine.verify_linux_symbols():
        # Drop the non-working ISF so it doesn't pollute the symbol path.
        try:
            os.remove(os.path.join(settings.MEDIA_ROOT, isf_rel))
        except OSError:
            pass
        _set(
            "failed_isf",
            method="remote",
            guidance=isf_mod.build_manual_guidance(banner),
            message="An ISF was found but did not resolve against this image. Build it manually.",
        )
        return

    symbol = Symbol.objects.create(
        name=(banner.split("(")[0].strip()[:100] or "Linux ISF"),
        os="Linux",
        description=banner[:500],
        symbols_file=isf_rel,
    )
    _set("ready", method="remote", linked_symbol=symbol, message="Kernel symbols ready.")


@shared_task
def reverify_linux_symbols(evidence_id):
    """
    Re-validate Linux kernel symbols for an evidence and update the extraction
    gate accordingly. Runs after a manual ISF upload (may *open* the gate) or
    after an ISF deletion (may *close* it), so it re-checks regardless of the
    current status.
    """
    from volatility_engine.models import LinuxSymbolResolution
    from volatility_engine import isf as isf_mod

    instance = Evidence.objects.get(id=evidence_id)
    if instance.os != "linux":
        return
    resolution = LinuxSymbolResolution.objects.filter(evidence=instance).first()
    if not resolution:
        return

    channel_layer = get_channel_layer()

    def _set(status, **fields):
        resolution.status = status
        for key, value in fields.items():
            setattr(resolution, key, value)
        resolution.save()
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "isf",
                    "status": resolution.status,
                    "banner": resolution.banner,
                    "method": resolution.method,
                    "message": resolution.message,
                    "guidance": resolution.guidance,
                },
            },
        )

    _set("verifying", message="Re-checking kernel symbols…")
    engine = VolatilityEngine(instance)
    if engine.verify_linux_symbols():
        _set("ready", guidance=None, message="Kernel symbols ready.")
    else:
        guidance = isf_mod.build_manual_guidance(resolution.banner) if resolution.banner else None
        _set("failed_isf", guidance=guidance,
             message="No usable ISF for this evidence. Re-fetch automatically or upload a matching ISF.")