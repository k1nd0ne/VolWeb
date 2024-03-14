from main.models import Indicator
from stix2 import Indicator as StixIndicator, Bundle


def create_indicator(indicator):
    pattern_mapping = {
        "artifact-sha1": "[artifact:hashes.'SHA-1' = '{}']",
        "artifact-sha256": "[artifact:hashes.'SHA-256' = '{}']",
        "artifact-md5": "[artifact:hashes.'MD5' = '{}']",
        "artifact-url": "[artifact:url = '{}']",
        "autonomous-system": "[autonomous-system:number = {}]",
        "directory": "[directory:path = '{}']",
        "domain-name": "[domain-name:value = '{}']",
        "email-addr": "[email-addr:value = '{}']",
        "file-sha256": "[file:hashes.'SHA-256' = '{}']",
        "file-sha1": "[file:hashes.'SHA-1' = '{}']",
        "file-md5": "[file:hashes.'MD5' = '{}']",
        "file-path": "[file:path = '{}']",
        "ipv4-addr": "[ipv4-addr:value = '{}']",
        "ipv6-addr": "[ipv6-addr:value = '{}']",
        "mac-addr": "[mac-addr:value = '{}']",
        "mutex": "[mutex:name = '{}']",
        "network-traffic": "[network-traffic:src_port = {}]",
        "process-cmdline": "[process:command_line = '{}']",
        "process-name": "[process:name = '{}']",
        "process-cwd": "[process:cwd = '{}']",
        "software": "[software:name = '{}']",
        "url": "[url:value = '{}']",
        "user-account": "[user-account:user_id = '{}']",
        "windows-registry-key": "[windows-registry-key:key = '{}']",
        "x509-certificate": "[x509-certificate:hashes.'SHA-1' = '{}']",
    }

    pattern_template = pattern_mapping.get(indicator.type)
    if pattern_template:
        value = (
            str(indicator.value).replace("\\", "\\\\")
            if "path" in indicator.type
            or "cmdline" in indicator.type
            or "registry-key" in indicator.type
            else indicator.value
        )
        pattern = pattern_template.format(value)
        stix_indicator = StixIndicator(
            pattern_type="stix",
            pattern=pattern,
            valid_from=indicator.evidence.dump_linked_case.case_last_update,
            description=indicator.description,
        )
        return stix_indicator
    return None


def export_bundle(indicators):
    stix_indicators = []
    for indicator in indicators:
        result = create_indicator(indicator=indicator)
        if result:
            stix_indicators.append(result)

    bundle = Bundle(objects=stix_indicators)
    bundle_json = bundle.serialize(pretty=True)
    return bundle_json
