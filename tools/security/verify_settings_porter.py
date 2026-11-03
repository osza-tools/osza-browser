#!/usr/bin/env python3
# ============================================================
# Osza - security settings porter verifier
#
# Standalone validation of osza-security-settings documents (the
# files SecuritySettingsPorter writes and reads), without a Qt
# build. It mirrors the validation rules of
# src/lib/security/securitysettingsporter.cpp:
#
#   - the format identifier and version are cross-checked against
#     the constants in the C++ source, so this script and the
#     browser cannot drift apart silently
#   - the header (format, version) is mandatory; a newer version
#     than the browser knows is rejected
#   - the checksum is verified the same way the importer verifies
#     it: SHA-256 over the compact serialization of the tools
#     object (sorted keys, no whitespace, integral floats as
#     integers). A mismatch is an error - the file changed after
#     the export; a missing checksum is a warning - the file was
#     hand-edited or written by an older version and still imports
#   - "tools" is optional but must be an object
#   - every known tool section is validated on its own: a
#     malformed section is reported, the rest still validates
#   - unknown tools are reported as warnings, not errors
#   - a field whose name mentions a "seed" is flagged: the real
#     exporter never writes the fingerprint master seed, so such
#     a file did not come from Osza and should not be imported
#   - the built-in recommended-baseline presets (essentials,
#     recommended-baseline, maximum-protection) are cross-checked
#     against securitypresets.cpp, so the offline picture of what
#     the browser recommends cannot drift either
#
# Usage:
#   python3 tools/security/verify_settings_porter.py
#     (no arguments: run the built-in self-test)
#   python3 tools/security/verify_settings_porter.py FILE [FILE...]
#     (validate files; exit code 0 when every file is valid)
#   python3 tools/security/verify_settings_porter.py --update-checksum FILE
#     (after an intentional hand edit: validate the file, then
#      write a fresh checksum into it so the import needs no
#      "import anyway" confirmation)
#
# Copyright (C) 2026 Osza Tools contributors
# GPL-3.0-or-later
# ============================================================

import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PORTER_SOURCE = os.path.join(HERE, os.pardir, os.pardir,
                             "src", "lib", "security", "securitysettingsporter.cpp")
PRESETS_SOURCE = os.path.join(HERE, os.pardir, os.pardir,
                              "src", "lib", "security", "securitypresets.cpp")

# The schema of one tool section: which fields exist and how they
# are checked. Keep in sync with SecuritySettingsPorter::applyDocument.
BOOL_TOOLS = ("adblock", "trackingParameters", "globalPrivacyControl")
EXCLUSION_TOOLS = ("httpsOnly", "fingerprintProtection")

THREAT_SOURCE_SCHEMES = ("http", "https", "file")
DNS_MODE_MIN = 0
DNS_MODE_MAX = 2


def constants_from_source():
    """Read format identifier, version and checksum algorithm from
    the C++ sources."""
    fmt = "osza-security-settings"
    version = 1
    algorithm = "sha256"
    try:
        with open(PORTER_SOURCE, encoding="utf-8") as f:
            source = f.read()
        m = re.search(r'SecuritySettingsPorter::formatIdentifier\(\)\s*\{\s*'
                      r'return QSL\("([^"]+)"\);', source)
        if m:
            fmt = m.group(1)
        m = re.search(r'SecuritySettingsPorter::formatVersion\(\)\s*\{\s*'
                      r'return (\d+);', source)
        if m:
            version = int(m.group(1))
        m = re.search(r'SecuritySettingsPorter::checksumAlgorithm\(\)\s*\{\s*'
                      r'return QSL\("([^"]+)"\);', source)
        if m:
            algorithm = m.group(1)
    except OSError:
        pass
    return fmt, version, algorithm


def preset_ids_from_source():
    """Read the built-in preset ids, in order, from securitypresets.cpp."""
    try:
        with open(PRESETS_SOURCE, encoding="utf-8") as f:
            source = f.read()
        return re.findall(r'preset\.id = QSL\("([^"]+)"\)', source)
    except OSError:
        return []


FORMAT, VERSION, ALGORITHM = constants_from_source()

# What the preset picker offers, from lightest to strictest.
EXPECTED_PRESET_IDS = ["essentials", "recommended-baseline", "maximum-protection"]


class Report:
    def __init__(self, path):
        self.path = path
        self.errors = []
        self.warnings = []

    def error(self, message):
        self.errors.append(message)

    def warn(self, message):
        self.warnings.append(message)

    @property
    def ok(self):
        return not self.errors

    def summary(self):
        lines = []
        state = "valid" if self.ok else "INVALID"
        lines.append("%s: %s" % (self.path, state))
        for message in self.errors:
            lines.append("  error:   %s" % message)
        for message in self.warnings:
            lines.append("  warning: %s" % message)
        return "\n".join(lines)


def is_url_with_scheme(value, schemes):
    # Mirrors QUrl::fromUserInput + scheme check: something with a
    # scheme prefix before any "/", "?" or "#".
    match = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*):", value)
    return bool(match) and match.group(1).lower() in schemes


def canonicalize(value):
    """Normalize a parsed JSON value the way Qt's JSON writer prints
    it: integral numbers (1.0) serialize as integers (1), so the
    checksum follows the parsed content and not the raw bytes."""
    if isinstance(value, bool):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, list):
        return [canonicalize(entry) for entry in value]
    if isinstance(value, dict):
        return {key: canonicalize(entry) for key, entry in value.items()}
    return value


def tools_checksum(tools):
    """SHA-256 of the canonical compact serialization of the tools
    object - the exact bytes SecuritySettingsPorter re-derives after
    parsing a file (sorted keys, no whitespace, UTF-8)."""
    canonical = json.dumps(canonicalize(tools), sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def document_checksum(document):
    """The checksum object the exporter would write for this document."""
    return {"algorithm": ALGORITHM, "tools": tools_checksum(document.get("tools", {}))}


def validate_document(document, report):
    if not isinstance(document, dict):
        report.error("the document is not a JSON object")
        return

    if document.get("format") != FORMAT:
        report.error("format is %r, expected %r" % (document.get("format"), FORMAT))
        return

    # Mirrors QJsonValue::toInt(): an integral double (1.0) reads
    # back as the integer 1 in the importer, so the same leniency
    # applies here.
    version = canonicalize(document.get("version"))
    if not isinstance(version, int) or isinstance(version, bool):
        report.error("version is missing or not a number")
        return
    if version > VERSION:
        report.error("version %d is newer than this browser knows (%d)" % (version, VERSION))
        return
    if version < VERSION:
        report.warn("version %d is older than the current format (%d)" % (version, VERSION))

    # The checksum is verified exactly like the importer verifies it.
    # A missing checksum is only a warning: older exports and checked
    # hand edits carry none and still import.
    checksum = document.get("checksum")
    if checksum is None:
        report.warn("no checksum; the file was hand-edited or written "
                    "by an older version, and imports without the "
                    "mismatch warning")
    elif not isinstance(checksum, dict):
        report.error("checksum is not an object")
    elif checksum.get("algorithm") != ALGORITHM:
        report.error("checksum algorithm is %r, expected %r"
                     % (checksum.get("algorithm"), ALGORITHM))
    elif not isinstance(checksum.get("tools"), str) \
            or len(checksum["tools"]) != 64 \
            or not re.fullmatch(r"[0-9a-fA-F]+", checksum["tools"]):
        report.error("checksum.tools is not a 64-character hex digest")
    elif tools_checksum(document.get("tools", {})) != checksum["tools"].lower():
        report.error("checksum does not match the tools section; the file "
                    "was changed or corrupted after it was exported")

    tools = document.get("tools")
    if tools is None:
        return
    if not isinstance(tools, dict):
        report.error("tools is not an object")
        return

    known = set(BOOL_TOOLS) | set(EXCLUSION_TOOLS) | {"secureDns", "threatBlock"}

    for name, section in tools.items():
        if name not in known:
            report.warn("unknown tool %r is ignored on import" % name)
            continue
        if not isinstance(section, dict):
            report.error("tools.%s is not an object" % name)
            continue

        if "seed" in name.lower():
            report.warn("tool %r mentions a seed; Osza never exports one" % name)

        if name in BOOL_TOOLS or name in EXCLUSION_TOOLS:
            enabled = section.get("enabled")
            if not isinstance(enabled, bool):
                report.error("tools.%s.enabled is missing or not a boolean" % name)

        if name in EXCLUSION_TOOLS:
            if "exclusions" in section:
                exclusions = section["exclusions"]
                if not isinstance(exclusions, list):
                    report.error("tools.%s.exclusions is not an array" % name)
                else:
                    for entry in exclusions:
                        if not isinstance(entry, str):
                            report.error("tools.%s.exclusions contains a non-string" % name)
                            break
                        if not entry.strip():
                            report.warn("tools.%s.exclusions contains an empty entry" % name)

        if name == "secureDns":
            # Mirrors QJsonValue::toInt(): 1.0 reads back as 1.
            mode = canonicalize(section.get("mode"))
            if not isinstance(mode, int) or isinstance(mode, bool) \
                    or not (DNS_MODE_MIN <= mode <= DNS_MODE_MAX):
                report.error("tools.secureDns.mode is missing or outside %d..%d"
                             % (DNS_MODE_MIN, DNS_MODE_MAX))
                mode = None
            servers = section.get("servers")
            if not isinstance(servers, list):
                report.error("tools.secureDns.servers is missing or not an array")
            else:
                for entry in servers:
                    if not isinstance(entry, str) or not entry.strip():
                        report.error("tools.secureDns.servers contains a non-string or empty entry")
                        break
                    if not is_url_with_scheme(entry.strip(), ("https",)):
                        report.error("tools.secureDns.servers entry %r is not an https URL template"
                                     % entry)
                        break
                if mode is not None and mode != DNS_MODE_MIN and not [s for s in servers
                                                                      if isinstance(s, str) and s.strip()]:
                    report.error("a secure DNS mode needs at least one server")

        if name == "threatBlock":
            enabled = section.get("enabled")
            if not isinstance(enabled, bool):
                report.error("tools.threatBlock.enabled is missing or not a boolean")
            if "sourceUrl" in section:
                source = section["sourceUrl"]
                if not isinstance(source, str) or not source.strip() \
                        or not is_url_with_scheme(source.strip(), THREAT_SOURCE_SCHEMES):
                    report.error("tools.threatBlock.sourceUrl is not an http(s) or file URL")

    # Privacy: the real exporter never writes anything seed-like.
    for key in document:
        if "seed" in key.lower():
            report.warn("top-level key %r mentions a seed; Osza never exports one" % key)


def validate_file(path):
    report = Report(path)

    try:
        with open(path, encoding="utf-8") as f:
            document = json.load(f)
    except OSError as e:
        report.error("cannot read the file: %s" % e)
        return report
    except json.JSONDecodeError as e:
        report.error("the file is not valid JSON: %s" % e)
        return report

    validate_document(document, report)
    return report


def self_test():
    """Checks the validator against fixtures that mirror the C++
    autotests (SecurityToolsTest::settingsPorter*Test)."""
    failures = []
    checks = [0]

    def check(condition, what):
        checks[0] += 1
        if not condition:
            failures.append(what)

    def validate(data):
        report = Report("<self-test>")
        validate_document(data, report)
        return report

    good_tools = {
        "adblock": {"enabled": True},
        "httpsOnly": {"enabled": True, "exclusions": ["legacy.example", "*.wild.example"]},
        "trackingParameters": {"enabled": False},
        "secureDns": {"mode": 1, "servers": ["https://dns.example/dns-query{?dns}"]},
        "threatBlock": {"enabled": True,
                        "sourceUrl": "https://porter.example/hosts"},
        "fingerprintProtection": {"enabled": True, "exclusions": []},
        "globalPrivacyControl": {"enabled": True},
    }
    good = {"format": FORMAT, "version": VERSION, "exportedAt": "2026-01-31T12:00:00Z",
            "checksum": document_checksum({"tools": good_tools}),
            "tools": good_tools}

    r = validate(good)
    check(r.ok, "a complete valid document must pass: %s" % r.summary())
    check(not r.warnings, "a complete valid document must not warn: %s" % r.summary())

    r = validate({"format": FORMAT, "version": VERSION})
    check(r.ok, "a document without tools must pass")

    r = validate({"format": FORMAT, "version": VERSION, "tools": {}})
    check(r.ok, "empty tools must pass")

    r = validate({"format": "other", "version": VERSION})
    check(not r.ok, "a wrong format identifier must fail")

    r = validate({"format": FORMAT, "version": VERSION + 1, "tools": {}})
    check(not r.ok, "a newer version must fail")

    r = validate({"format": FORMAT, "tools": {}})
    check(not r.ok, "a missing version must fail")

    r = validate({"format": FORMAT, "version": VERSION, "tools": 42})
    check(not r.ok, "a non-object tools section must fail")

    r = validate({"format": FORMAT, "version": VERSION,
                  "tools": {"adblock": {"enabled": "yes"}}})
    check(not r.ok, "a non-boolean enabled must fail")

    r = validate({"format": FORMAT, "version": VERSION,
                  "tools": {"httpsOnly": {"enabled": True, "exclusions": "no"}}})
    check(not r.ok, "a non-array exclusions field must fail")

    r = validate({"format": FORMAT, "version": VERSION,
                  "tools": {"secureDns": {"mode": 1, "servers": []}}})
    check(not r.ok, "a secure mode without servers must fail")

    r = validate({"format": FORMAT, "version": VERSION,
                  "tools": {"secureDns": {"mode": 9,
                                          "servers": ["https://dns.example/dns-query{?dns}"]}}})
    check(not r.ok, "a mode outside the enum must fail")

    r = validate({"format": FORMAT, "version": VERSION,
                  "tools": {"secureDns": {"mode": 1,
                                          "servers": ["http://dns.example/dns-query{?dns}"]}}})
    check(not r.ok, "a plain http DNS template must fail")

    r = validate({"format": FORMAT, "version": VERSION,
                  "tools": {"threatBlock": {"enabled": True, "sourceUrl": "ftp://x/y"}}})
    check(not r.ok, "an unsupported blocklist scheme must fail")

    r = validate({"format": FORMAT, "version": VERSION,
                  "tools": {"timeMachine": {"enabled": False}}})
    check(r.ok, "an unknown tool must not fail")
    check(any("unknown tool" in w for w in r.warnings),
          "an unknown tool must produce a warning")

    r = validate({"format": FORMAT, "version": VERSION,
                  "tools": {"adblock": {"enabled": True}, "seed": 1234}})
    check(r.ok, "a seed field must not fail validation on its own")
    check(any("seed" in w for w in r.warnings),
          "a seed field must be flagged as suspicious")

    r = validate({"format": FORMAT, "version": VERSION,
                  "tools": {"httpsOnly": {"enabled": True, "exclusions": ["  ", ""]}}})
    check(r.ok, "empty exclusion entries are only a warning")
    check(any("empty entry" in w for w in r.warnings),
          "empty exclusion entries must warn")

    # --- checksum rules, mirroring settingsPorterChecksumTest ---

    # A missing checksum is only a warning: older exports and checked
    # hand edits carry none.
    r = validate({"format": FORMAT, "version": VERSION, "tools": good_tools})
    check(r.ok, "a document without a checksum must pass")
    check(any("no checksum" in w for w in r.warnings),
          "a missing checksum must warn")

    # A tampered tools section with the original checksum is refused.
    tampered = dict(good)
    tampered["tools"] = dict(good_tools)
    tampered["tools"]["adblock"] = {"enabled": False}
    r = validate(tampered)
    check(not r.ok, "a checksum mismatch must fail")
    check(any("checksum does not match" in e for e in r.errors),
          "a checksum mismatch must say so")

    # Reformatting is not tampering: the checksum follows the parsed
    # content, so 1.0 for 1 keeps it valid.
    reformatted = json.loads(json.dumps(good))
    reformatted["tools"]["secureDns"]["mode"] = 1.0
    r = validate(reformatted)
    check(r.ok, "an integral float written for an integer must keep "
                "the checksum valid: %s" % r.summary())

    # A malformed checksum field is refused: not an object, an unknown
    # algorithm, a non-string digest, a wrong-length digest.
    r = validate({"format": FORMAT, "version": VERSION, "tools": good_tools,
                  "checksum": "sha256"})
    check(not r.ok, "a non-object checksum must fail")

    bad_algo = dict(good)
    bad_algo["checksum"] = {"algorithm": "md5",
                            "tools": document_checksum({"tools": good_tools})["tools"]}
    r = validate(bad_algo)
    check(not r.ok, "an unknown checksum algorithm must fail")

    r = validate({"format": FORMAT, "version": VERSION, "tools": good_tools,
                  "checksum": {"algorithm": ALGORITHM, "tools": 12345}})
    check(not r.ok, "a non-string checksum digest must fail")

    r = validate({"format": FORMAT, "version": VERSION, "tools": good_tools,
                  "checksum": {"algorithm": ALGORITHM, "tools": "tooshort"}})
    check(not r.ok, "a wrong-length checksum digest must fail")

    # The updater writes the checksum the exporter would have written.
    hand_edited = {"format": FORMAT, "version": VERSION, "tools": good_tools}
    hand_edited["checksum"] = document_checksum(hand_edited)
    r = validate(hand_edited)
    check(r.ok, "a document updated by --update-checksum must pass")
    check(not [w for w in r.warnings if "checksum" in w],
          "an updated document must not warn about the checksum")

    # The source cross-check really reads the C++ constants.
    source = open(PORTER_SOURCE, encoding="utf-8").read()
    check('QSL("%s")' % FORMAT in source,
          "the format identifier must match the C++ source")
    check("return %d;" % VERSION in source,
          "the format version must match the C++ source")
    check('QSL("%s")' % ALGORITHM in source,
          "the checksum algorithm must match the C++ source")
    check("QJsonDocument::Compact" in source and "Sha256" in source,
          "the porter must hash the compact serialization with SHA-256")

    # The preset cross-check: the same three baselines, in the same
    # order, as the C++ preset picker offers them.
    check(preset_ids_from_source() == EXPECTED_PRESET_IDS,
          "the built-in preset ids must match securitypresets.cpp: %r"
          % preset_ids_from_source())

    if failures:
        print("self-test FAILED:")
        for what in failures:
            print("  - %s" % what)
        return False

    print("self-test passed: %d checks, format %r version %d checksum %r"
          % (checks[0], FORMAT, VERSION, ALGORITHM))
    return True


def update_checksum(path):
    """After an intentional hand edit: validate the document, then
    write the checksum the exporter would have written, so the
    import needs no 'import anyway' confirmation.

    The stale checksum is dropped before validating: after a hand
    edit it mismatches by definition, and it is exactly what this
    mode replaces. Everything else must still validate."""
    try:
        with open(path, encoding="utf-8") as f:
            document = json.load(f)
    except OSError as e:
        print("%s: cannot read the file: %s" % (path, e))
        return False
    except json.JSONDecodeError as e:
        print("%s: the file is not valid JSON: %s" % (path, e))
        return False

    document.pop("checksum", None)

    report = Report(path)
    validate_document(document, report)
    if not report.ok:
        print(report.summary())
        print("The checksum was NOT updated: fix the errors first.")
        return False

    document["checksum"] = document_checksum(document)

    # Written the way the browser writes exports: sorted keys,
    # indented, UTF-8.
    with open(path, "w", encoding="utf-8") as f:
        json.dump(document, f, indent=4, sort_keys=True, ensure_ascii=False)
        f.write("\n")

    final_report = validate_file(path)
    print(final_report.summary())
    return final_report.ok


def main():
    args = sys.argv[1:]
    update_mode = False

    if "--update-checksum" in args:
        args.remove("--update-checksum")
        update_mode = True
        if not args:
            print("usage: verify_settings_porter.py --update-checksum FILE [FILE...]")
            return 1

    if not args:
        return 0 if self_test() else 1

    if update_mode:
        all_ok = True
        for path in args:
            all_ok = update_checksum(path) and all_ok
        return 0 if all_ok else 1

    all_ok = True
    for path in args:
        report = validate_file(path)
        print(report.summary())
        all_ok = all_ok and report.ok

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
