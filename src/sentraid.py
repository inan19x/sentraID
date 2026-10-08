#!/usr/bin/env python3

import configparser
import os
import queue
import re
import sys
import time
from collections import defaultdict, deque
from datetime import datetime


PROGRAM_NAME = "sentraID"

CONFIG_PATH = os.path.join("config", "sentraid.conf")
ALERT_LOG_PATH = os.path.join("logs", "sentraid.log")

DEFAULT_LOGS = {
    "redhat": "/var/log/secure",
    "debian": "/var/log/auth.log",
}

SUPPORTED_OS_FAMILIES = {
    "redhat",
    "debian",
    "windows",
}

WINDOWS_EVENT_IDS = {
    4624,  # Successful logon
    4625,  # Failed logon
}


class SentraIDError(Exception):
    """sentraID application error."""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def load_config(config_path):
    """
    Load sentraid.conf.

    Expected configuration:

        [general]
        os_family=redhat

        [thresholds]
        brute_force_count=10
        brute_force_window=60

        [special_id]
        root
        systemx
        bob

    access_log is intentionally no longer configurable.

    Log sources are selected automatically:

        redhat  -> /var/log/secure
        debian  -> /var/log/auth.log
        windows -> Windows Security Event Log
    """

    config = configparser.ConfigParser(
        allow_no_value=True
    )

    try:
        with open(
            config_path,
            "r",
            encoding="utf-8",
        ) as config_file:
            config.read_file(config_file)

    except OSError as exc:
        raise SentraIDError(
            f"unable to read config file: {exc}"
        )

    if not config.has_section("general"):
        raise SentraIDError(
            "missing [general] section in config"
        )

    if not config.has_option(
        "general",
        "os_family",
    ):
        raise SentraIDError(
            "missing configuration option: os_family"
        )

    os_family = config.get(
        "general",
        "os_family",
    ).strip().lower()

    if os_family not in SUPPORTED_OS_FAMILIES:
        raise SentraIDError(
            "os_family must be one of: "
            "redhat, debian, windows"
        )

    brute_force_count = config.getint(
        "thresholds",
        "brute_force_count",
        fallback=10,
    )

    brute_force_window = config.getint(
        "thresholds",
        "brute_force_window",
        fallback=60,
    )

    if brute_force_count <= 0:
        raise SentraIDError(
            "brute_force_count must be greater than zero"
        )

    if brute_force_window <= 0:
        raise SentraIDError(
            "brute_force_window must be greater than zero"
        )

    special_users = set()

    if config.has_section("special_id"):
        for user in config.options("special_id"):
            user = user.strip()

            if user:
                special_users.add(
                    user.lower()
                )

    return {
        "os_family": os_family,
        "brute_force_count": brute_force_count,
        "brute_force_window": brute_force_window,
        "special_users": special_users,
    }


# ---------------------------------------------------------------------------
# Linux syslog parsing
# ---------------------------------------------------------------------------

def parse_syslog_line(line):
    """
    Parse the common syslog prefix used by:

        /var/log/secure
        /var/log/auth.log

    Example:

        Oct  2 21:30:00 server01 sshd[12345]:
        Failed password for root from 192.0.2.10 port 22 ssh2
    """

    line = line.rstrip("\r\n")

    pattern = re.compile(
        r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
        r"\s+(?P<host>\S+)"
        r"\s+(?P<process>[^:\[]+)"
        r"(?:\[(?P<pid>\d+)\])?"
        r":\s+(?P<message>.*)$"
    )

    match = pattern.match(line)

    if not match:
        return None

    return {
        "timestamp": match.group("timestamp"),
        "host": match.group("host"),
        "process": match.group("process"),
        "pid": match.group("pid"),
        "message": match.group("message"),
    }


def parse_sshd_event(parsed):
    """
    Convert an sshd log message into a normalized event.

    Returns:

        {
            "event": "...",
            "user": "...",
            "srcip": "..."
        }

    or None if the line isn't one of the events we care about.
    """

    if parsed is None:
        return None

    if parsed["process"].strip() != "sshd":
        return None

    message = parsed["message"]

    # ------------------------------------------------------------------
    # Invalid user
    #
    # Failed password for invalid user admin from 192.0.2.10 ...
    # ------------------------------------------------------------------

    match = re.search(
        r"Failed password for invalid user (?P<user>\S+)"
        r"\s+from\s+(?P<srcip>\S+)",
        message,
        re.IGNORECASE,
    )

    if match:
        return {
            "event": "invalid_user",
            "user": match.group("user"),
            "srcip": match.group("srcip"),
        }

    # ------------------------------------------------------------------
    # Authentication failure
    #
    # Failed password for root from 192.0.2.10 ...
    # Failed publickey for ...
    # Failed keyboard-interactive/pam for ...
    # ------------------------------------------------------------------

    match = re.search(
        r"Failed\s+(?:password|publickey|keyboard-interactive/pam)"
        r"\s+for\s+(?P<user>\S+)"
        r"\s+from\s+(?P<srcip>\S+)",
        message,
        re.IGNORECASE,
    )

    if match:
        return {
            "event": "auth_failure",
            "user": match.group("user"),
            "srcip": match.group("srcip"),
        }

    # ------------------------------------------------------------------
    # Successful authentication
    #
    # Accepted password for alice from 192.0.2.10 ...
    # Accepted publickey for alice from 192.0.2.10 ...
    # ------------------------------------------------------------------

    match = re.search(
        r"Accepted\s+(?:password|publickey|keyboard-interactive/pam)"
        r"\s+for\s+(?P<user>\S+)"
        r"\s+from\s+(?P<srcip>\S+)",
        message,
        re.IGNORECASE,
    )

    if match:
        return {
            "event": "auth_success",
            "user": match.group("user"),
            "srcip": match.group("srcip"),
        }

    return None


# ---------------------------------------------------------------------------
# Windows Event Log parsing
# ---------------------------------------------------------------------------

def parse_windows_event_xml(xml_text):
    """
    Parse a Windows Security Event Log XML event.

    Only Event IDs 4624 and 4625 are accepted.

    4624 -> auth_success
    4625 -> auth_failure
    """

    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(xml_text)

    except ET.ParseError:
        return None

    namespace = {
        "e": "http://schemas.microsoft.com/win/2004/08/events/event"
    }

    event_id_element = root.find(
        "e:System/e:EventID",
        namespace,
    )

    if event_id_element is None:
        return None

    try:
        event_id = int(
            event_id_element.text
        )

    except (TypeError, ValueError):
        return None

    if event_id not in WINDOWS_EVENT_IDS:
        return None

    event_data = root.find(
        "e:EventData",
        namespace,
    )

    if event_data is None:
        return None

    fields = {}

    for data in event_data:
        field_name = data.attrib.get("Name")

        if field_name:
            fields[field_name] = data.text or ""

    username = fields.get(
        "TargetUserName",
        "",
    ).strip()

    domain = fields.get(
        "TargetDomainName",
        "",
    ).strip()

    source_ip = fields.get(
        "IpAddress",
        "",
    ).strip()

    logon_type = fields.get(
        "LogonType",
        "",
    ).strip()

    try:
        logon_type = int(logon_type)

    except ValueError:
        logon_type = 0

    if not username:
        return None

    if not source_ip:
        return None

    # Windows sometimes uses "-" when there is no remote
    # network address. Do not correlate those events as if
    # they came from the same source.
    if source_ip == "-":
        return None

    if event_id == 4625:
        event_name = "auth_failure"

    else:
        event_name = "auth_success"

    return {
        "event": event_name,
        "event_id": event_id,
        "user": username,
        "domain": domain,
        "srcip": source_ip,
        "logon_type": logon_type,
    }


def windows_event_callback(
    action,
    context,
    event_handle,
):
    """
    Callback used by win32evtlog.EvtSubscribe.

    The callback only renders the event and puts the XML
    into a queue. Detection happens in the main thread.
    """

    import win32evtlog

    event_queue = context["queue"]

    if action == win32evtlog.EvtSubscribeActionError:
        event_queue.put(
            SentraIDError(
                "Windows Event Log subscription error"
            )
        )

        return

    if action != win32evtlog.EvtSubscribeActionDeliver:
        return

    try:
        xml_text = win32evtlog.EvtRender(
            event_handle,
            win32evtlog.EvtRenderEventXml,
        )

        event_queue.put(xml_text)

    except Exception as exc:
        event_queue.put(
            SentraIDError(
                f"unable to render Windows event: {exc}"
            )
        )


def follow_windows_security_log():
    """
    Follow the Windows Security Event Log.

    Only future 4624/4625 events are received.

    Historical events are intentionally ignored at startup,
    matching the Linux follow_log() behavior.
    """

    if os.name != "nt":
        raise SentraIDError(
            "Windows Event Log support requires Windows"
        )

    try:
        import win32evtlog

    except ImportError:
        raise SentraIDError(
            "Windows support requires pywin32; "
            "install it with: pip install pywin32"
        )

    event_queue = queue.Queue()

    context = {
        "queue": event_queue,
    }

    query = (
        "*[System["
        "(EventID=4624 or EventID=4625)"
        "]]"
    )

    try:
        subscription = win32evtlog.EvtSubscribe(
            "Security",
            win32evtlog.EvtSubscribeToFutureEvents,
            Callback=windows_event_callback,
            Context=context,
            Query=query,
        )

    except Exception as exc:
        raise SentraIDError(
            f"unable to subscribe to Windows Security "
            f"Event Log: {exc}"
        )

    try:
        while True:
            try:
                item = event_queue.get(
                    timeout=1.0
                )

            except queue.Empty:
                continue

            if isinstance(
                item,
                SentraIDError,
            ):
                raise item

            event = parse_windows_event_xml(
                item
            )

            if event is not None:
                yield event

    finally:
        try:
            win32evtlog.EvtClose(
                subscription
            )

        except Exception:
            pass


# ---------------------------------------------------------------------------
# Alert handling
# ---------------------------------------------------------------------------

def build_alert(
    event,
    srcip,
    user=None,
    failures=None,
):
    """
    Build a standard sentraID alert.
    """

    timestamp = datetime.now().strftime(
        "%H:%M:%S"
    )

    parts = [
        timestamp,
        "ALERT",
        f"{PROGRAM_NAME}:",
        f"srcip={srcip}",
        f"event={event}",
    ]

    if user is not None:
        parts.append(
            f"user={user}"
        )

    if failures is not None:
        parts.append(
            f"failures={failures}"
        )

    return " ".join(parts)


def write_alert(alert):
    try:
        parent = os.path.dirname(
            ALERT_LOG_PATH
        )

        if parent:
            os.makedirs(
                parent,
                exist_ok=True,
            )

        with open(
            ALERT_LOG_PATH,
            "a",
            encoding="utf-8",
        ) as alert_file:
            alert_file.write(
                alert + "\n"
            )

    except OSError as exc:
        raise SentraIDError(
            f"unable to write alert log: {exc}"
        )


def emit_alert(alert):
    """
    Print the alert immediately and write the
    exact same line to logs/sentraid.log.
    """

    print(
        alert,
        flush=True,
    )

    write_alert(alert)


# ---------------------------------------------------------------------------
# Linux log following
# ---------------------------------------------------------------------------

def open_log(path):
    try:
        return open(
            path,
            "r",
            encoding="utf-8",
            errors="replace",
        )

    except OSError as exc:
        raise SentraIDError(
            f"unable to open access log: {exc}"
        )


def follow_log(path):
    """
    Follow a Linux authentication log.

    Initial startup:
        Start at EOF so historical entries are ignored.

    Rotation/replacement:
        Start the replacement file from the beginning.

    Truncation:
        Start the truncated file from the beginning.
    """

    while not os.path.exists(path):
        time.sleep(0.5)

    log_file = open_log(path)

    try:
        # Ignore historical entries on initial startup.
        log_file.seek(
            0,
            os.SEEK_END,
        )

        current_inode = os.fstat(
            log_file.fileno()
        ).st_ino

        while True:
            line = log_file.readline()

            if line:
                yield line
                continue

            time.sleep(0.5)

            try:
                stat = os.stat(path)
                current_position = (
                    log_file.tell()
                )

                # File was truncated.
                if stat.st_size < current_position:
                    log_file.close()

                    log_file = open_log(
                        path
                    )

                    current_inode = os.fstat(
                        log_file.fileno()
                    ).st_ino

                    continue

                # File was replaced/rotated.
                if stat.st_ino != current_inode:
                    log_file.close()

                    log_file = open_log(
                        path
                    )

                    current_inode = os.fstat(
                        log_file.fileno()
                    ).st_ino

                    # Read replacement file from beginning.
                    continue

            except FileNotFoundError:
                try:
                    log_file.close()

                except OSError:
                    pass

                while not os.path.exists(path):
                    time.sleep(0.5)

                log_file = open_log(
                    path
                )

                current_inode = os.fstat(
                    log_file.fileno()
                ).st_ino

            except OSError:
                # Ignore temporary filesystem errors.
                continue

    finally:
        try:
            log_file.close()

        except OSError:
            pass


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------

class DetectionEngine:
    """
    Common detection engine for Linux and Windows.

    Detection rules:

    1. brute_force
       - Source IP only.
       - N or more failures within brute_force_window.

    2. success_after_failure
       - Source IP + username.
       - At least one previous failure within
         brute_force_window.

    3. special_login
       - Successful authentication by a user listed
         in [special_id].
    """

    def __init__(
        self,
        brute_force_count,
        brute_force_window,
        special_users,
    ):
        self.brute_force_count = (
            brute_force_count
        )

        self.brute_force_window = (
            brute_force_window
        )

        self.special_users = (
            special_users
        )

        # ------------------------------------------------------------
        # Brute-force state.
        #
        # Source IP -> failure timestamps
        # ------------------------------------------------------------

        self.failures_by_ip = (
            defaultdict(deque)
        )

        # Prevent repeated brute-force alerts while
        # the attack continues beyond the threshold.
        self.brute_force_alerted = set()

        # ------------------------------------------------------------
        # Success-after-failure state.
        #
        # (source IP, username) -> failure timestamps
        # ------------------------------------------------------------

        self.failures_by_identity = (
            defaultdict(deque)
        )

    def cleanup_ip(
        self,
        srcip,
        now,
    ):
        """
        Remove expired brute-force failure timestamps
        for a source IP.
        """

        failure_times = (
            self.failures_by_ip.get(
                srcip
            )
        )

        if not failure_times:
            return

        cutoff = (
            now
            - self.brute_force_window
        )

        while (
            failure_times
            and failure_times[0] < cutoff
        ):
            failure_times.popleft()

        if not failure_times:
            self.failures_by_ip.pop(
                srcip,
                None,
            )

            self.brute_force_alerted.discard(
                srcip
            )

    def cleanup_identity(
        self,
        identity,
        now,
    ):
        """
        Remove expired success-after-failure
        timestamps for an IP + username.
        """

        failure_times = (
            self.failures_by_identity.get(
                identity
            )
        )

        if not failure_times:
            return

        cutoff = (
            now
            - self.brute_force_window
        )

        while (
            failure_times
            and failure_times[0] < cutoff
        ):
            failure_times.popleft()

        if not failure_times:
            self.failures_by_identity.pop(
                identity,
                None,
            )

    def cleanup_all(
        self,
        now,
    ):
        """
        Periodically remove stale state.

        This prevents old source IPs and identities from
        accumulating indefinitely.
        """

        for srcip in list(
            self.failures_by_ip.keys()
        ):
            self.cleanup_ip(
                srcip,
                now,
            )

        for identity in list(
            self.failures_by_identity.keys()
        ):
            self.cleanup_identity(
                identity,
                now,
            )

    def record_failure(
        self,
        event,
        now,
    ):
        """
        Process a failed authentication.

        Brute-force detection:
            source IP only.

        Success-after-failure correlation:
            source IP + username.
        """

        srcip = event["srcip"]
        user = event["user"]

        normalized_user = (
            user.lower()
        )

        # ------------------------------------------------------------
        # Cleanup old state.
        # ------------------------------------------------------------

        self.cleanup_ip(
            srcip,
            now,
        )

        identity = (
            srcip,
            normalized_user,
        )

        self.cleanup_identity(
            identity,
            now,
        )

        # ------------------------------------------------------------
        # Record failure for brute-force detection.
        # ------------------------------------------------------------

        self.failures_by_ip[
            srcip
        ].append(now)

        # ------------------------------------------------------------
        # Record failure for success-after-failure detection.
        # ------------------------------------------------------------

        self.failures_by_identity[
            identity
        ].append(now)

        # ------------------------------------------------------------
        # Linux-specific invalid-user alert.
        #
        # Windows 4625 events do not generate this alert because
        # the Windows implementation intentionally only targets:
        #
        #   brute_force
        #   success_after_failure
        #   special_login
        #
        # ------------------------------------------------------------

        if event["event"] == "invalid_user":
            alert = build_alert(
                "invalid_user",
                srcip,
                user=user,
            )

            emit_alert(alert)

        # ------------------------------------------------------------
        # Brute force.
        #
        # IMPORTANT:
        # This is intentionally counted per source IP,
        # regardless of username.
        # ------------------------------------------------------------

        failure_times = (
            self.failures_by_ip[
                srcip
            ]
        )

        cutoff = (
            now
            - self.brute_force_window
        )

        failure_count = sum(
            1
            for timestamp in failure_times
            if timestamp >= cutoff
        )

        if (
            failure_count
            >= self.brute_force_count
            and srcip
            not in self.brute_force_alerted
        ):
            alert = build_alert(
                "brute_force",
                srcip,
                failures=failure_count,
            )

            emit_alert(alert)

            self.brute_force_alerted.add(
                srcip
            )

    def record_success(
        self,
        event,
        now,
    ):
        """
        Process a successful authentication.

        success_after_failure:
            same source IP + same username

        special_login:
            username exists in [special_id]
        """

        srcip = event["srcip"]
        user = event["user"]

        normalized_user = (
            user.lower()
        )

        identity = (
            srcip,
            normalized_user,
        )

        # ------------------------------------------------------------
        # Cleanup expired state.
        # ------------------------------------------------------------

        self.cleanup_ip(
            srcip,
            now,
        )

        self.cleanup_identity(
            identity,
            now,
        )

        # ------------------------------------------------------------
        # success_after_failure
        #
        # At least ONE matching 4625 within the configured
        # brute_force_window is sufficient.
        # ------------------------------------------------------------

        failure_times = (
            self.failures_by_identity.get(
                identity,
                deque(),
            )
        )

        cutoff = (
            now
            - self.brute_force_window
        )

        recent_failure_count = sum(
            1
            for timestamp in failure_times
            if timestamp >= cutoff
        )

        if recent_failure_count > 0:
            alert = build_alert(
                "success_after_failure",
                srcip,
                user=user,
            )

            emit_alert(alert)

        # ------------------------------------------------------------
        # special_login
        # ------------------------------------------------------------

        if (
            normalized_user
            in self.special_users
        ):
            alert = build_alert(
                "special_login",
                srcip,
                user=user,
            )

            emit_alert(alert)

        # ------------------------------------------------------------
        # A successful login ends the current failure sequence
        # for this source IP and this identity.
        # ------------------------------------------------------------

        self.failures_by_identity.pop(
            identity,
            None,
        )

        # The successful authentication also ends the
        # current brute-force sequence for the source IP.
        self.failures_by_ip.pop(
            srcip,
            None,
        )

        self.brute_force_alerted.discard(
            srcip
        )

    def process(
        self,
        event,
    ):
        """
        Process one normalized authentication event.
        """

        now = time.time()

        event_type = event.get(
            "event"
        )

        if event_type in {
            "invalid_user",
            "auth_failure",
        }:
            self.record_failure(
                event,
                now,
            )

        elif event_type == "auth_success":
            self.record_success(
                event,
                now,
            )


# ---------------------------------------------------------------------------
# Linux event processing
# ---------------------------------------------------------------------------

def process_line(
    line,
    detection_engine,
):
    """
    Parse one Linux syslog line and send the
    normalized event to the common detector.
    """

    parsed = parse_syslog_line(
        line
    )

    if parsed is None:
        return

    event = parse_sshd_event(
        parsed
    )

    if event is None:
        return

    detection_engine.process(
        event
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    try:
        config = load_config(
            CONFIG_PATH
        )

        detection_engine = DetectionEngine(
            brute_force_count=config[
                "brute_force_count"
            ],
            brute_force_window=config[
                "brute_force_window"
            ],
            special_users=config[
                "special_users"
            ],
        )

        os_family = config[
            "os_family"
        ]

        # ------------------------------------------------------------
        # Windows
        # ------------------------------------------------------------

        if os_family == "windows":
            print(
                f"{PROGRAM_NAME} monitoring: "
                "Windows Security Event Log "
                "(4624, 4625)",
                flush=True,
            )

            for event in (
                follow_windows_security_log()
            ):
                detection_engine.process(
                    event
                )

            return 0

        # ------------------------------------------------------------
        # Linux
        # ------------------------------------------------------------

        access_log = DEFAULT_LOGS[
            os_family
        ]

        print(
            f"{PROGRAM_NAME} monitoring: "
            f"{access_log}",
            flush=True,
        )

        for line in follow_log(
            access_log
        ):
            process_line(
                line,
                detection_engine,
            )

    except KeyboardInterrupt:
        print(
            f"{PROGRAM_NAME} stopped.",
            flush=True,
        )

        return 0

    except SentraIDError as exc:
        print(
            f"{PROGRAM_NAME} error: {exc}",
            file=sys.stderr,
        )

        return 1

    except Exception as exc:
        print(
            f"{PROGRAM_NAME} error: {exc}",
            file=sys.stderr,
        )

        return 1


if __name__ == "__main__":
    sys.exit(main())
