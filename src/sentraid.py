#!/usr/bin/env python3

import configparser
import os
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


class SentraIDError(Exception):
    """sentraID application error."""


def load_config(config_path):
    config = configparser.ConfigParser(allow_no_value=True)

    try:
        with open(config_path, "r", encoding="utf-8") as config_file:
            config.read_file(config_file)
    except OSError as exc:
        raise SentraIDError(f"unable to read config file: {exc}")

    if not config.has_section("general"):
        raise SentraIDError("missing [general] section in config")

    if not config.has_option("general", "os_family"):
        raise SentraIDError("missing configuration option: os_family")

    os_family = config.get("general", "os_family").strip().lower()

    if os_family not in DEFAULT_LOGS:
        raise SentraIDError(
            "os_family must be either 'redhat' or 'debian'"
        )

    access_log = config.get(
        "general",
        "access_log",
        fallback=DEFAULT_LOGS[os_family],
    ).strip()

    if not access_log:
        access_log = DEFAULT_LOGS[os_family]

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

    success_window = config.getint(
        "thresholds",
        "success_after_failure_window",
        fallback=300,
    )

    if brute_force_count <= 0:
        raise SentraIDError("brute_force_count must be greater than zero")

    if brute_force_window <= 0:
        raise SentraIDError("brute_force_window must be greater than zero")

    if success_window <= 0:
        raise SentraIDError(
            "success_after_failure_window must be greater than zero"
        )

    special_users = []

    if config.has_section("special_id"):
        for user in config.options("special_id"):
            user = user.strip()

            if user:
                special_users.append(user)

    # ConfigParser lowercases option names by default, which is desirable
    # for Linux usernames in this context.
    special_users = set(special_users)

    return {
        "os_family": os_family,
        "access_log": access_log,
        "brute_force_count": brute_force_count,
        "brute_force_window": brute_force_window,
        "success_after_failure_window": success_window,
        "special_users": special_users,
    }


def parse_syslog_line(line):
    """
    Parse the common syslog prefix used by /var/log/secure
    and /var/log/auth.log.

    Example:

    Oct  2 21:30:00 server01 sshd[12345]: Failed password ...
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

    # ------------------------------------------------------------
    # Invalid user
    #
    # Failed password for invalid user admin from 192.0.2.10 ...
    # ------------------------------------------------------------

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

    # ------------------------------------------------------------
    # Authentication failure for a valid user
    #
    # Failed password for root from 192.0.2.10 ...
    #
    # Also handles:
    # Failed publickey for ...
    # Failed keyboard-interactive/pam for ...
    # ------------------------------------------------------------

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

    # ------------------------------------------------------------
    # Successful authentication
    #
    # Accepted password for alice from 192.0.2.10 ...
    # Accepted publickey for alice from 192.0.2.10 ...
    # Accepted keyboard-interactive/pam for alice from ...
    # ------------------------------------------------------------

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


def build_alert(event, srcip, user=None, failures=None):
    timestamp = datetime.now().strftime("%H:%M:%S")

    parts = [
        timestamp,
        "ALERT",
        f"{PROGRAM_NAME}:",
        f"srcip={srcip}",
        f"event={event}",
    ]

    if user is not None:
        parts.append(f"user={user}")

    if failures is not None:
        parts.append(f"failures={failures}")

    return " ".join(parts)


def write_alert(alert):
    try:
        parent = os.path.dirname(ALERT_LOG_PATH)

        if parent:
            os.makedirs(parent, exist_ok=True)

        with open(
            ALERT_LOG_PATH,
            "a",
            encoding="utf-8",
        ) as alert_file:
            alert_file.write(alert + "\n")

    except OSError as exc:
        raise SentraIDError(f"unable to write alert log: {exc}")


def emit_alert(alert):
    """
    Print the alert immediately and write the exact same
    line to logs/sentraid.log.
    """

    print(alert, flush=True)
    write_alert(alert)


def open_log(path):
    try:
        return open(
            path,
            "r",
            encoding="utf-8",
            errors="replace",
        )
    except OSError as exc:
        raise SentraIDError(f"unable to open access log: {exc}")


def follow_log(path):
    """
    Follow an authentication log.

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
        log_file.seek(0, os.SEEK_END)

        current_inode = os.fstat(log_file.fileno()).st_ino

        while True:
            line = log_file.readline()

            if line:
                yield line
                continue

            time.sleep(0.5)

            try:
                stat = os.stat(path)
                current_position = log_file.tell()

                # File was truncated.
                if stat.st_size < current_position:
                    log_file.close()
                    log_file = open_log(path)
                    current_inode = os.fstat(
                        log_file.fileno()
                    ).st_ino

                    continue

                # File was replaced/rotated.
                if stat.st_ino != current_inode:
                    log_file.close()
                    log_file = open_log(path)
                    current_inode = os.fstat(
                        log_file.fileno()
                    ).st_ino

                    # Read the replacement file from the beginning.
                    continue

            except FileNotFoundError:
                try:
                    log_file.close()
                except OSError:
                    pass

                while not os.path.exists(path):
                    time.sleep(0.5)

                log_file = open_log(path)
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


class DetectionEngine:
    """
    Maintains the small amount of in-memory state needed for:

    - brute_force
    - success_after_failure
    """

    def __init__(
        self,
        brute_force_count,
        brute_force_window,
        success_after_failure_window,
        special_users,
    ):
        self.brute_force_count = brute_force_count
        self.brute_force_window = brute_force_window
        self.success_after_failure_window = (
            success_after_failure_window
        )
        self.special_users = special_users

        # srcip -> deque of failure timestamps
        self.failures = defaultdict(deque)

        # Prevent repeated brute-force alerts while the attack
        # continues beyond the threshold.
        self.brute_force_alerted = set()

    def cleanup_failures(self, srcip, now):
        failure_times = self.failures[srcip]

        cutoff = now - max(
            self.brute_force_window,
            self.success_after_failure_window,
        )

        while failure_times and failure_times[0] < cutoff:
            failure_times.popleft()

        if not failure_times:
            self.failures.pop(srcip, None)
            self.brute_force_alerted.discard(srcip)

    def record_failure(self, event, now):
        srcip = event["srcip"]

        self.cleanup_failures(srcip, now)

        self.failures[srcip].append(now)

        # --------------------------------------------------------
        # Invalid user is an immediate event.
        # --------------------------------------------------------

        if event["event"] == "invalid_user":
            alert = build_alert(
                "invalid_user",
                srcip,
                user=event["user"],
            )
            emit_alert(alert)

        # --------------------------------------------------------
        # Brute force.
        # --------------------------------------------------------

        failure_times = self.failures[srcip]

        brute_force_cutoff = now - self.brute_force_window

        recent_failures = [
            timestamp
            for timestamp in failure_times
            if timestamp >= brute_force_cutoff
        ]

        failure_count = len(recent_failures)

        if (
            failure_count >= self.brute_force_count
            and srcip not in self.brute_force_alerted
        ):
            alert = build_alert(
                "brute_force",
                srcip,
                failures=failure_count,
            )

            emit_alert(alert)

            self.brute_force_alerted.add(srcip)

    def record_success(self, event, now):
        srcip = event["srcip"]
        user = event["user"]

        self.cleanup_failures(srcip, now)

        failure_times = self.failures.get(srcip, deque())

        cutoff = now - self.success_after_failure_window

        recent_failure_count = sum(
            1
            for timestamp in failure_times
            if timestamp >= cutoff
        )

        # --------------------------------------------------------
        # Successful login after recent failures.
        # --------------------------------------------------------

        if recent_failure_count > 0:
            alert = build_alert(
                "success_after_failure",
                srcip,
                user=user,
            )

            emit_alert(alert)

        # --------------------------------------------------------
        # Special user login.
        # --------------------------------------------------------

        if user.lower() in self.special_users:
            alert = build_alert(
                "special_login",
                srcip,
                user=user,
            )

            emit_alert(alert)

        # A successful login ends the current failure sequence.
        self.failures.pop(srcip, None)
        self.brute_force_alerted.discard(srcip)

    def process(self, event):
        now = time.time()

        if event["event"] in {
            "invalid_user",
            "auth_failure",
        }:
            self.record_failure(event, now)

        elif event["event"] == "auth_success":
            self.record_success(event, now)


def process_line(line, detection_engine):
    parsed = parse_syslog_line(line)

    if parsed is None:
        return

    event = parse_sshd_event(parsed)

    if event is None:
        return

    detection_engine.process(event)


def main():
    try:
        config = load_config(CONFIG_PATH)

        detection_engine = DetectionEngine(
            brute_force_count=config["brute_force_count"],
            brute_force_window=config["brute_force_window"],
            success_after_failure_window=config[
                "success_after_failure_window"
            ],
            special_users=config["special_users"],
        )

        access_log = config["access_log"]

        print(
            f"{PROGRAM_NAME} monitoring: {access_log}",
            flush=True,
        )

        for line in follow_log(access_log):
            process_line(line, detection_engine)

    except KeyboardInterrupt:
        print(f"{PROGRAM_NAME} stopped.", flush=True)
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

