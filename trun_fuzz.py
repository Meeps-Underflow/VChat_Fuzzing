#!/usr/bin/env python3
import socket
import time
import sys

from boofuzz import (
    Session,
    Target,
    TCPSocketConnection,
    FuzzLoggerText,
    FuzzLoggerCsv,
    s_initialize,
    s_string,
    s_delim,
    s_static,
)
from boofuzz.monitors.base_monitor import BaseMonitor


class TcpCrashOnlyMonitor(BaseMonitor):
    def __init__(self, host, port, timeout=1.0, recheck_delay=0.2):
        super().__init__()
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self.recheck_delay = float(recheck_delay)

    def _alive(self):
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout):
                return True
        except Exception:
            return False

    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        # Return True if alive, False if crashed
        return self._alive()

    def get_crash_synopsis(self):
        return f"Service at {self.host}:{self.port} stopped accepting TCP connections."


def main():
    host = "10.0.2.15"
    port = 9999

    text_logger = FuzzLoggerText()
    file_logger = FuzzLoggerText(open("fuzz_log.txt", "w"))
    csv_logger = FuzzLoggerCsv(open("fuzz_log.csv", "w", newline=""))

    mon = TcpCrashOnlyMonitor(host=host, port=port, timeout=1.0)

    session = Session(
        sleep_time=0.2,
        target=Target(
            connection=TCPSocketConnection(host, int(port)),
            monitors=[mon],
        ),
        reuse_target_connection=True,
        fuzz_loggers=[text_logger, file_logger, csv_logger],
        # Stop on first crash: set thresholds to 1
        crash_threshold_request=1,
        crash_threshold_element=1,
        receive_data_after_fuzz=False,  # optional; keep minimal
    )

    s_initialize("TRUN")
    s_string("TRUN", fuzzable=False, name="TRUN-Command")
    s_delim(" ", fuzzable=False, name="TRUN-Space")
    s_string("A", name="TRUN-STRING")
    s_static("\r\n", name="TRUN-CRLF")

    session.connect(s_get("TRUN"))
    session.fuzz()


if __name__ == "__main__":
    sys.exit(main())
