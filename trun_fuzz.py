
#!/usr/bin/env python3
import socket
import subprocess
import shlex
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


class TcpHealthMonitor(BaseMonitor):
    def __init__(self, host, port, timeout=1.0, start_command=None, stop_command=None, check_delay=0.2):
        super().__init__()
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self.start_command = start_command  # e.g., "/usr/local/bin/myservice --flag"
        self.stop_command = stop_command    # e.g., "pkill -f myservice"
        self.check_delay = float(check_delay)
        self._last_crash_reason = None

    def _tcp_is_alive(self):
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout):
                return True
        except Exception as e:
            self._last_crash_reason = f"TCP {self.host}:{self.port} not accepting connections: {e}"
            return False

    def alive(self):
        return self._tcp_is_alive()

    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        if not self._tcp_is_alive():
            time.sleep(self.check_delay)

    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        return self._tcp_is_alive()

    def start_target(self):
        if not self.start_command:
            return False
        try:
            subprocess.Popen(shlex.split(self.start_command))
            time.sleep(self.check_delay)
            return True
        except Exception as e:
            self._last_crash_reason = f"Failed to start target: {e}"
            return False

    def stop_target(self):
        if not self.stop_command:
            return
        try:
            subprocess.call(shlex.split(self.stop_command))
            time.sleep(self.check_delay)
        except Exception:
            pass

    def restart_target(self, target=None, fuzz_data_logger=None, session=None):
        self.stop_target()
        return self.start_target()

    def get_crash_synopsis(self):
        return self._last_crash_reason or "External monitor detected the target is unresponsive."


def receive_banner(target=None, fuzz_data_logger=None, session=None, sock=None):
    try:
        target.recv(1024)
    except Exception:
        pass


def main():
    host = "10.0.2.15"
    port = 9999

    text_logger = FuzzLoggerText()
    file_logger = FuzzLoggerText(open("fuzz_log.txt", "w"))
    csv_logger = FuzzLoggerCsv(open("fuzz_log.csv", "w", newline=""))

    mon = TcpHealthMonitor(
        host=host,
        port=port,
        timeout=1.0,
        # Optionally manage the target:
        # start_command="/path/to/target --arg",
        # stop_command="pkill -f target",
    )

    session = Session(
        sleep_time=1,
        target=Target(
            connection=TCPSocketConnection(host, int(port)),
            monitors=[mon],
        ),
        reuse_target_connection=True,
        fuzz_loggers=[text_logger, file_logger, csv_logger],
        pre_send_callbacks=[receive_banner],
        receive_data_after_fuzz=True,
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
