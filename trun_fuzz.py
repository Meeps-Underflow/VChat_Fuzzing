#!/usr/bin/env python
from boofuzz import *
import sys
import socket
import time

# Function to receive a banner message from the target system (typically used for services that send a welcome message)
def receive_banner(sock):
    try:
        sock.recv(1024)
    except Exception:
        pass

def main():
    host = '10.0.2.15'  # Target host (Windows target)
    port = 9999         # Target port

    # Create different loggers for tracking fuzzing progress
    text_logger = FuzzLoggerText()
    file_logger = FuzzLoggerText(open("fuzz_log.txt", "w"))
    csv_logger = FuzzLoggerCsv(open("fuzz_log.csv", "w", newline=""))

    # External monitor callbacks (no RPC)
    # Consider the service "crashed" if we cannot establish a fresh TCP connection shortly after a fuzz case.
    CONNECT_TIMEOUT = 1.0
    SETTLE_DELAY = 0.5  # give target a moment to die if it will

    def post_probe():
        # Allow a brief delay for crashes that occur right after payload delivery
        if SETTLE_DELAY > 0:
            time.sleep(SETTLE_DELAY)
        try:
            with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
                return True  # Service still accepting connections
        except Exception:
            # External.get_crash_synopsis() will provide a generic synopsis string
            return False

    external_monitor = External(
        pre=None,         # no pre action
        post=post_probe,  # liveness probe after each test
        start=None,       # optional: could add remote restart logic here
        stop=None
    )

    # Initialize a fuzzing session with the External monitor attached
    session = Session(
        sleep_time=1,
        target=Target(
            connection=TCPSocketConnection(host, int(port)),
            monitors=[external_monitor]
        ),
        # Reconnect per test helps surface service death between cases
        reuse_target_connection=False,
        fuzz_loggers=[text_logger, file_logger, csv_logger],
        receive_data_after_each_request=False,
        receive_data_after_fuzz=False
    )

    # Define the fuzzing structure for the "TRUN" command
    s_initialize("TRUN")
    s_string('TRUN', fuzzable=False, name='TRUN-Command')
    s_delim(' ', fuzzable=False, name='TRUN-Space')
    s_string('A', name='TRUN-STRING')
    s_static('\r\n', name='TRUN-CRLF')

    session.pre_send = receive_banner
    session.connect(s_get("TRUN"))
    session.fuzz()

# Entry point for the script
if __name__ == '__main__':
    main()
