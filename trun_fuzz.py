#!/usr/bin/env python
from boofuzz import *
import socket
import time
import sys

# Very small timeout for health checks (seconds)
HEALTH_CHECK_TIMEOUT = 2.0

def receive_banner(sock):
    try:
        sock.recv(1024)
    except Exception:
        # ignore banner read errors — the target might not send one
        pass

def check_alive(target=None, fuzz_data_logger=None, session=None):
    """
    post_test_case callback: attempt to connect to the target service.
    If connect fails, log the failure and stop the session.
    """
    # Grab host/port from the Target's connection object if possible
    try:
        conn = session.target.connection
        host = conn.host
        port = conn.port
    except Exception:
        # Fallback to defaults (edit these if your target values differ)
        host = "10.0.2.15"
        port = 9999

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(HEALTH_CHECK_TIMEOUT)
    try:
        s.connect((host, int(port)))
        s.close()
        return True
    except Exception as e:
        # Log the failure (boofuzz logger) and stop fuzzing
        msg = f"Target unresponsive after test case: {e}"
        # Use fuzz_data_logger if available to get consistent logging
        if fuzz_data_logger:
            try:
                fuzz_data_logger.log_fail(msg)
            except Exception:
                print("Failed to call fuzz_data_logger.log_fail() — falling back to print")
                print(msg)
        else:
            print(msg)

        # Stop the session so boofuzz will keep the state and logs
        if session:
            try:
                session.stop()
            except Exception:
                # If stopping fails, exit to be safe
                print("session.stop() failed; exiting.")
                sys.exit(1)
        else:
            sys.exit(1)

        return False

def main():
    host = '10.0.2.15'
    port = 9999

    # Create different loggers for tracking fuzzing progress
    text_logger = FuzzLoggerText()
    file_logger = FuzzLoggerText(open("fuzz_log.txt", "w"))
    csv_logger = FuzzLoggerCsv(open("fuzz_log.csv", "w", newline=""))

    # Initialize a fuzzing session
    session = Session(
        sleep_time=1,
        target=Target(connection=TCPSocketConnection(host, int(port))),
        reuse_target_connection=True,
        fuzz_loggers=[text_logger, file_logger, csv_logger]
    )

    # Define the fuzzing structure for the "TRUN" command
    s_initialize("TRUN")
    s_string('TRUN', fuzzable=False, name='TRUN-Command')
    s_delim(' ', fuzzable=False, name='TRUN-Space')
    s_string('A', name='TRUN-STRING')
    s_static('\r\n', name='TRUN-CRLF')

    session.pre_send = receive_banner

    # Register the post-test-case health check
    session.post_test_case_callbacks = [check_alive]

    session.connect(s_get("TRUN"))

    session.fuzz()

if __name__ == '__main__':
    main()
