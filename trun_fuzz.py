#!/usr/bin/env python
from boofuzz import *
import sys

def receive_banner(sock):
    sock.recv(1024)

def main():
    host = '10.0.2.15'  # Windows machine IP
    port = 9999

    # Create loggers
    text_logger = FuzzLoggerText()
    file_logger = FuzzLoggerText(open("fuzz_log.txt", "w"))
    csv_logger = FuzzLoggerCsv(open("fuzz_log.csv", "w", newline=""))

    # Create a custom monitor that detects connection failures
    class ConnectionMonitor(BaseMonitor):
        def post_send(self, target=None, fuzz_data_logger=None, session=None):
            try:
                # Try to send a simple ping to see if the service is still alive
                target.recv(1024, timeout=1)
                return True  # Service is still alive
            except:
                fuzz_data_logger.log_fail("Target connection lost - possible crash detected")
                return False  # Service appears to have crashed

    # Create the target with the connection monitor
    target = Target(
        connection=TCPSocketConnection(host, int(port)),
        monitors=[ConnectionMonitor()]
    )

    # Initialize the fuzzing session
    session = Session(
        sleep_time=1,
        target=target,
        reuse_target_connection=False,  # Don't reuse connections to detect crashes
        fuzz_loggers=[text_logger, file_logger, csv_logger]
    )

    # Define the fuzzing structure
    s_initialize("TRUN")
    s_string('TRUN', fuzzable=False, name='TRUN-Command')
    s_delim(' ', fuzzable=False, name='TRUN-Space')
    s_string('A', name='TRUN-STRING')
    s_static('\r\n', name='TRUN-CRLF')

    session.pre_send = receive_banner
    session.connect(s_get("TRUN"))
    session.fuzz()

if __name__ == '__main__':
    main()
