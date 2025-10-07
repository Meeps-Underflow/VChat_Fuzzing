#!/usr/bin/env python3
from boofuzz import *
import socket
import sys

HOST = "10.0.2.15"
PORT = 9999

# === Your monitor class exactly as you gave it ===
class TcpPingMonitor(boofuzz.monitors.BaseMonitor):
    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((target._target_connection.host, target._target_connection.port))
            return True
        except socket.error as e:
            fuzz_data_logger.log_fail(f"Opening TCP connection failed: {e}")
            return False
        finally:
            sock.close()

    def __repr__(self):
        return "TCP Ping Monitor"

def receive_banner(sock):
    try:
        sock.recv(1024)
    except Exception:
        pass

def main():
    # loggers
    text_logger = FuzzLoggerText()
    file_logger = FuzzLoggerText(open("fuzz_log.txt", "w"))
    csv_logger = FuzzLoggerCsv(open("fuzz_log.csv", "w", newline=""))

    # attach your monitor
    tcp_monitor = TcpPingMonitor()
    target = Target(connection=TCPSocketConnection(HOST, PORT),
                    monitors=[tcp_monitor])

    # session
    session = Session(
        sleep_time=1,
        target=target,
        reuse_target_connection=True,  # keep your original setting
        fuzz_loggers=[text_logger, file_logger, csv_logger]
    )

    # TRUN message
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
