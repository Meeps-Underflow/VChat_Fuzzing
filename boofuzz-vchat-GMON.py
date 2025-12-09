#!/usr/bin/env python  # Uses the env command to locate the Python interpreter in the system's PATH environment variable
from boofuzz import *  # Imports everything from the boofuzz module, making functions and classes available without a prefix
from boofuzz.monitors.base_monitor import BaseMonitor
import sys  # Imports the sys module to interact with the system (e.g., exit the script)
import socket
import time

# This custom monitor checks if the target TCP service is alive before and after each fuzz case.
# It helps automatically detect crashes or hangs without requiring manual supervision.
class TcpHealthMonitor(BaseMonitor):
    def __init__(self, host, port, timeout=1.0, check_delay=0.2):
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self.check_delay = float(check_delay)

    # Private helper to verify target availability via TCP connection
    def _tcp_is_alive(self):
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout):
                return True # Alive
        except Exception as e:
            return False # Dead / Crashed 

    # Check status after fuzz case
    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        return self._tcp_is_alive()
    
    # Check status after fuzz case
    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        if not self._tcp_is_alive():
            time.sleep(self.check_delay)

# Function to receive a banner message from the target system (typically used for services that send a welcome message)
def receive_banner(sock):
    sock.recv(1024)  # Reads up to 1024 bytes from the socket but doesn't store or process them

# Main function to set up and start fuzzing
def main():
    host = '10.211.55.6'  # Target host (IP address of the machine running the vulnerable service)
    port = 9999  # Target port (port number of the service to fuzz)

    # Create different loggers for tracking fuzzing progress
    text_logger = FuzzLoggerText()  # Logs fuzzing progress to the console
    csv_logger = FuzzLoggerCsv(open("csv/gmon_fuzz_log.csv", "w", newline=""))  # Logs fuzzing progress to a CSV file

    # Custom TCP Monitor
    mon = TcpHealthMonitor(
        host=host,
        port=port,
        timeout=0.5,
    )

    # Initialize a fuzzing session
    session = Session(
        sleep_time=1,  # Wait 1 second between each fuzz case
        target=Target(connection=TCPSocketConnection(host, int(port)), monitors=[mon]),  # Set up a TCP connection to the target
        reuse_target_connection=True,  # Reuse the same connection for multiple fuzz cases
        fuzz_loggers=[text_logger, csv_logger],  # Use the specified loggers to record fuzzing data
        post_start_target_callbacks=[receive_banner], # Read banner after connection established 
        receive_data_after_fuzz=True # Capture response after each fuzz case
    )

    # Define the fuzzing structure for the "GMON" command
    s_initialize("GMON")  # Initialize a fuzzing block named "GMON"
    s_string('GMON', fuzzable=False, name='GMON-Command')  # Send the command "GMON" (not fuzzable)
    s_delim(' ', fuzzable=False, name='GMON-Space')  # Send a space after "GMON" (not fuzzable)
    s_string('A', name='GMON-STRING')  # Fuzz this part by sending different "A" variations
    s_static('\r\n', name='GMON-CRLF')  # Append a carriage return + newline to mimic real commands

    # session.pre_send = receive_banner  # Assign `receive_banner` as a pre-send callback to read any initial response

    session.connect(s_get("GMON"))  # Connect the fuzzing session to the "GMON" structure defined above

    session.fuzz()  # Start the fuzzing process

# Entry point for the script
if __name__ == '__main__':
    main()  # Call the main function if the script is run directly, not when it is imported as a module.
