#!/usr/bin/env python3
"""
Sample Syslog Generator

This script generates sample syslog files for testing the Syslog Analyzer application.
It creates two log files with some overlapping timestamps and various error messages.
"""

import random
import datetime
import os
import time

# Configuration
LEFT_LOG_FILE = "sample_left.log"
RIGHT_LOG_FILE = "sample_right.log"
ERROR_KEYWORDS = [
    "ERROR", "Failed", "Exception", "denied", "timeout", 
    "segfault", "panic", "fatal", "out of memory"
]
SERVICES = [
    "apache2", "sshd", "kernel", "systemd", "cron", "nginx", 
    "mysqld", "postfix", "dhclient", "NetworkManager"
]
USERS = ["root", "www-data", "admin", "user", "system"]
ACTIONS = [
    "started", "stopped", "restarted", "configured", "modified", 
    "connected", "disconnected", "loaded", "unloaded", "processed"
]

def generate_timestamp(base_time, offset_seconds=0):
    """Generate a syslog timestamp with optional offset from base time"""
    log_time = base_time + datetime.timedelta(seconds=offset_seconds)
    return log_time.strftime("%b %d %H:%M:%S")

def generate_log_entry(timestamp, host="localhost", is_error=False):
    """Generate a random log entry"""
    service = random.choice(SERVICES)
    pid = random.randint(1000, 9999)
    
    if is_error:
        error_keyword = random.choice(ERROR_KEYWORDS)
        message = f"{error_keyword}: {random.choice(USERS)} could not {random.choice(ACTIONS)} {service}"
    else:
        action = random.choice(ACTIONS)
        user = random.choice(USERS)
        message = f"{user} {action} {service} successfully"
    
    return f"{timestamp} {host} {service}[{pid}]: {message}"

def generate_logs(num_entries=100, error_rate=0.1, time_overlap=0.5):
    """Generate two sample log files with some time overlap and errors"""
    # Create base timestamps for both logs
    now = datetime.datetime.now()
    left_base_time = now - datetime.timedelta(hours=2)
    
    # Right log starts later with some overlap
    right_offset = int((1 - time_overlap) * num_entries)
    right_base_time = left_base_time + datetime.timedelta(seconds=right_offset)
    
    # Generate left log
    with open(LEFT_LOG_FILE, 'w') as left_file:
        for i in range(num_entries):
            timestamp = generate_timestamp(left_base_time, i)
            is_error = random.random() < error_rate
            entry = generate_log_entry(timestamp, "server1", is_error)
            left_file.write(entry + "\n")
    
    # Generate right log with some overlap
    with open(RIGHT_LOG_FILE, 'w') as right_file:
        for i in range(num_entries):
            timestamp = generate_timestamp(right_base_time, i)
            is_error = random.random() < error_rate
            entry = generate_log_entry(timestamp, "server2", is_error)
            right_file.write(entry + "\n")
    
    print(f"Generated sample logs:")
    print(f"- {LEFT_LOG_FILE}: {num_entries} entries starting at {generate_timestamp(left_base_time)}")
    print(f"- {RIGHT_LOG_FILE}: {num_entries} entries starting at {generate_timestamp(right_base_time)}")
    print(f"Time overlap: {time_overlap * 100:.0f}%")
    print(f"Error rate: {error_rate * 100:.0f}%")

def generate_sequential_errors(filename, num_entries=20):
    """Generate a log file with a sequence of related errors"""
    now = datetime.datetime.now()
    base_time = now - datetime.timedelta(minutes=30)
    
    with open(filename, 'w') as f:
        # Normal operation
        for i in range(5):
            timestamp = generate_timestamp(base_time, i)
            entry = generate_log_entry(timestamp, "server3", False)
            f.write(entry + "\n")
        
        # Series of errors
        error_service = random.choice(SERVICES)
        error_pid = random.randint(1000, 9999)
        
        # Memory issue sequence
        f.write(f"{generate_timestamp(base_time, 10)} server3 {error_service}[{error_pid}]: WARNING: High memory usage detected\n")
        f.write(f"{generate_timestamp(base_time, 12)} server3 {error_service}[{error_pid}]: WARNING: System memory utilization above 85%\n")
        f.write(f"{generate_timestamp(base_time, 15)} server3 {error_service}[{error_pid}]: ERROR: Failed to allocate memory\n")
        f.write(f"{generate_timestamp(base_time, 17)} server3 {error_service}[{error_pid}]: ERROR: out of memory\n")
        f.write(f"{generate_timestamp(base_time, 20)} server3 kernel[1]: Out of memory: Killed process {error_pid} ({error_service})\n")
        
        # Recovery
        f.write(f"{generate_timestamp(base_time, 25)} server3 systemd[1]: {error_service}.service: Main process exited, code=killed, status=9/KILL\n")
        f.write(f"{generate_timestamp(base_time, 27)} server3 systemd[1]: {error_service}.service: Unit entered failed state\n")
        f.write(f"{generate_timestamp(base_time, 30)} server3 systemd[1]: {error_service}.service: Service restart attempt\n")
        f.write(f"{generate_timestamp(base_time, 32)} server3 {error_service}[{error_pid+100}]: Started successfully with reduced memory allocation\n")
        
        # Normal operation resumed
        for i in range(35, 40):
            timestamp = generate_timestamp(base_time, i)
            entry = generate_log_entry(timestamp, "server3", False)
            f.write(entry + "\n")
    
    print(f"Generated sequential error log: {filename}")

if __name__ == "__main__":
    print("Generating sample syslog files for Syslog Analyzer testing...")
    generate_logs(200, error_rate=0.15)
    generate_sequential_errors("sample_error_sequence.log")
    print("Done!")