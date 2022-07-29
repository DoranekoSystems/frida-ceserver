import socket
import os
import sys
import re
import time
import threading
import struct
import paramiko


class ADBAutomation:
    def __init__(self, configJson):
        self.ceserver_path = configJson["ceserver_path"]
        self.frida_server_path = configJson["frida_server_path"]
        self.gdbserver_path = configJson["gdbserver_path"]

    def exec_ceserver(self):
        binary_name = self.ceserver_path.split("/")[-1]
        os.system("adb forward tcp:52734 tcp:52734")
        os.system(f"adb shell su -c pkill -f {binary_name}")
        os.system(f"start cmd /k adb shell su -c .{self.ceserver_path} -p 52734")

    def exec_frida_server(self):
        binary_name = self.frida_server_path.split("/")[-1]
        os.system(f"adb shell su -c pkill -f {binary_name}")
        os.system(f"start cmd /k adb shell su -c .{self.frida_server_path}")

    def exec_gdbserver(self):
        os.system("adb forward tcp:1234 tcp:1234")
        binary_name = self.gdbserver_path.split("/")[-1]
        os.system(f"adb shell su -c pkill -f {binary_name}")
        os.system(
            f"start cmd /k adb shell su -c .{self.gdbserver_path} --multi 0.0.0.0:1234"
        )


class SSHAutomation:
    def __init__(self, configJson):
        self.ip = configJson["ip"]
        self.username = configJson["username"]
        self.password = configJson["password"]

        self.ceserver_path = configJson["ceserver_path"]
        self.debugserver_path = configJson["debugserver_path"]

        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.WarningPolicy())
        self.client.connect(self.ip, username=self.username, password=self.password)

    def exec_ceserver(self):
        # check ceserver running
        stdin, stdout, stderror = self.client.exec_command(
            f"ps aux | grep -i {self.ceserver_path}"
        )
        for line in stdout:
            if line.find(f"{self.ceserver_path}") != -1 and line.find("grep") == -1:
                return
        stdin, stdout, stderror = self.client.exec_command(f"{self.ceserver_path}")
        for line in stdout:
            print(line, end="")
        for line in stderror:
            print(line, end="")

    def exec_debugserver(self):
        stdin, stdout, stderror = self.client.exec_command(
            f"{self.debugserver_path}  0.0.0.0:1234"
        )
        for line in stdout:
            print(line, end="")
        for line in stderror:
            print(line, end="")
