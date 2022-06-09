import socket
import os
import sys
import re
import time
import threading
import struct


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
