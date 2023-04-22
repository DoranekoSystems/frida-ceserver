import os
import sys
import frida


def on_message(message, data):
    print(f"sample:{message}")
