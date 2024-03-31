import socket
import struct


class LLDBAutomation:
    def __init__(self, server_ip, server_port):
        self.ip = server_ip
        self.lldb_server_port = server_port
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((server_ip, server_port))
        self.s.send(b"+")
        self.disable_ack()

    def disable_ack(self):
        self.s.send(b"$QStartNoAckMode#b0")
        self.s.recv(1)
        self.s.recv(4096)
        self.s.send(b"+")

    def calc_checksum(self, message):
        sum = 0
        for c in message:
            sum += ord(c)
        sum = sum % 256
        return f"{sum:02x}"

    def encode_message(self, message):
        encode_message = ""
        flag = False
        for i in range(len(message)):
            if message[i] == "*" and not flag:
                flag = True
                encode_message += message[i - 1] * (ord(message[i + 1]) - 29)
            else:
                if not flag:
                    encode_message += message[i]
                else:
                    flag = False
        return encode_message

    def send_message(self, message, recvflag=True):
        m = "$" + message + "#" + self.calc_checksum(message)
        self.s.send(m.encode())
        if recvflag:
            result = self.s.recv(4096)
            # ignore $***#hh
            return result[1:-3]

    def attach(self, pid):
        self.send_message(f"vAttach;{pid:02x}")
        self.attach_pid = pid

    def cont(self):
        result = self.send_message("c")
        return result

    def cont2(self, signal, thread):
        result = self.send_message(f"vCont;C{signal:02x}:{thread:02x};c")
        return result

    def step(self, thread):
        result = self.send_message(f"vCont;s:{thread:02x}")
        return result

    def readmem(self, address, size):
        result = self.send_message(f"x{address:02x},{size}")
        return result

    def writemem(self, address, size, buffer_list):
        buffer = "".join("{:02x}".format(x) for x in buffer_list)
        result = self.send_message(f"M{address:02x},{size}:{buffer}")
        if result == b"OK":
            return True
        else:
            return False

    def get_register_info(self, thread):
        message = self.send_message(f"g;thread:{thread}").decode()
        return self.encode_message(message)

    def read_register(self, regnum):
        result = self.send_message(f"p{regnum:02x}")
        if regnum == 33:
            value = struct.unpack("<I", bytes.fromhex(result.decode()))[0]
        else:
            value = struct.unpack("<Q", bytes.fromhex(result.decode()))[0]
        return value

    def write_register(self, regnum, value):
        result = self.send_message(f"P{regnum:02x}={value}")
        if result == b"OK":
            return True
        else:
            return False

    # 2:write 3:read 4:access
    def set_watchpoint(self, address, size, _type):
        command = ""
        if _type == "x":
            command = "Z0"
        elif _type == "w":
            command = "Z2"
        elif _type == "r":
            command = "Z3"
        elif _type == "a":
            command = "Z4"
        result = self.send_message(f"{command},{address:02x},{size}")
        if result == b"OK":
            return True
        else:
            # Already set breakpoint
            if result == b"E09":
                return True
            else:
                return False

    def remove_watchpoint(self, address, size, _type):
        command = ""
        if _type == "x":
            command = "z0"
        elif _type == "w":
            command = "z2"
        elif _type == "r":
            command = "z3"
        elif _type == "a":
            command = "z4"
        result = self.send_message(f"{command},{address:02x},{size}")
        if result == b"OK":
            return True
        else:
            # Already remove breakpoint
            if result == b"E08":
                return True
            elif result == b"":
                return True
            else:
                return False

    def parse_result(self, result):
        _dict = {}
        for r in result.decode().split(";"):
            if r.find(":") != -1:
                key, value = r.split(":")
                if key == "medata" and key in _dict:
                    if int(value, 16) > int(_dict[key], 16):
                        _dict[key] = value
                else:
                    _dict[key] = value
        return _dict

    def interrupt(self):
        self.send_message("\x03", False)
