import random
from struct import pack, unpack

from define import ARCHITECTURE, WinDef


class HandleManager:
    numbers = numbers = list(range(1, 0x100000 + 1))
    used = []
    handle_infos = {}

    @classmethod
    def create_handle(cls):
        if not cls.numbers:
            return None
        chosen = random.choice(cls.numbers)
        cls.numbers.remove(chosen)
        cls.used.append(chosen)
        return chosen

    @classmethod
    def close_handle(cls, handle):
        if handle in cls.used:
            cls.used.remove(handle)
            cls.numbers.append(handle)
        else:
            print(f"handle {handle} was not used or does not exist.")

    @classmethod
    def get_info(cls, handle):
        return cls.handle_infos[handle]

    @classmethod
    def set_info(cls, handle, info):
        cls.handle_infos[handle] = info


def recvall(s, size, flags=0):
    buffer = bytearray(size)
    view = memoryview(buffer)
    pos = 0
    while pos < size:
        read = s.recv_into(view[pos:], size - pos, flags)
        if not read:
            continue  # IncompleteReadError(bytes(view[:pos]), size)
        pos += read
    return bytes(buffer)


class BinaryReader:
    def __init__(self, base):
        self.base = base

    def read_int8(self):
        result = recvall(self.base, 1)
        ret = unpack("<b", result)[0]
        return ret

    def read_int16(self):
        result = recvall(self.base, 2)
        ret = unpack("<h", result)[0]
        return ret

    def read_int32(self):
        result = recvall(self.base, 4)
        ret = unpack("<i", result)[0]
        return ret

    def read_int64(self):
        result = recvall(self.base, 8)
        ret = unpack("<q", result)[0]
        return ret

    def read_uint8(self):
        result = recvall(self.base, 1)
        ret = unpack("<B", result)[0]
        return ret

    def read_uint16(self):
        result = recvall(self.base, 2)
        ret = unpack("<H", result)[0]
        return ret

    def read_uint32(self):
        result = recvall(self.base, 4)
        ret = unpack("<I", result)[0]
        return ret

    def read_uint64(self):
        result = recvall(self.base, 8)
        ret = unpack("<Q", result)[0]
        return ret

    def read_string16(self):
        length = self.read_uint16()
        result = recvall(self.base, length)
        ret = result.decode()
        return ret


class BinaryWriter:
    def __init__(self, base):
        self.base = base

    def write_int8(self, number):
        i8 = pack("<b", number)
        self.base.sendall(i8)

    def write_int16(self, number):
        i16 = pack("<h", number)
        self.base.sendall(i16)

    def write_int32(self, number):
        i32 = pack("<i", number)
        self.base.sendall(i32)

    def write_int64(self, number):
        i64 = pack("<q", number)
        self.base.sendall(i64)

    def write_uint8(self, number):
        ui8 = pack("<B", number)
        self.base.sendall(ui8)

    def write_uint16(self, number):
        ui16 = pack("<H", number)
        self.base.sendall(ui16)

    def write_uint32(self, number):
        ui32 = pack("<I", number)
        self.base.sendall(ui32)

    def write_uint64(self, number):
        ui64 = pack("<Q", number)
        self.base.sendall(ui64)


class PipeReadEmulator:
    def __init__(self):
        self.index = 0
        self.read_message = b""

    def read_int8(self):
        result = self.read_message[self.index : self.index + 1]
        ret = unpack("<b", result)[0]
        self.read_message = self.read_message[self.index + 1 :]
        return ret

    def read_int16(self):
        result = self.read_message[self.index : self.index + 2]
        ret = unpack("<h", result)[0]
        self.read_message = self.read_message[self.index + 2 :]
        return ret

    def read_int32(self):
        result = self.read_message[self.index : self.index + 4]
        ret = unpack("<i", result)[0]
        self.read_message = self.read_message[self.index + 4 :]
        return ret

    def read_int64(self):
        result = self.read_message[self.index : self.index + 8]
        ret = unpack("<q", result)[0]
        self.read_message = self.read_message[self.index + 8 :]
        return ret

    def read_uint8(self):
        result = self.read_message[self.index : self.index + 1]
        ret = unpack("<B", result)[0]
        self.read_message = self.read_message[self.index + 1 :]
        return ret

    def read_uint16(self):
        result = self.read_message[self.index : self.index + 2]
        ret = unpack("<H", result)[0]
        self.read_message = self.read_message[self.index + 2 :]
        return ret

    def read_uint32(self):
        result = self.read_message[self.index : self.index + 4]
        ret = unpack("<I", result)[0]
        self.read_message = self.read_message[self.index + 4 :]
        return ret

    def read_uint64(self):
        result = self.read_message[self.index : self.index + 8]
        ret = unpack("<Q", result)[0]
        self.read_message = self.read_message[self.index + 8 :]
        return ret

    def get_message_size(self):
        return len(self.read_message)

    def write_message(self, message):
        self.read_message += message


class PipeWriteEmulator:
    def __init__(self):
        self.write_message = b""

    def write_int8(self, number):
        i8 = pack("<b", number)
        self.write_message += i8

    def write_int16(self, number):
        i16 = pack("<h", number)
        self.write_message += i16

    def write_int32(self, number):
        i32 = pack("<i", number)
        self.write_message += i32

    def write_int64(self, number):
        i64 = pack("<q", number)
        self.write_message += i64

    def write_uint8(self, number):
        ui8 = pack("<B", number)
        self.write_message += ui8

    def write_uint16(self, number):
        ui16 = pack("<H", number)
        self.write_message += ui16

    def write_uint32(self, number):
        ui32 = pack("<I", number)
        self.write_message += ui32

    def write_uint64(self, number):
        ui64 = pack("<Q", number)
        self.write_message += ui64

    def write_utf8_string(self, message):
        self.write_message += message.encode()

    def write_byte_array(self, message):
        self.write_message += message

    def read_message(self, size):
        ret = self.write_message[0:size]
        self.write_message = self.write_message[size:]
        return ret

    def get_message_size(self):
        return len(self.write_message)


def arch_to_number(arch):
    if arch == ARCHITECTURE.IA32.value:
        return 0
    elif arch == ARCHITECTURE.X64.value:
        return 1
    elif arch == ARCHITECTURE.ARM.value:
        return 2
    elif arch == ARCHITECTURE.ARM64.value:
        return 3


def protection_string_to_type(protectionstring):
    if protectionstring.find("s") != -1:
        return WinDef.MEM_MAPPED
    else:
        return WinDef.MEM_PRIVATE


def protection_string_to_protection(protectionstring):
    w = 0
    x = 0

    if protectionstring.find("x") != -1:
        x = True
    else:
        x = False

    if protectionstring.find("w") != -1:
        w = True
    else:
        w = False

    if x:
        # executable
        if w:
            return WinDef.PAGE_EXECUTE_READWRITE
        else:
            return WinDef.PAGE_EXECUTE_READ
    else:
        # not executable
        if w:
            return WinDef.PAGE_READWRITE
        else:
            return WinDef.PAGE_READONLY
