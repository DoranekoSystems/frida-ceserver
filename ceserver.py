import bisect
import importlib.util
import json
import os
import platform
import queue
import socket
import subprocess
import threading
import time
import zlib
from enum import IntEnum
from struct import pack, unpack

import lz4.block
from packaging.version import parse

import mono_pipeserver
from define import ARCHITECTURE, MODE, OS
from lldbauto import LLDBAutomation
from util import HandleManager

PID = 0
API = 0
EXTEND_API = 0
SYMBOL_API = 0
DEVICE = 0
_MODE = 0
CONFIG = 0
ARCH = 0
SESSION = 0
CEVERSION = ""
TARGETOS = 0
MANUAL_PARSER = 0
JAVA_DISSECT = 0
NATIVE_CESERVER_IP = 0
CUSTOM_SYMBOL_LOADER = []
DEBUGSERVER_IP = 0
CUSTOM_READ_MEMORY = 0
DATA_COLLECTOR = 0

PROCESSES = []
LLDB = 0
LLDB_REGISTER_COUNT = 255
DEBUG_EVENT = []
REGISTER_INFO = []
WP_INFO_LIST = [
    {
        "address": 0,
        "bpsize": 0,
        "type": 0,
        "switch": False,
        "enabled": False,
    }
    for i in range(LLDB_REGISTER_COUNT)
]
CONTINUE_QUEUE = queue.Queue()
IS_STOPPED = False

Lock = threading.Lock()

PROCESS_ALL_ACCESS = 0x1F0FFF

TH32CS_SNAPPROCESS = 0x2
TH32CS_SNAPTHREAD = 0x4
TH32CS_SNAPMODULE = 0x8

PAGE_NOACCESS = 1
PAGE_READONLY = 2
PAGE_READWRITE = 4
PAGE_WRITECOPY = 8
PAGE_EXECUTE = 16
PAGE_EXECUTE_READ = 32
PAGE_EXECUTE_READWRITE = 64

MEM_MAPPED = 262144
MEM_PRIVATE = 131072

PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4

MAP_SHARED = 1
MAP_PRIVATE = 2
MAP_ANONYMOUS = 32

VQE_PAGEDONLY = 1
VQE_DIRTYONLY = 2
VQE_NOSHARED = 4

RegionList = None
ModuleList = None
ModuleListIterator = 0


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
        return MEM_MAPPED
    else:
        return MEM_PRIVATE


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
            return PAGE_EXECUTE_READWRITE
        else:
            return PAGE_EXECUTE_READ
    else:
        # not executable
        if w:
            return PAGE_READWRITE
        else:
            return PAGE_READONLY


def virtualqueryex(address):
    global RegionList
    if RegionList is None:
        RegionList = API.VirtualQueryExFull(VQE_NOSHARED)
    lp_address = address
    sorts = [region[0] + region[1] for region in RegionList]
    index = bisect.bisect_left(sorts, lp_address + 1)
    if index == len(sorts):
        return False
    start = int(RegionList[index][0])
    if start <= lp_address:
        base = lp_address
        size = RegionList[index][1]
        protection = RegionList[index][2]
        _type = RegionList[index][3]
        filename = RegionList[index][4]
        return [base, size, protection, _type, filename]
    else:
        base = lp_address
        size = start - lp_address
        protection = PAGE_NOACCESS
        _type = 0
        filename = ""
        return [base, size, protection, _type, filename]


def module32first():
    global ModuleList
    global ModuleListIterator
    if ModuleList is None:
        ModuleList = API.EnumModules()
    ModuleListIterator = 0
    base = ModuleList[0]["base"]
    size = ModuleList[0]["size"]
    name = ModuleList[0]["name"]
    ModuleListIterator += 1
    return [base, size, name]


def module32next():
    global ModuleListIterator
    if len(ModuleList) > ModuleListIterator:
        base = ModuleList[ModuleListIterator]["base"]
        size = ModuleList[ModuleListIterator]["size"]
        name = ModuleList[ModuleListIterator]["name"]
        ModuleListIterator += 1
        return [base, size, name]
    else:
        return False


class CECMD(IntEnum):
    CMD_GETVERSION = 0
    CMD_CLOSECONNECTION = 1
    CMD_TERMINATESERVER = 2
    CMD_OPENPROCESS = 3
    CMD_CREATETOOLHELP32SNAPSHOT = 4
    CMD_PROCESS32FIRST = 5
    CMD_PROCESS32NEXT = 6
    CMD_CLOSEHANDLE = 7
    CMD_VIRTUALQUERYEX = 8
    CMD_READPROCESSMEMORY = 9
    CMD_WRITEPROCESSMEMORY = 10
    CMD_STARTDEBUG = 11
    CMD_STOPDEBUG = 12
    CMD_WAITFORDEBUGEVENT = 13
    CMD_CONTINUEFROMDEBUGEVENT = 14
    CMD_SETBREAKPOINT = 15
    CMD_REMOVEBREAKPOINT = 16
    CMD_SUSPENDTHREAD = 17
    CMD_RESUMETHREAD = 18
    CMD_GETTHREADCONTEXT = 19
    CMD_SETTHREADCONTEXT = 20
    CMD_GETARCHITECTURE = 21
    CMD_MODULE32FIRST = 22
    CMD_MODULE32NEXT = 23
    CMD_GETSYMBOLLISTFROMFILE = 24
    CMD_LOADEXTENSION = 25
    CMD_ALLOC = 26
    CMD_FREE = 27
    CMD_CREATETHREAD = 28
    CMD_LOADMODULE = 29
    CMD_SPEEDHACK_SETSPEED = 30
    CMD_VIRTUALQUERYEXFULL = 31
    CMD_GETREGIONINFO = 32
    CMD_GETABI = 33
    CMD_SET_CONNECTION_NAME = 34
    CMD_CREATETOOLHELP32SNAPSHOTEX = 35
    CMD_CHANGEMEMORYPROTECTION = 36
    CMD_GETOPTIONS = 37
    CMD_GETOPTIONVALUE = 38
    CMD_SETOPTIONVALUE = 39
    CMD_PTRACE_MMAP = 40
    CMD_OPENNAMEDPIPE = 41
    CMD_PIPEREAD = 42
    CMD_PIPEWRITE = 43
    CMD_GETCESERVERPATH = 44
    CMD_ISANDROID = 45
    CMD_AOBSCAN = 200
    CMD_COMMANDLIST2 = 255


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


def get_symbollist_from_file(filename, output):
    if TARGETOS in [OS.LINUX.value, OS.ANDROID.value] and MANUAL_PARSER:
        ret = SYMBOL_API.GetSymbolListFromFile(filename)
    else:
        ret = API.GetSymbolListFromFile(filename)
    if len(CUSTOM_SYMBOL_LOADER) > 0:
        for symbolfile, filepath in CUSTOM_SYMBOL_LOADER.items():
            if symbolfile == filename:
                with open(filepath, encoding="utf-8") as f:
                    jdict = json.loads(f.read().replace("\n", ""))
                    script_method = sorted(
                        jdict["ScriptMethod"], key=lambda x: x["Address"]
                    )
                    for i, method in enumerate(script_method):
                        baseaddress = method["Address"]
                        if i == len(script_method) - 1:
                            size = 8
                        else:
                            size = (
                                script_method[i + 1]["Address"]
                                - script_method[i]["Address"]
                            )
                        _type = 0
                        name = method["Name"]
                        ret.append([baseaddress, size, _type, name])
    if ret and len(ret) > 0:
        bytecode = b""
        for i in range(len(ret)):
            baseaddress = ret[i][0]
            size = ret[i][1]
            _type = 0
            name = ret[i][3].encode()
            if len(name) > 127:
                name = name[0:127]
            namelength = len(name)
            try:
                tmp = pack(
                    "<Qiib" + str(namelength) + "s",
                    baseaddress,
                    size,
                    _type,
                    namelength,
                    name,
                )
                bytecode = b"".join([bytecode, tmp])
            except Exception:
                pass
        compress_data = zlib.compress(bytecode)
        sendall_data = pack("<iii", 0, len(compress_data) + 12, len(bytecode))
        sendall_data += compress_data
        output[0] = sendall_data
    else:
        output[0] = b"\x00\x00\x00\x00\x00\x00\x00\x00"


def interrupt_func():
    while True:
        Lock.acquire()
        if (
            len(
                [
                    wp
                    for wp in WP_INFO_LIST
                    if (wp["switch"] and not wp["enabled"])
                    or (not wp["switch"] and wp["enabled"])
                ]
            )
            > 0
        ):
            LLDB.interrupt()
        Lock.release()
        time.sleep(0.25)


def debugger_thread():
    global REGISTER_INFO
    global WP_INFO_LIST
    global IS_STOPPED

    signal = -1
    thread = -1
    is_debugserver = TARGETOS == OS.IOS.value or TARGETOS == OS.MAC.value
    while True:
        IS_STOPPED = True
        c = CONTINUE_QUEUE.get(block=True)
        IS_STOPPED = False
        if c[0] == 1:
            result = LLDB.cont()
        elif c[0] == 2:
            threadid = c[1]
            result = LLDB.step(threadid)
        Lock.acquire()
        info = LLDB.parse_result(result)
        if is_debugserver:
            if "metype" not in info:
                print("Debugger Thread:info is empty.")
                Lock.release()
                continue
            metype = info["metype"]
            threadid = int(
                [info[x] for x in info.keys() if x.find("thread") != -1][0], 16
            )
        else:
            try:
                tkey = [
                    x
                    for x in info.keys()
                    if (x.find("T") == 0 and x.find("thread") != -1)
                ][0]
            except Exception:
                print("Debugger Thread:info is empty.")
                Lock.release()
                continue
            thread = int(info[tkey], 16)
            threadid = thread
            signal = int([x for x in info.keys() if x.find("T") == 0][0][1:3], 16)
            if info["reason"] == "watchpoint":
                # watchpoint
                metype = "6"
            else:
                # breakpoint
                if signal == 5:
                    metype = "6"
                else:
                    metype = "5"

        # Breadkpoint Exception
        if metype == "6":
            if is_debugserver:
                medata = int(info["medata"], 16)
                if medata == 1:  # Breakpoint
                    address = unpack("<Q", bytes.fromhex(info["20"]))[0]
                    medata = address
                else:  # Watchpoint
                    medata = int(info["medata"], 16)
            else:
                # watchpoint
                if info["reason"] == "watchpoint":
                    description = info["description"]
                    ascii_string = bytearray.fromhex(description).decode()
                    extracted_sequence = ascii_string.split()[0]
                    medata = int(extracted_sequence)
                # breakpoint
                else:
                    address = unpack(
                        "<Q", bytes.fromhex(LLDB.encode_message(info["20"]))
                    )[0]
                    medata = address

            if medata > 0x100000:
                register_list = []
                if ARCH == ARCHITECTURE.ARM64.value:
                    for i in range(34):
                        try:
                            if i == 33:
                                address = unpack("<I", bytes.fromhex(info[f"{i:02x}"]))[
                                    0
                                ]
                            else:
                                address = unpack("<Q", bytes.fromhex(info[f"{i:02x}"]))[
                                    0
                                ]

                        except Exception:
                            address = 0
                        register_list.append(address)
                else:
                    pass

                event = {
                    "debugevent": 5,
                    "threadid": threadid,
                    "address": medata,
                    "register": register_list,
                }
                DEBUG_EVENT.append(event)

        if metype == "5" or metype == "6":
            setflag = False
            # set watchpoint
            for i in range(LLDB_REGISTER_COUNT):
                wp = WP_INFO_LIST[i]
                if wp["switch"] and not wp["enabled"]:
                    address = wp["address"]
                    size = wp["bpsize"]
                    _type = wp["type"]
                    print(
                        f"SetWatchpoint:Address:0x{address:02x},Size:{size},Type:{_type}"
                    )
                    ret = LLDB.set_watchpoint(address, size, _type)
                    print(f"Result:{ret}")
                    if ret:
                        WP_INFO_LIST[i]["enabled"] = True
                    setflag = True

            # remove watchpoint
            for i in range(LLDB_REGISTER_COUNT):
                wp = WP_INFO_LIST[i]
                if not wp["switch"] and wp["enabled"]:
                    address = wp["address"]
                    size = wp["bpsize"]
                    _type = wp["type"]
                    print(
                        f"RemoveWatchpoint:Address:0x{address:02x},Size:{size},Type:{_type}"
                    )
                    ret = LLDB.remove_watchpoint(address, size, _type)
                    print(f"Result:{ret}")
                    if ret:
                        WP_INFO_LIST[i]["enabled"] = False
                    setflag = True
            if setflag:
                CONTINUE_QUEUE.put([1, threadid])

        Lock.release()


script_dict = {}


def load_frida_script(jscode, number_str, filename=""):
    global script_dict
    session = SESSION
    script = session.create_script(jscode)

    if filename != "":
        spec = importlib.util.spec_from_file_location("callback", filename)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        script.on("message", module.on_message)
    else:

        def on_message(message, data):
            print(message)

        script.on("message", on_message)
    script.load()
    script_dict[number_str] = script


def unload_frida_script(number_str):
    global script_dict
    script = script_dict[number_str]
    script.unload()
    script_dict.pop(number_str)


def handler(ns, nc, command, thread_count):
    global process_id
    global LLDB
    global REGISTER_INFO
    global WP_INFO_LIST
    global CONTINUE_QUEUE
    global PROCESSES
    global SESSION
    global PID
    global API
    global SYMBOL_API

    reader = BinaryReader(ns)
    writer = BinaryWriter(ns)
    reader2 = BinaryReader(nc)
    writer2 = BinaryWriter(nc)

    # print(str(thread_count) + ":" + str(CECMD(command).name))
    if command == CECMD.CMD_CREATETOOLHELP32SNAPSHOT:
        dw_flags = reader.read_int32()
        pid = reader.read_int32()
        h_snapshot = HandleManager.create_handle()
        writer.write_int32(h_snapshot)

    elif command == CECMD.CMD_CREATETOOLHELP32SNAPSHOTEX:
        dw_flags = reader.read_int32()
        pid = reader.read_int32()
        bytecode = b""
        if dw_flags & TH32CS_SNAPMODULE == TH32CS_SNAPMODULE:
            ret = module32first()
            while True:
                if ret:
                    modulename = ret[2].encode()
                    modulenamesize = len(modulename)
                    modulebase = int(ret[0], 16)
                    modulepart = 0
                    modulesize = ret[1]
                    if parse(CEVERSION) >= parse("7.5.1"):
                        tmp = pack(
                            "<iQIIII" + str(modulenamesize) + "s",
                            1,
                            modulebase,
                            modulepart,
                            modulesize,
                            0,
                            modulenamesize,
                            modulename,
                        )
                    else:
                        tmp = pack(
                            "<iQIII" + str(modulenamesize) + "s",
                            1,
                            modulebase,
                            modulepart,
                            modulesize,
                            modulenamesize,
                            modulename,
                        )
                    bytecode = b"".join([bytecode, tmp])
                else:
                    break
                ret = module32next()
            if parse(CEVERSION) >= parse("7.5.1"):
                tmp = pack("<iQIIII", 0, 0, 0, 0, 0, 0)
            else:
                tmp = pack("<iQIII", 0, 0, 0, 0, 0)
            bytecode = b"".join([bytecode, tmp])
            ns.sendall(bytecode)
        elif dw_flags & TH32CS_SNAPTHREAD == TH32CS_SNAPTHREAD:
            idlist = API.GetThreadList()
            writer.write_int32(len(idlist))
            for id in idlist:
                writer.write_int32(id)
        else:
            h_snapshot = HandleManager.create_handle()
            writer.write_int32(h_snapshot)

    elif command == CECMD.CMD_PROCESS32FIRST or command == CECMD.CMD_PROCESS32NEXT:
        h_snapshot = reader.read_int32()
        # print("hSnapshot:" + str(h_snapshot))
        if command == CECMD.CMD_PROCESS32FIRST:
            if _MODE == MODE.ENUM.value:
                PROCESSES = DEVICE.enumerate_processes()
                process = PROCESSES.pop(0)
                if len(PROCESSES) == 0:
                    ret = 0
                else:
                    ret = 1
            else:
                ret = 1
        else:
            if _MODE == MODE.ENUM.value:
                process = PROCESSES.pop(0)
                if len(PROCESSES) == 0:
                    ret = 0
                else:
                    ret = 1
            else:
                ret = 0
        if ret != 0:
            if _MODE == MODE.ENUM.value:
                processname = process.name.encode()
                processnamesize = len(processname)
                _pid = process.pid
            else:
                processname = "self".encode()
                processnamesize = len(processname)
                _pid = PID
            bytecode = pack(
                "<iii" + str(processnamesize) + "s",
                ret,
                _pid,
                processnamesize,
                processname,
            )
            ns.sendall(bytecode)
        else:
            bytecode = pack("<iii", 0, 0, 0)
            ns.sendall(bytecode)

    elif command == CECMD.CMD_MODULE32FIRST or command == CECMD.CMD_MODULE32NEXT:
        h_snapshot = reader.read_int32()
        if command == CECMD.CMD_MODULE32FIRST:
            ret = module32first()
        else:
            ret = module32next()
        if ret:
            modulename = ret[2].encode()
            modulenamesize = len(modulename)
            modulebase = int(ret[0], 16)
            modulepart = 0
            modulesize = ret[1]
            if parse(CEVERSION) >= parse("7.5.1"):
                bytecode = pack(
                    "<iQIIII" + str(modulenamesize) + "s",
                    1,
                    modulebase,
                    modulepart,
                    modulesize,
                    0,
                    modulenamesize,
                    modulename,
                )
            elif parse(CEVERSION) >= parse("7.3.1"):
                bytecode = pack(
                    "<iQIII" + str(modulenamesize) + "s",
                    1,
                    modulebase,
                    modulepart,
                    modulesize,
                    modulenamesize,
                    modulename,
                )
            else:
                bytecode = pack(
                    "<iQII" + str(modulenamesize) + "s",
                    1,
                    modulebase,
                    modulesize,
                    modulenamesize,
                    modulename,
                )
            ns.sendall(bytecode)
        else:
            if parse(CEVERSION) >= parse("7.3.1"):
                bytecode = pack("<iQIII", 0, 0, 0, 0, 0)
            else:
                bytecode = pack("<iQII", 0, 0, 0, 0)
            ns.sendall(bytecode)

    elif command == CECMD.CMD_CLOSEHANDLE:
        reader.read_int32()
        # CloseHandle(h)
        writer.write_int32(1)

    elif command == CECMD.CMD_OPENPROCESS:
        pid = reader.read_int32()
        if nc != 0:
            writer2.write_uint8(CECMD.CMD_OPENPROCESS)
            writer2.write_int32(pid)
            processhandle = reader2.read_int32()
        else:
            processhandle = HandleManager.create_handle()

            if _MODE == MODE.ENUM.value:

                def on_message(message, data):
                    print(message)

                SESSION = DEVICE.attach(pid)
                if TARGETOS == OS.WINDOWS.value:
                    with open("javascript/core_win.js", "r") as f:
                        jscode = f.read()
                else:
                    with open("javascript/core.js", "r") as f:
                        jscode = f.read()
                    with open("javascript/symbol.js", "r") as f:
                        jscode2 = f.read()
                script = SESSION.create_script(jscode)
                script.on("message", on_message)
                script.load()
                api = script.exports_sync
                api.SetConfig(CONFIG)
                symbol_api = 0
                if TARGETOS != OS.WINDOWS.value:
                    script2 = SESSION.create_script(jscode2)
                    script2.on("message", on_message)
                    script2.load()
                    symbol_api = script2.exports_sync
                if JAVA_DISSECT:
                    if TARGETOS in [OS.ANDROID.value, OS.IOS.value]:
                        print("javaDissect Enabled")
                        import java_pipeserver as javapipe

                        jthread = threading.Thread(
                            target=javapipe.pipeserver,
                            args=(
                                process_id,
                                SESSION,
                            ),
                            daemon=True,
                        )
                        jthread.start()
                PID = pid
                API = api
                SYMBOL_API = symbol_api
                if DATA_COLLECTOR == "mono" or DATA_COLLECTOR == "objc":
                    mono_pipeserver.mono_init(SESSION, DATA_COLLECTOR)
        print("Processhandle:" + str(processhandle))
        writer.write_int32(processhandle)

    elif command == CECMD.CMD_GETARCHITECTURE:
        if parse(CEVERSION) >= parse("7.4.1"):
            handle = reader.read_int32()
        arch_number = arch_to_number(ARCH)
        writer.write_int8(arch_number)

    elif command == CECMD.CMD_SET_CONNECTION_NAME:
        size = reader.read_int32()
        name = ns.recv(size).decode()
        print(f"This thread is called {name}")

    elif command == CECMD.CMD_READPROCESSMEMORY:
        handle = reader.read_uint32()
        address = reader.read_uint64()
        size = reader.read_uint32()
        compress = reader.read_int8()
        if nc != 0:
            writer2.write_uint8(CECMD.CMD_READPROCESSMEMORY)
            writer2.write_uint32(handle)
            writer2.write_uint64(address)
            writer2.write_uint32(size)
            writer2.write_int8(compress)
            if compress == 0:
                read = reader2.read_uint32()
                if read == 0:
                    ret = False
                else:
                    ret = b""
                    while True:
                        ret += nc.recv(4096)
                        if len(ret) == read:
                            break
            else:
                uncompressed_size = reader2.read_uint32()
                compressed_size = reader2.read_uint32()
                if compressed_size == 0:
                    ret = False
                else:
                    ret = b""
                    while True:
                        ret += nc.recv(4096)
                        if len(ret) == compressed_size:
                            break
        else:
            ret = API.ReadProcessMemory(address, size)
        if compress == 0:
            if ret:
                # iOS
                if CUSTOM_READ_MEMORY and TARGETOS == OS.IOS.value:
                    decompress_bytes = b""
                    tmp = ret
                    last_uncompressed = b""
                    # todo:bv4-
                    while True:
                        if (tmp[0:4] != b"bv41") or (tmp[0:4] == b"bv4$"):
                            break
                        uncompressed_size, compressed_size = unpack("<II", tmp[4:12])
                        last_uncompressed = lz4.block.decompress(
                            tmp[12 : 12 + compressed_size],
                            uncompressed_size,
                            dict=last_uncompressed,
                        )
                        tmp = tmp[12 + compressed_size :]
                        decompress_bytes += last_uncompressed
                    ret = decompress_bytes
                # Android
                elif CUSTOM_READ_MEMORY and TARGETOS == OS.ANDROID.value:
                    uncompressed_size = unpack("<I", ret[-4:])[0]
                    decompress_bytes = lz4.block.decompress(ret[:-4], uncompressed_size)
                    ret = decompress_bytes
                writer.write_int32(len(ret))
                ns.sendall(ret)
            else:
                writer.write_int32(0)
        else:
            if ret:
                if nc != 0:
                    compress_data = ret
                else:
                    uncompressed_size = len(ret)
                    compress_data = zlib.compress(ret, level=compress)
                writer.write_int32(uncompressed_size)
                writer.write_int32(len(compress_data))
                ns.sendall(compress_data)
            else:
                writer.write_int32(0)
                writer.write_int32(0)

    elif command == CECMD.CMD_WRITEPROCESSMEMORY:
        handle = reader.read_uint32()
        address = reader.read_uint64()
        size = reader.read_uint32()
        if size > 0:
            _buf = ns.recv(size)
            # extended functionality
            # Addresses 0 to 100 will interpret the written content as frida javascript code and execute the script.
            if 0 <= address <= 100:
                if _buf.find("UNLOAD".encode()) != 0:
                    message = _buf.decode()
                    jscode = "?".join(message.split("?")[:-1])
                    pyfilename = message.split("?")[-1]
                    if pyfilename != "":
                        filename = os.path.join("callback", pyfilename)
                    else:
                        filename = ""
                    load_frida_script(jscode, str(address), filename)
                else:
                    if str(address) in script_dict:
                        unload_frida_script(str(address))
                ret = True
            else:
                # Address == 0xFFFFFFFFFFFFFFFF => ExtendCommand
                if address == 0xFFFFFFFFFFFFFFFF:
                    message = _buf.decode()
                    jdict = json.loads(message)
                    command = jdict["command"]
                    if command == "HexEditor":
                        watch_address = int(jdict["address"], 16)

                        def run():
                            hostos = platform.system()
                            if hostos == "Darwin":
                                from applescript import tell

                                cwd = os.getcwd()
                                pycmd = f"python3 main.py -p {PID} --memoryview {hex(watch_address)}"
                                tell.app(
                                    "Terminal",
                                    'do script "' + f"cd {cwd};{pycmd}" + '"',
                                )
                            elif hostos == "Windows":
                                subprocess.call(
                                    f"python main.py -p {PID} --memoryview {hex(watch_address)}",
                                    creationflags=subprocess.CREATE_NEW_CONSOLE,
                                )
                            else:
                                print("Not Support")

                        t1 = threading.Thread(target=run)
                        t1.start()
                    ret = True
                else:
                    if IS_STOPPED:
                        ret = LLDB.writemem(address, len(_buf), list(_buf))
                    else:
                        ret = API.WriteProcessMemory(address, list(_buf))
            if ret:
                writer.write_int32(size)
            else:
                writer.write_int32(0)
        else:
            writer.write_int32(0)

    elif command == CECMD.CMD_VIRTUALQUERYEXFULL:
        handle = reader.read_int32()
        flags = reader.read_int8()
        address = 0
        sendbyte_code = b""
        region_size = 0
        if IS_STOPPED:
            ret = RegionList
        else:
            ret = API.VirtualQueryExFull(flags)
        region_size = len(ret)
        for ri in ret:
            protection = ri[2]
            baseaddress = ri[0]
            _type = ri[3]
            size = ri[1]
            bytecode = pack("<QQII", baseaddress, size, protection, _type)
            sendbyte_code += bytecode
        writer.write_int32(region_size)
        ns.sendall(sendbyte_code)

    elif command == CECMD.CMD_VIRTUALQUERYEX:
        handle = reader.read_int32()
        baseaddress = reader.read_uint64()
        ret = virtualqueryex(baseaddress)
        if ret:
            protection = ret[2]
            baseaddress = ret[0]
            _type = ret[3]
            size = ret[1]
            bytecode = pack("<bIIQQ", 1, protection, _type, baseaddress, size)
            ns.sendall(bytecode)
        else:
            protection = 0
            baseaddress = 0
            _type = 0
            size = 0
            bytecode = pack("<bIIQQ", 0, protection, _type, baseaddress, size)
            ns.sendall(bytecode)

    elif command == CECMD.CMD_GETREGIONINFO:
        handle = reader.read_int32()
        baseaddress = reader.read_uint64()
        ret = virtualqueryex(baseaddress)
        if ret:
            protection = ret[2]
            baseaddress = ret[0]
            _type = ret[3]
            size = ret[1]
            bytecode = pack("<bIIQQ", 1, protection, _type, baseaddress, size)
            ns.sendall(bytecode)
            filename = ret[4]
            filenamesize = len(filename)
            writer.write_uint8(filenamesize)
            ns.sendall(filename.encode())
        else:
            protection = 0
            baseaddress = 0
            _type = 0
            size = 0
            bytecode = pack("<bIIQQ", 0, protection, _type, baseaddress, size)
            ns.sendall(bytecode)
            writer.write_int8(0)

    elif command == CECMD.CMD_TERMINATESERVER:
        ns.close()
        return -1

    elif command == CECMD.CMD_GETVERSION:
        if parse(CEVERSION) >= parse("7.5.1"):
            version = 6
            versionstring = "CHEATENGINE Network 2.3".encode()
        elif parse(CEVERSION) >= parse("7.4.3"):
            version = 5
            versionstring = "CHEATENGINE Network 2.2".encode()
        elif parse(CEVERSION) >= parse("7.4.2"):
            version = 4
            versionstring = "CHEATENGINE Network 2.2".encode()
        elif parse(CEVERSION) >= parse("7.3.2"):
            version = 2
            versionstring = "CHEATENGINE Network 2.1".encode()
        else:
            version = 1
            versionstring = "CHEATENGINE Network 2.0".encode()
        versionsize = len(versionstring)
        bytecode = pack(
            "<ib" + str(versionsize) + "s", version, versionsize, versionstring
        )
        ns.sendall(bytecode)

    elif command == CECMD.CMD_GETSYMBOLLISTFROMFILE:
        if parse(CEVERSION) >= parse("7.5.1"):
            reader.read_uint32()
            symbolpathsize = reader.read_uint32()
            symbolname = ns.recv(symbolpathsize).decode()
            output = [0]
            get_symbollist_from_file(symbolname, output)
        else:
            symbolpathsize = reader.read_int16()
            symbolname = ns.recv(symbolpathsize + 2).decode()
            output = [0]
            get_symbollist_from_file(symbolname[2:], output)
        ns.sendall(output[0])

    elif command == CECMD.CMD_LOADEXTENSION:
        handle = reader.read_int32()
        writer.write_int32(1)

    elif command == CECMD.CMD_SPEEDHACK_SETSPEED:
        handle = reader.read_int32()
        data = ns.recv(4)
        speedratio = unpack("<f", data)[0]
        r = API.ExtSetSpeed(speedratio)
        writer.write_int32(r)

    elif command == CECMD.CMD_ALLOC:
        handle = reader.read_int32()
        prefered_base = reader.read_uint64()
        size = reader.read_int32()
        address = API.ExtAlloc(prefered_base, size)
        writer.write_uint64(address)

    elif command == CECMD.CMD_FREE:
        handle = reader.read_int32()
        address = reader.read_uint64()
        size = reader.read_int32()
        r = API.ExtFree(address, size)
        writer.write_int32(r)

    elif command == CECMD.CMD_LOADMODULE:
        handle = reader.read_int32()
        modulepathlength = reader.read_int32()
        modulepath = ns.recv(modulepathlength).decode()
        if modulepath.find("libMonoDataCollector") != -1:
            writer.write_uint64(0x7FFFDEADBEAF)
        else:
            r = API.ExtLoadModule(modulepath)
            writer.write_uint64(r)

    elif command == CECMD.CMD_CREATETHREAD:
        handle = reader.read_int32()
        startaddress = reader.read_uint64()
        parameter = reader.read_uint64()
        r = API.ExtCreateThread(startaddress, parameter)
        threadhandle = HandleManager.create_handle()
        writer.write_int32(threadhandle)

    elif command == CECMD.CMD_GETABI:
        writer.write_int8(1)

    elif command == CECMD.CMD_STARTDEBUG:
        handle = reader.read_int32()
        target_ip = DEBUGSERVER_IP.split(":")[0]
        target_port = int(DEBUGSERVER_IP.split(":")[1])

        LLDB = LLDBAutomation(target_ip, target_port)
        LLDB.attach(PID)
        t1 = threading.Thread(target=debugger_thread)
        t1.start()
        t2 = threading.Thread(target=interrupt_func)
        t2.start()

        event = {
            "debugevent": -2,
            "threadid": PID,
            "maxBreakpointCount": LLDB_REGISTER_COUNT,
            "maxWatchpointCount": 4,
            "maxSharedBreakpoints": LLDB_REGISTER_COUNT,
        }
        DEBUG_EVENT.append(event)
        writer.write_int32(1)

    elif command == CECMD.CMD_WAITFORDEBUGEVENT:
        handle = reader.read_int32()
        timeout = reader.read_int32()
        if len(DEBUG_EVENT) > 0:
            writer.write_int32(1)
            event = DEBUG_EVENT.pop()
            debugevent = event["debugevent"]
            threadid = event["threadid"]
            if debugevent == -2:
                writer.write_int32(debugevent)
                writer.write_int64(threadid)
                writer.write_uint8(event["maxBreakpointCount"])
                writer.write_int8(event["maxWatchpointCount"])
                writer.write_uint8(event["maxSharedBreakpoints"])
                ns.sendall(b"\x00" * 5)
            elif debugevent == 5:
                REGISTER_INFO = event["register"]
                writer.write_int32(debugevent)
                writer.write_int64(threadid)
                writer.write_uint64(event["address"])
        else:
            time.sleep(timeout / (1000 * 20))
            writer.write_int32(0)

    elif command == CECMD.CMD_CONTINUEFROMDEBUGEVENT:
        handle = reader.read_int32()
        tid = reader.read_int32()
        ignore = reader.read_int32()
        CONTINUE_QUEUE.put([ignore, tid])
        writer.write_int32(1)

    elif command == CECMD.CMD_SETBREAKPOINT:
        handle = reader.read_int32()
        tid = reader.read_int32()
        debugreg = reader.read_int32()
        address = reader.read_uint64()
        bptype = reader.read_int32()
        bpsize = reader.read_int32()

        wp = WP_INFO_LIST[debugreg]
        # auto
        if tid != -1:
            if IS_STOPPED:
                LLDB.set_watchpoint(address, wp["bpsize"], wp["type"])
            writer.write_int32(1)
        # manual
        else:
            if not wp["switch"] and not wp["enabled"]:
                _type = ""
                if bptype == 0:
                    _type = "x"
                    bpsize = 4
                elif bptype == 1:
                    _type = "w"
                elif bptype == 2:
                    _type = "r"
                elif bptype == 3:
                    _type = "a"
                if IS_STOPPED:
                    ret = LLDB.set_watchpoint(address, bpsize, _type)
                    enabled = True
                else:
                    print("CMD_SETBREAKPOINT")
                    enabled = False
                bp = {
                    "address": address,
                    "bpsize": bpsize,
                    "type": _type,
                    "switch": True,
                    "enabled": enabled,
                }
                WP_INFO_LIST[debugreg] = bp
                writer.write_int32(1)
            else:
                writer.write_int32(0)

    elif command == CECMD.CMD_REMOVEBREAKPOINT:
        handle = reader.read_int32()
        tid = reader.read_int32()
        debugreg = reader.read_int32()
        reader.read_int32()
        wp = WP_INFO_LIST[debugreg]
        if tid != -1:
            if IS_STOPPED:
                LLDB.remove_watchpoint(wp["address"], wp["bpsize"], wp["type"])
            writer.write_int32(1)
        else:
            if wp["switch"] and wp["enabled"]:
                if IS_STOPPED:
                    ret = LLDB.remove_watchpoint(
                        wp["address"], wp["bpsize"], wp["type"]
                    )
                    if ret:
                        WP_INFO_LIST[debugreg]["enabled"] = False
                else:
                    print("CMD_REMOVEBREAKPOINT")
                WP_INFO_LIST[debugreg]["switch"] = False
                writer.write_int32(1)
            else:
                writer.write_int32(0)

    elif command == CECMD.CMD_GETTHREADCONTEXT:
        handle = reader.read_int32()
        tid = reader.read_int32()
        if parse(CEVERSION) < parse("7.4.2"):
            _type = reader.read_int32()
        writer.write_int32(1)
        if ARCH == ARCHITECTURE.ARM64.value:
            if parse(CEVERSION) >= parse("7.4.2"):
                writer.write_int32(808)  # structsize
                ### Context ###
                writer.write_int32(808)  # structsize
                writer.write_int32(3)  # type
                if len(REGISTER_INFO) > 0:  # general registers
                    for value in REGISTER_INFO:
                        writer.write_uint64(value)
                else:
                    ns.sendall(b"\x00" * 8 * 34)
                ### ContextFP ###
                ns.sendall(b"\x00" * 16 * 33)
            else:
                writer.write_int32(8 * 34)
                if len(REGISTER_INFO) > 0:
                    for value in REGISTER_INFO:
                        writer.write_uint64(value)
                else:
                    ns.sendall(b"\x00" * 8 * 34)

    elif command == CECMD.CMD_SETTHREADCONTEXT:
        if parse(CEVERSION) >= parse("7.4.2"):
            handle = reader.read_int32()
            tid = reader.read_int32()
            structsize = reader.read_int32()
            context = ns.recv(structsize)
            for i in range(1, 34):
                try:
                    value = unpack("<Q", context[i * 8 : i * 8 + 8])[0]
                    if REGISTER_INFO[i - 1] != value:
                        if LLDB.write_register(
                            i - 1, int.to_bytes(value, 8, "little").hex()
                        ):
                            REGISTER_INFO[i - 1] = value
                except Exception:
                    address = 0
            writer.write_int32(1)
        else:
            print("SETTHREADCONTEXT not support.")

    elif command == CECMD.CMD_CHANGEMEMORYPROTECTION:
        handle = reader.read_int32()
        address = reader.read_uint64()
        size = reader.read_int32()
        windowsprotection = reader.read_int32()
        newprotectionstr = "---"
        if windowsprotection == PAGE_EXECUTE_READWRITE:
            newprotectionstr = "rwx"
        elif windowsprotection == PAGE_EXECUTE_READ:
            newprotectionstr = "r-x"
        elif windowsprotection == PAGE_EXECUTE:
            newprotectionstr = "--x"
        elif windowsprotection == PAGE_READWRITE:
            newprotectionstr = "rw-"
        elif windowsprotection == PAGE_READONLY:
            newprotectionstr = "r--"
        result = API.ExtChangeMemoryProtection(address, size, newprotectionstr)
        if result:
            ret = 1
        else:
            ret = 0
        writer.write_int32(ret)
        writer.write_int32(windowsprotection)

    elif command == CECMD.CMD_GETOPTIONS:
        writer.write_int16(0)

    elif command == CECMD.CMD_OPENNAMEDPIPE:
        name = reader.read_string16()
        timeout = reader.read_uint32()
        pipehandle = HandleManager.create_handle()
        HandleManager.set_info(pipehandle, {"name": name})
        writer.write_int32(pipehandle)

    elif command == CECMD.CMD_PIPEREAD:
        pipehandle = reader.read_uint32()
        size = reader.read_uint32()
        timeout = reader.read_uint32()
        info = HandleManager.get_info(pipehandle)
        if info["name"].find("cemonodc_pid") == 0:
            mono_writer = mono_pipeserver.WRITER
            ret = mono_writer.read_message(size)
        writer.write_uint32(len(ret))
        ns.sendall(ret)

    elif command == CECMD.CMD_PIPEWRITE:
        pipehandle = reader.read_uint32()
        size = reader.read_uint32()
        timeout = reader.read_uint32()
        buf = ns.recv(size)
        info = HandleManager.get_info(pipehandle)
        if info["name"].find("cemonodc_pid") == 0:
            mono_pipeserver.mono_process(buf)
        writer.write_uint32(size)

    elif command == CECMD.CMD_ISANDROID:
        writer.write_int8(1)

    elif command == CECMD.CMD_GETCESERVERPATH:
        path = b"/data/local/tmp/ceserver"
        writer.write_int16(len(path))
        ns.sendall(path)
    else:
        pass
    # print("END")
    return 1


def main_thread(conn, native_client, thread_count):
    while True:
        try:
            b = conn.recv(1)
            if b == b"":
                conn.close()
                print("Peer has disconnected")
                break
            command = unpack("<b", b)[0]
            ret = handler(conn, native_client, command, thread_count)
        except Exception:
            import traceback

            print("EXCEPTION:" + str(CECMD(command)))
            traceback.print_exc()
            conn.close()
            break
        if ret == -1:
            break


def ceserver(pid, api, symbol_api, config, session, device):
    global PID
    global API
    global EXTEND_API
    global SYMBOL_API
    global DEVICE
    global _MODE
    global CONFIG
    global ARCH
    global SESSION
    global CEVERSION
    global TARGETOS
    global MANUAL_PARSER
    global JAVA_DISSECT
    global NATIVE_CESERVER_IP
    global CUSTOM_SYMBOL_LOADER
    global DEBUGSERVER_IP
    global CUSTOM_READ_MEMORY
    global DATA_COLLECTOR

    PID = pid
    API = api
    SYMBOL_API = symbol_api
    DEVICE = device
    _MODE = config["general"]["mode"]
    CONFIG = config
    ARCH = config["general"]["arch"]
    SESSION = session
    CEVERSION = config["general"]["ceversion"]
    TARGETOS = config["general"]["target_os"]
    MANUAL_PARSER = config["extended_function"]["manual_parser"]
    JAVA_DISSECT = config["extended_function"]["java_dissect"]
    NATIVE_CESERVER_IP = config["ipconfig"]["native_ceserver_ip"]
    CUSTOM_SYMBOL_LOADER = config["extended_function"]["custom_symbol_loader"]
    DEBUGSERVER_IP = config["ipconfig"]["debugserver_ip"]
    CUSTOM_READ_MEMORY = config["extended_function"]["custom_read_memory"]
    DATA_COLLECTOR = config["extended_function"]["data_collector"]
    if (
        DATA_COLLECTOR == "mono" or DATA_COLLECTOR == "objc"
    ) and _MODE != MODE.ENUM.value:
        mono_pipeserver.mono_init(session, DATA_COLLECTOR)
    listen_host = config["general"]["listen_host"]
    listen_port = config["general"]["listen_port"]

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        thread_count = 0
        s.bind((listen_host, listen_port))
        s.listen(32)
        s.settimeout(1)
        while True:
            try:
                conn, addr = s.accept()
                print("accept", addr)
                native_client = 0
                if NATIVE_CESERVER_IP != "":
                    target_ip = NATIVE_CESERVER_IP.split(":")[0]
                    target_port = NATIVE_CESERVER_IP.split(":")[1]
                    native_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    native_client.connect((target_ip, int(target_port)))

                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                # conn.settimeout(5000)
                thread_count += 1
                thread = threading.Thread(
                    target=main_thread,
                    args=([conn, native_client, thread_count]),
                    daemon=True,
                )
                thread.start()
            except socket.timeout:
                continue
