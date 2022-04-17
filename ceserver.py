import socket
import select
import sys
from struct import *
import zlib
import time
import json
from enum import IntEnum, auto
import threading
import random
from packaging.version import Version, parse
from define import OS
from lldbauto import *


PID = 0
API = 0
SYMBOL_API = 0
ARCH = 0
SESSION = 0
CEVERSION = ""
TARGETOS = 0
MANUAL_PARSER = 0
JAVA_DISSECT = 0
NATIVE_CESERVER_IP = 0
CUSTOM_SYMBOL_LOADER = []
DEBUGSERVER_IP = 0

LLDB = 0
DEBUG_EVENT = []
BP_LIST = []
REGISTER_INFO = {}

PROCESS_ALL_ACCESS = 0x1F0FFF

TH32CS_SNAPPROCESS = 0x2
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

    def ReadInt8(self):
        result = recvall(self.base, 1)
        ret = unpack("<b", result)[0]
        return ret

    def ReadInt16(self):
        result = recvall(self.base, 2)
        ret = unpack("<h", result)[0]
        return ret

    def ReadInt32(self):
        result = recvall(self.base, 4)
        ret = unpack("<i", result)[0]
        return ret

    def ReadInt64(self):
        result = recvall(self.base, 8)
        ret = unpack("<q", result)[0]
        return ret

    def ReadUInt8(self):
        result = recvall(self.base, 1)
        ret = unpack("<B", result)[0]
        return ret

    def ReadUInt16(self):
        result = recvall(self.base, 2)
        ret = unpack("<H", result)[0]
        return ret

    def ReadUInt32(self):
        result = recvall(self.base, 4)
        ret = unpack("<I", result)[0]
        return ret

    def ReadUInt64(self):
        result = recvall(self.base, 8)
        ret = unpack("<Q", result)[0]
        return ret


class BinaryWriter:
    def __init__(self, base):
        self.base = base

    def WriteInt8(self, number):
        i8 = pack("<b", number)
        self.base.sendall(i8)

    def WriteInt16(self, number):
        i16 = pack("<h", number)
        self.base.sendall(i16)

    def WriteInt32(self, number):
        i32 = pack("<i", number)
        self.base.sendall(i32)

    def WriteInt64(self, number):
        i64 = pack("<q", number)
        self.base.sendall(i64)

    def WriteUInt8(self, number):
        ui8 = pack("<B", number)
        self.base.sendall(ui8)

    def WriteUInt16(self, number):
        ui16 = pack("<H", number)
        self.base.sendall(ui16)

    def WriteUInt32(self, number):
        ui32 = pack("<I", number)
        self.base.sendall(ui32)

    def WriteUInt64(self, number):
        ui64 = pack("<Q", number)
        self.base.sendall(ui64)


def GetSymbolListFromFile(filename, output):
    if TARGETOS in [OS.LINUX, OS.ANDROID] and MANUAL_PARSER:
        ret = SYMBOL_API.GetSymbolListFromFile(filename)
    else:
        ret = API.GetSymbolListFromFile(filename)
    if len(CUSTOM_SYMBOL_LOADER) > 0:
        for symbolfile, filepath in CUSTOM_SYMBOL_LOADER.items():
            if symbolfile == filename:
                with open(filepath, encoding="utf-8") as f:
                    jdict = json.loads(f.read().replace("\n", ""))
                    ScriptMethod = sorted(
                        jdict["ScriptMethod"], key=lambda x: x["Address"]
                    )
                    for i, method in enumerate(ScriptMethod):
                        baseaddress = method["Address"]
                        if i == len(ScriptMethod) - 1:
                            size = 8
                        else:
                            size = (
                                ScriptMethod[i + 1]["Address"]
                                - ScriptMethod[i]["Address"]
                            )
                        _type = 0
                        name = method["Name"]
                        ret.append([baseaddress, size, _type, name])
    if ret != False and len(ret) > 0:
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
            except Exception as e:
                pass
        compress_data = zlib.compress(bytecode)
        sendall_data = pack("<iii", 0, len(compress_data) + 12, len(bytecode))
        sendall_data += compress_data
        output[0] = sendall_data
    else:
        output[0] = b"\x00\x00\x00\x00\x00\x00\x00\x00"


def debugger_thread():
    global REGISTER_INFO
    while True:
        result = LLDB.cont()
        info = LLDB.parse_result(result)
        if "metype" not in info:
            continue
        metype = info["metype"]
        # Breadkpoint Exception
        if metype == "6":
            medata = int(info["medata"], 16)
            if medata > 0x100000:
                threadid = int(info["T05thread"], 16)
                address = struct.unpack("<Q", bytes.fromhex(info["20"]))[0]
                event = {
                    "debugevent": 5,
                    "threadid": threadid,
                    "address": medata,
                    "pc": address + 4,
                }
                DEBUG_EVENT.append(event)


script_dict = {}


def load_frida_script(jscode, numberStr):
    global script_dict
    session = SESSION
    script = session.create_script(jscode)

    def on_message(message, data):
        print(message)

    script.on("message", on_message)
    script.load()
    script_dict[numberStr] = script


def unload_frida_script(numberStr):
    global script_dict
    script = script_dict[numberStr]
    script.unload()
    script_dict.pop(numberStr)


def handler(ns, nc, command, thread_count):
    global process_id
    global LLDB
    global BP_LIST
    global REGISTER_INFO

    reader = BinaryReader(ns)
    writer = BinaryWriter(ns)
    reader2 = BinaryReader(nc)
    writer2 = BinaryWriter(nc)

    # print(str(thread_count) + ":" + str(CECMD(command)))
    if command == CECMD.CMD_CREATETOOLHELP32SNAPSHOT:
        dwFlags = reader.ReadInt32()
        pid = reader.ReadInt32()
        hSnapshot = random.randint(1, 0x10000)
        writer.WriteInt32(hSnapshot)

    elif command == CECMD.CMD_PROCESS32FIRST or command == CECMD.CMD_PROCESS32NEXT:
        hSnapshot = reader.ReadInt32()
        print("hSnapshot:" + str(hSnapshot))
        if command == CECMD.CMD_PROCESS32FIRST:
            ret = 1
        else:
            ret = 0
        if ret != 0:
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
        hSnapshot = reader.ReadInt32()
        if command == CECMD.CMD_MODULE32FIRST:
            ret = API.Module32First()
        else:
            ret = API.Module32Next()
        if ret != False:
            modulename = ret[2].encode()
            modulenamesize = len(modulename)
            modulebase = int(ret[0], 16)
            modulepart = 0
            modulesize = ret[1]
            if parse(CEVERSION) >= parse("7.3.1"):
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
        h = reader.ReadInt32()
        # CloseHandle(h)
        writer.WriteInt32(1)

    elif command == CECMD.CMD_OPENPROCESS:
        pid = reader.ReadInt32()
        if nc != 0:
            writer2.WriteUInt8(CECMD.CMD_OPENPROCESS)
            writer2.WriteInt32(pid)
            processhandle = reader2.ReadInt32()
        else:
            processhandle = random.randint(0, 0x10000)
        print("Processhandle:" + str(processhandle))
        pHandle = processhandle
        writer.WriteInt32(processhandle)

    elif command == CECMD.CMD_GETARCHITECTURE:
        arch = ARCH
        writer.WriteInt8(arch)

    elif command == CECMD.CMD_READPROCESSMEMORY:
        handle = reader.ReadUInt32()
        address = reader.ReadUInt64()
        size = reader.ReadUInt32()
        compress = reader.ReadInt8()
        if nc != 0:
            writer2.WriteUInt8(CECMD.CMD_READPROCESSMEMORY)
            writer2.WriteUInt32(handle)
            writer2.WriteUInt64(address)
            writer2.WriteUInt32(size)
            writer2.WriteInt8(compress)
            if compress == 0:
                read = reader2.ReadUInt32()
                if read == 0:
                    ret = False
                else:
                    ret = b""
                    while True:
                        ret += nc.recv(4096)
                        if len(ret) == read:
                            break
            else:
                uncompressedSize = reader2.ReadUInt32()
                compressedSize = reader2.ReadUInt32()
                if compressedSize == 0:
                    ret = False
                else:
                    ret = b""
                    while True:
                        ret += nc.recv(4096)
                        if len(ret) == compressedSize:
                            break
        else:
            ret = API.ReadProcessMemory(address, size)
        if compress == 0:
            if ret != False:
                writer.WriteInt32(len(ret))
                ns.sendall(ret)
            else:
                writer.WriteInt32(0)
        else:
            if ret != False:
                if nc != 0:
                    compress_data = ret
                else:
                    uncompressedSize = len(ret)
                    compress_data = zlib.compress(ret, level=compress)
                writer.WriteInt32(uncompressedSize)
                writer.WriteInt32(len(compress_data))
                ns.sendall(compress_data)
            else:
                writer.WriteInt32(0)
                writer.WriteInt32(0)

    elif command == CECMD.CMD_WRITEPROCESSMEMORY:
        handle = reader.ReadUInt32()
        address = reader.ReadUInt64()
        size = reader.ReadUInt32()
        if size > 0:
            _buf = ns.recv(size)
            # extended functionality
            # Addresses 0 to 100 will interpret the written content as frida javascript code and execute the script.
            if 0 <= address <= 100:
                if _buf.find("UNLOAD".encode()) != 0:
                    load_frida_script(_buf.decode(), str(address))
                else:
                    if str(address) in script_dict:
                        unload_frida_script(str(address))
                ret = True
            else:
                ret = API.WriteProcessMemory(address, list(_buf))
            if ret != False:
                writer.WriteInt32(size)
            else:
                writer.WriteInt32(0)
        else:
            writer.WriteInt32(0)

    elif command == CECMD.CMD_VIRTUALQUERYEXFULL:
        handle = reader.ReadInt32()
        flags = reader.ReadInt8()
        address = 0
        sendbyteCode = b""
        regionSize = 0
        ret = API.VirtualQueryExFull(flags)
        regionSize = len(ret)
        for ri in ret:
            protection = ri[2]
            baseaddress = ri[0]
            _type = ri[3]
            size = ri[1]
            bytecode = pack("<QQII", baseaddress, size, protection, _type)
            sendbyteCode += bytecode
        writer.WriteInt32(regionSize)
        ns.sendall(sendbyteCode)

    elif command == CECMD.CMD_VIRTUALQUERYEX:
        handle = reader.ReadInt32()
        baseaddress = reader.ReadUInt64()
        ret = API.VirtualQueryEx(baseaddress)
        if ret != False:
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
        handle = reader.ReadInt32()
        baseaddress = reader.ReadUInt64()
        ret = API.VirtualQueryEx(baseaddress)
        if ret != False:
            protection = ret[2]
            baseaddress = ret[0]
            _type = ret[3]
            size = ret[1]
            bytecode = pack("<bIIQQ", 1, protection, _type, baseaddress, size)
            ns.sendall(bytecode)
            filename = ret[4]
            filenamesize = len(filename)
            writer.WriteUInt8(filenamesize)
            ns.sendall(filename.encode())
        else:
            protection = 0
            baseaddress = 0
            _type = 0
            size = 0
            bytecode = pack("<bIIQQ", 0, protection, _type, baseaddress, size)
            ns.sendall(bytecode)
            writer.WriteInt8(0)

    elif command == CECMD.CMD_TERMINATESERVER:
        ns.close()
        return -1

    elif command == CECMD.CMD_GETVERSION:
        if parse(CEVERSION) >= parse("7.3.2"):
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
        symbolpathsize = reader.ReadInt16()
        symbolname = ns.recv(symbolpathsize + 2).decode()
        output = [0]
        GetSymbolListFromFile(symbolname[2:], output)
        ns.sendall(output[0])

    elif command == CECMD.CMD_LOADEXTENSION:
        handle = reader.ReadInt32()
        writer.WriteInt32(1)

    elif command == CECMD.CMD_SPEEDHACK_SETSPEED:
        handle = reader.ReadInt32()
        data = ns.recv(4)
        speedratio = unpack("<f", data)[0]
        r = API.ExtSetSpeed(speedratio)
        writer.WriteInt32(r)

    elif command == CECMD.CMD_ALLOC:
        handle = reader.ReadInt32()
        preferedBase = reader.ReadUInt64()
        size = reader.ReadInt32()
        address = API.ExtAlloc(preferedBase, size)
        writer.WriteUInt64(address)

    elif command == CECMD.CMD_FREE:
        handle = reader.ReadInt32()
        address = reader.ReadUInt64()
        size = reader.ReadInt32()
        r = API.ExtFree(address, size)
        writer.WriteInt32(r)

    elif command == CECMD.CMD_LOADMODULE:
        handle = reader.ReadInt32()
        modulepathlength = reader.ReadInt32()
        modulepath = ns.recv(modulepathlength).decode()
        r = API.ExtLoadModule(modulepath)
        writer.WriteInt32(r)

    elif command == CECMD.CMD_CREATETHREAD:
        handle = reader.ReadInt32()
        startaddress = reader.ReadUInt64()
        parameter = reader.ReadUInt64()
        r = API.ExtCreateThread(startaddress, parameter)
        threadhandle = random.randint(0, 0x10000)
        writer.WriteInt32(threadhandle)

    elif command == CECMD.CMD_GETABI:
        writer.WriteInt8(1)

    elif command == CECMD.CMD_STARTDEBUG:
        handle = reader.ReadInt32()
        target_ip = DEBUGSERVER_IP.split(":")[0]
        target_port = int(DEBUGSERVER_IP.split(":")[1])
        LLDB = LLDBAutomation(target_ip, target_port)
        LLDB.attach(PID)
        t = threading.Thread(target=debugger_thread)
        t.start()
        event = {
            "debugevent": -2,
            "threadid": PID,
            "maxBreakpointCount": 4,
            "maxWatchpointCount": 4,
            "maxSharedBreakpoints": 4,
        }
        DEBUG_EVENT.append(event)
        writer.WriteInt32(1)

    elif command == CECMD.CMD_WAITFORDEBUGEVENT:
        handle = reader.ReadInt32()
        timeout = reader.ReadInt32()
        if len(DEBUG_EVENT) > 0:
            writer.WriteInt32(1)
            event = DEBUG_EVENT.pop()
            debugevent = event["debugevent"]
            threadid = event["threadid"]
            if debugevent == -2:
                writer.WriteInt32(debugevent)
                writer.WriteInt64(threadid)
                writer.WriteInt8(event["maxBreakpointCount"])
                writer.WriteInt8(event["maxWatchpointCount"])
                writer.WriteInt8(event["maxSharedBreakpoints"])
                ns.sendall(b"\x00" * 5)
            elif debugevent == 5:
                REGISTER_INFO["pc"] = event["pc"]
                writer.WriteInt32(debugevent)
                writer.WriteInt64(threadid)
                writer.WriteUInt64(event["address"])
        else:
            time.sleep(timeout / 1000)
            writer.WriteInt32(0)

    elif command == CECMD.CMD_CONTINUEFROMDEBUGEVENT:
        handle = reader.ReadInt32()
        tid = reader.ReadInt32()
        ignore = reader.ReadInt32()
        writer.WriteInt32(1)

    elif command == CECMD.CMD_SETBREAKPOINT:
        handle = reader.ReadInt32()
        tid = reader.ReadInt32()
        debugreg = reader.ReadInt32()
        address = reader.ReadUInt64()
        bptype = reader.ReadInt32()
        bpsize = reader.ReadInt32()

        # executebp not support
        if bptype == 0:
            writer.WriteInt32(0)
        else:
            bpaddr_list = [l.get("address") for l in BP_LIST]
            if address not in bpaddr_list:
                _type = ""
                if bptype == 1:
                    _type = "w"
                elif bptype == 2:
                    _type = "r"
                elif bptype == 3:
                    _type = "a"
                LLDB.interrupt()
                LLDB.set_watchpoint(address, bpsize, _type)
                BP_LIST.append(
                    {
                        "address": address,
                        "bpsize": bpsize,
                        "type": _type,
                        "debugreg": debugreg,
                    }
                )
            writer.WriteInt32(1)

    elif command == CECMD.CMD_REMOVEBREAKPOINT:
        handle = reader.ReadInt32()
        tid = reader.ReadInt32()
        debugreg = reader.ReadInt32()
        wasWatchpoint = reader.ReadInt32()
        bp = [x for x in BP_LIST if x["debugreg"] == debugreg][0]
        address = bp["address"]
        _type = bp["type"]
        bpsize = bp["bpsize"]
        LLDB.interrupt()
        LLDB.remove_watchpoint(address, _type, bpsize)
        BP_LIST.remove(bp)
        writer.WriteInt32(1)

    elif command == CECMD.CMD_GETTHREADCONTEXT:
        handle = reader.ReadInt32()
        tid = reader.ReadInt32()
        _type = reader.ReadInt32()
        writer.WriteInt32(1)
        writer.WriteInt32(8 * 27)
        ns.sendall(b"\x00" * 8 * 16)
        pc = 0
        if "pc" in REGISTER_INFO:
            pc = REGISTER_INFO["pc"]
        writer.WriteUInt64(pc)
        ns.sendall(b"\x00" * 8 * 10)

    else:
        pass
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
        except:
            import traceback

            print("EXCEPTION:" + str(CECMD(command)))
            traceback.print_exc()
            conn.close()
            break
        if ret == -1:
            break


def ceserver(pid, api, symbol_api, config, session):
    global PID
    global API
    global SYMBOL_API
    global ARCH
    global SESSION
    global CEVERSION
    global TARGETOS
    global MANUAL_PARSER
    global JAVA_DISSECT
    global NATIVE_CESERVER_IP
    global CUSTOM_SYMBOL_LOADER
    global DEBUGSERVER_IP

    PID = pid
    API = api
    SYMBOL_API = symbol_api
    ARCH = config["arch"]
    SESSION = session
    CEVERSION = config["ceversion"]
    TARGETOS = config["targetOS"]
    MANUAL_PARSER = config["manualParser"]
    JAVA_DISSECT = config["javaDissect"]
    NATIVE_CESERVER_IP = config["native_ceserver_ip"]
    CUSTOM_SYMBOL_LOADER = config["custom_symbol_loader"]
    DEBUGSERVER_IP = config["debugserver_ip"]

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        thread_count = 0
        s.bind(("127.0.0.1", 52736))
        s.listen(32)
        lock = threading.Lock()
        while True:
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
