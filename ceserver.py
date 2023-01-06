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
import mono_pipeserver
from define import OS
from lldbauto import *
import lz4.block

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
CUSTOM_READ_MEMORY = 0
DATA_COLLECTOR = 0

LLDB = 0
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
    for i in range(4)
]

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

    def ReadString16(self):
        l = self.ReadUInt16()
        result = recvall(self.base, l)
        ret = result.decode()
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
    if TARGETOS in [OS.LINUX.value, OS.ANDROID.value] and MANUAL_PARSER:
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


def interrupt_func():
    while True:
        Lock.acquire()
        if (
            len(
                [
                    wp
                    for wp in WP_INFO_LIST
                    if (wp["switch"] == True and wp["enabled"] == False)
                    or (wp["switch"] == False and wp["enabled"] == True)
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

    signal = -1
    thread = -1
    is_debugserver = TARGETOS == OS.IOS.value or TARGETOS == OS.MAC.value
    while True:
        if is_debugserver:
            result = LLDB.cont()
        else:
            # first
            if signal == -1:
                result = LLDB.cont()
            else:
                result = LLDB.cont2(signal, thread)
        Lock.acquire()
        info = LLDB.parse_result(result)
        if is_debugserver:
            if "metype" not in info:
                print("Debugger Thread:info is empty.")
                Lock.release()
                continue
            metype = info["metype"]
        else:
            if "thread" not in info:
                print("Debugger Thread:info is empty.")
                Lock.release()
                continue
            thread = int(info["thread"], 16)
            signal = int([x for x in info.keys() if x.find("T") == 0][0][1:3], 16)
            if signal == 2 or signal == 5:
                signal = 0
            # watchpoint
            if len([x for x in info.keys() if x.find("watch") != -1]) > 0:
                metype = "6"
            else:
                metype = "5"

        # Breadkpoint Exception
        if metype == "6":
            if is_debugserver:
                medata = int(info["medata"], 16)
            else:
                # example: 'T05watch': '0*"7fe22293dc'
                medata = int(
                    [info[x] for x in info.keys() if x.find("watch") != -1][0].split(
                        '"'
                    )[1],
                    16,
                )
            if medata > 0x100000:
                threadid = int(
                    [info[x] for x in info.keys() if x.find("thread") != -1][0], 16
                )

                if is_debugserver:
                    result = LLDB.step(threadid)
                else:
                    wp = [wp for wp in WP_INFO_LIST if wp["address"] == medata][0]
                    ret1 = LLDB.remove_watchpoint(medata, wp["bpsize"], wp["type"])
                    ret2 = LLDB.step(threadid)
                    ret3 = LLDB.set_watchpoint(medata, wp["bpsize"], wp["type"])

                if not is_debugserver:
                    registers = LLDB.get_register_info(threadid)

                register_list = []
                for i in range(34):
                    if is_debugserver:
                        try:
                            if i == 33:
                                address = struct.unpack(
                                    "<I", bytes.fromhex(info[f"{i:02x}"])
                                )[0]
                            else:
                                address = struct.unpack(
                                    "<Q", bytes.fromhex(info[f"{i:02x}"])
                                )[0]

                        except Exception as e:
                            address = 0
                    else:
                        try:
                            string = registers[i * 16 : i * 16 + 16]
                            address = struct.unpack("<Q", bytes.fromhex(string))[0]
                            if i == 32:
                                address -= 4
                        except Exception as e:
                            address = 0
                    register_list.append(address)

                event = {
                    "debugevent": 5,
                    "threadid": threadid,
                    "address": medata,
                    "register": register_list,
                }
                DEBUG_EVENT.append(event)

        if metype == "5" or metype == "6":
            threadid = int(
                [info[x] for x in info.keys() if x.find("thread") != -1][0], 16
            )
            # set watchpoint
            for i in range(4):
                wp = WP_INFO_LIST[i]
                if wp["switch"] == True and wp["enabled"] == False:
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

            # remove watchpoint
            for i in range(4):
                wp = WP_INFO_LIST[i]
                if wp["switch"] == False and wp["enabled"] == True:
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

        Lock.release()


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
    global REGISTER_INFO
    global WP_INFO_LIST

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

    elif command == CECMD.CMD_CREATETOOLHELP32SNAPSHOTEX:
        dwFlags = reader.ReadInt32()
        pid = reader.ReadInt32()
        bytecode = b""
        if dwFlags & TH32CS_SNAPMODULE == TH32CS_SNAPMODULE:
            ret = API.Module32First()
            while True:
                if ret != False:
                    modulename = ret[2].encode()
                    modulenamesize = len(modulename)
                    modulebase = int(ret[0], 16)
                    modulepart = 0
                    modulesize = ret[1]
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
                ret = API.Module32Next()
            tmp = pack("<iQIII", 0, 0, 0, 0, 0)
            bytecode = b"".join([bytecode, tmp])
            ns.sendall(bytecode)
        elif dwFlags & TH32CS_SNAPTHREAD == TH32CS_SNAPTHREAD:
            idlist = API.GetThreadList()
            writer.WriteInt32(len(idlist))
            for id in idlist:
                writer.WriteInt32(id)
        else:
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
        if parse(CEVERSION) >= parse("7.4.1"):
            handle = reader.ReadInt32()
        arch = ARCH
        writer.WriteInt8(arch)

    elif command == CECMD.CMD_SET_CONNECTION_NAME:
        size = reader.ReadInt32()
        ns.recv(size)

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
                # iOS
                if CUSTOM_READ_MEMORY and TARGETOS == OS.IOS.value:
                    decompress_bytes = b""
                    tmp = ret
                    last_uncompressed = b""
                    # todo:bv4-
                    while True:
                        if (tmp[0:4] != b"bv41") or (tmp[0:4] == b"bv4$"):
                            break
                        uncompressed_size, compressed_size = struct.unpack(
                            "<II", tmp[4:12]
                        )
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
                    uncompressed_size = struct.unpack("<I", ret[-4:])[0]
                    decompress_bytes = lz4.block.decompress(ret[:-4], uncompressed_size)
                    ret = decompress_bytes
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
        if parse(CEVERSION) >= parse("7.4.3"):
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
        if modulepath.find("libMonoDataCollector") != -1:
            writer.WriteUInt64(0x7FFFDEADBEAF)
        else:
            r = API.ExtLoadModule(modulepath)
            writer.WriteUInt64(r)

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
        t1 = threading.Thread(target=debugger_thread)
        t1.start()
        t2 = threading.Thread(target=interrupt_func)
        t2.start()

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
                REGISTER_INFO = event["register"]
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
            wp = WP_INFO_LIST[debugreg]
            if wp["switch"] == False and wp["enabled"] == False:
                print("CMD_SETBREAKPOINT")
                _type = ""
                if bptype == 1:
                    _type = "w"
                elif bptype == 2:
                    _type = "r"
                elif bptype == 3:
                    _type = "a"
                bp = {
                    "address": address,
                    "bpsize": bpsize,
                    "type": _type,
                    "switch": True,
                    "enabled": False,
                }
                WP_INFO_LIST[debugreg] = bp
                writer.WriteInt32(1)
            else:
                writer.WriteInt32(0)

    elif command == CECMD.CMD_REMOVEBREAKPOINT:
        handle = reader.ReadInt32()
        tid = reader.ReadInt32()
        debugreg = reader.ReadInt32()
        wasWatchpoint = reader.ReadInt32()
        wp = WP_INFO_LIST[debugreg]

        if tid != -1:
            writer.WriteInt32(1)
        else:
            if wp["switch"] == True and wp["enabled"] == True:
                print("CMD_REMOVEBREAKPOINT")
                WP_INFO_LIST[debugreg]["switch"] = False
                writer.WriteInt32(1)
            else:
                writer.WriteInt32(0)

    elif command == CECMD.CMD_GETTHREADCONTEXT:
        handle = reader.ReadInt32()
        tid = reader.ReadInt32()
        if parse(CEVERSION) < parse("7.4.2"):
            _type = reader.ReadInt32()
        writer.WriteInt32(1)
        if ARCH == 3:
            if parse(CEVERSION) >= parse("7.4.2"):
                writer.WriteInt32(808)  # structsize
                ### Context ###
                writer.WriteInt32(808)  # structsize
                writer.WriteInt32(3)  # type
                if len(REGISTER_INFO) > 0:  # general registers
                    for value in REGISTER_INFO:
                        writer.WriteUInt64(value)
                else:
                    ns.sendall(b"\x00" * 8 * 34)
                ### ContextFP ###
                ns.sendall(b"\x00" * 16 * 33)
            else:
                writer.WriteInt32(8 * 34)
                if len(REGISTER_INFO) > 0:
                    for value in REGISTER_INFO:
                        writer.WriteUInt64(value)
                else:
                    ns.sendall(b"\x00" * 8 * 34)

    elif command == CECMD.CMD_SETTHREADCONTEXT:
        if parse(CEVERSION) >= parse("7.4.2"):
            handle = reader.ReadInt32()
            tid = reader.ReadInt32()
            structsize = reader.ReadInt32()
            ns.recv(structsize)
            writer.WriteInt32(1)
        else:
            print("SETTHREADCONTEXT not support.")

    elif command == CECMD.CMD_CHANGEMEMORYPROTECTION:
        handle = reader.ReadInt32()
        address = reader.ReadUInt64()
        size = reader.ReadInt32()
        windowsprotection = reader.ReadInt32()
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
        if result == True:
            ret = 1
        else:
            ret = 0
        writer.WriteInt32(ret)
        writer.WriteInt32(windowsprotection)

    elif command == CECMD.CMD_GETOPTIONS:
        writer.WriteInt16(0)

    elif command == CECMD.CMD_OPENNAMEDPIPE:
        pipename = reader.ReadString16()
        timeout = reader.ReadUInt32()
        pipehandle = random.randint(1, 0x10000)
        writer.WriteInt32(pipehandle)

    elif command == CECMD.CMD_PIPEREAD:
        pipehandle = reader.ReadUInt32()
        size = reader.ReadUInt32()
        timeout = reader.ReadUInt32()

        mono_writer = mono_pipeserver.WRITER
        ret = mono_writer.ReadMessage(size)
        writer.WriteUInt32(len(ret))
        ns.sendall(ret)

    elif command == CECMD.CMD_PIPEWRITE:
        pipehandle = reader.ReadUInt32()
        size = reader.ReadUInt32()
        timeout = reader.ReadUInt32()
        buf = ns.recv(size)

        mono_pipeserver.mono_process(buf)
        writer.WriteUInt32(size)

    elif command == CECMD.CMD_ISANDROID:
        writer.WriteInt8(1)

    elif command == CECMD.CMD_GETCESERVERPATH:
        path = b"/data/local/tmp/ceserver"
        writer.WriteInt16(len(path))
        ns.sendall(path)
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
    global CUSTOM_READ_MEMORY
    global DATA_COLLECTOR

    PID = pid
    API = api
    SYMBOL_API = symbol_api
    ARCH = config["general"]["arch"]
    SESSION = session
    CEVERSION = config["general"]["ceversion"]
    TARGETOS = config["general"]["targetOS"]
    MANUAL_PARSER = config["extended_function"]["manualParser"]
    JAVA_DISSECT = config["extended_function"]["javaDissect"]
    NATIVE_CESERVER_IP = config["ipconfig"]["native_ceserver_ip"]
    CUSTOM_SYMBOL_LOADER = config["extended_function"]["custom_symbol_loader"]
    DEBUGSERVER_IP = config["ipconfig"]["debugserver_ip"]
    CUSTOM_READ_MEMORY = config["extended_function"]["custom_read_memory"]
    DATA_COLLECTOR = config["extended_function"]["data_collector"]
    if DATA_COLLECTOR == "mono" or DATA_COLLECTOR == "objc":
        mono_pipeserver.mono_init(session,DATA_COLLECTOR)

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
