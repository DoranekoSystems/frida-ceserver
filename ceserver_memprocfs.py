import bisect
import random
import socket
import threading
import zlib
from enum import IntEnum
from struct import pack, unpack

import memprocfs
from packaging.version import parse

import mono_pipeserver

PID = 0
CEVERSION = 0
ARCH = 0

VMM = 0

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
Process = 0
ProcessList = None
ProcessListIterator = 0


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
        RegionList = Process.maps.vad()
    lp_address = address
    sorts = [region["start"] for region in RegionList]
    index = bisect.bisect_left(sorts, lp_address + 1)
    if index == len(sorts):
        return False
    start = RegionList[index]["start"]
    if start <= lp_address:
        base = lp_address
        size = RegionList[index]["end"] - RegionList[index]["start"]
        protection = protection_string_to_protection(RegionList[index]["protection"])
        _type = protection_string_to_type(RegionList[index]["protection"])
        filename = ""
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
        ModuleList = Process.module_list()
    ModuleListIterator = 0
    base = ModuleList[0].base
    size = ModuleList[0].image_size
    name = ModuleList[0].fullname
    ModuleListIterator += 1
    return [base, size, name]


def module32next():
    global ModuleListIterator
    if len(ModuleList) > ModuleListIterator:
        base = ModuleList[ModuleListIterator].base
        size = ModuleList[ModuleListIterator].image_size
        name = ModuleList[ModuleListIterator].fullname
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
    output[0] = b"\x00\x00\x00\x00\x00\x00\x00\x00"


def handler(ns, command, thread_count):
    global Process
    global ProcessList
    global ProcessListIterator
    global RegionList

    reader = BinaryReader(ns)
    writer = BinaryWriter(ns)

    # print(str(thread_count) + ":" + str(CECMD(command).name))
    if command == CECMD.CMD_CREATETOOLHELP32SNAPSHOT:
        dw_flags = reader.read_int32()
        pid = reader.read_int32()
        h_snapshot = random.randint(1, 0x10000)
        ProcessList = VMM.process_list()
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
                    modulebase = ret[0]
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
            threads = Process.maps.thread()
            idlist = [thread["tid"] for thread in threads]
            writer.write_int32(len(idlist))
            for id in idlist:
                writer.write_int32(id)
        else:
            ProcessList = VMM.process_list()
            h_snapshot = random.randint(1, 0x10000)
            writer.write_int32(h_snapshot)

    elif command == CECMD.CMD_PROCESS32FIRST or command == CECMD.CMD_PROCESS32NEXT:
        h_snapshot = reader.read_int32()
        # print("hSnapshot:" + str(hSnapshot))
        if ProcessListIterator < len(ProcessList):
            process = ProcessList[ProcessListIterator]
            processname = process.fullname.encode()
            processnamesize = len(processname)
            _pid = process.pid
            bytecode = pack(
                "<iii" + str(processnamesize) + "s",
                1,
                _pid,
                processnamesize,
                processname,
            )
            ProcessListIterator += 1
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
            modulebase = ret[0]
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
        _ = reader.read_int32()
        # CloseHandle(h)
        writer.write_int32(1)

    elif command == CECMD.CMD_OPENPROCESS:
        pid = reader.read_int32()
        Process = [p for p in ProcessList if p.pid == pid][0]
        processhandle = random.randint(0, 0x10000)
        print("Processhandle:" + str(processhandle))
        writer.write_int32(processhandle)

    elif command == CECMD.CMD_GETARCHITECTURE:
        if parse(CEVERSION) >= parse("7.4.1"):
            _handle = reader.read_int32()
        arch = ARCH
        writer.write_int8(arch)

    elif command == CECMD.CMD_SET_CONNECTION_NAME:
        size = reader.read_int32()
        ns.recv(size)

    elif command == CECMD.CMD_READPROCESSMEMORY:
        _handle = reader.read_uint32()
        address = reader.read_uint64()
        size = reader.read_uint32()
        compress = reader.read_int8()

        ret = Process.memory.read(address, size)
        if compress == 0:
            if ret:
                writer.write_int32(len(ret))
                ns.sendall(ret)
            else:
                writer.write_int32(0)
        else:
            if ret:
                uncompressed_size = len(ret)
                compress_data = zlib.compress(ret, level=compress)
                writer.write_int32(uncompressed_size)
                writer.write_int32(len(compress_data))
                ns.sendall(compress_data)
            else:
                writer.write_int32(0)
                writer.write_int32(0)

    elif command == CECMD.CMD_WRITEPROCESSMEMORY:
        # wip
        _handle = reader.read_uint32()
        address = reader.read_uint64()
        size = reader.read_uint32()
        if size > 0:
            _buf = ns.recv(size)
            Process.memory.write(address, _buf)
            ret = True
            if ret:
                writer.write_int32(size)
            else:
                writer.write_int32(0)
        else:
            writer.write_int32(0)

    elif command == CECMD.CMD_VIRTUALQUERYEXFULL:
        _handle = reader.read_int32()
        _flags = reader.read_int8()
        address = 0
        sendbyte_code = b""
        RegionList = Process.maps.vad()
        region_size = len(RegionList)
        for ri in RegionList:
            protection = protection_string_to_protection(ri["protection"])
            baseaddress = ri["start"]
            _type = protection_string_to_type(ri["protection"])
            size = ri["end"] - ri["start"]
            bytecode = pack("<QQII", baseaddress, size, protection, _type)
            sendbyte_code += bytecode
        writer.write_int32(region_size)
        ns.sendall(sendbyte_code)

    elif command == CECMD.CMD_VIRTUALQUERYEX:
        _handle = reader.read_int32()
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
        _handle = reader.read_int32()
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
            _fileoffset = reader.read_uint32()
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
        _handle = reader.read_int32()
        writer.write_int32(1)

    elif command == CECMD.CMD_SPEEDHACK_SETSPEED:
        _handle = reader.read_int32()
        data = ns.recv(4)
        _speedratio = unpack("<f", data)[0]
        r = 0
        writer.write_int32(r)

    elif command == CECMD.CMD_ALLOC:
        _handle = reader.read_int32()
        _prefered_base = reader.read_uint64()
        size = reader.read_int32()
        writer.write_uint64(0)

    elif command == CECMD.CMD_FREE:
        _handle = reader.read_int32()
        address = reader.read_uint64()
        size = reader.read_int32()
        writer.write_int32(0)

    elif command == CECMD.CMD_LOADMODULE:
        _handle = reader.read_int32()
        modulepathlength = reader.read_int32()
        _modulepath = ns.recv(modulepathlength).decode()
        writer.write_uint64(0)

    elif command == CECMD.CMD_CREATETHREAD:
        _handle = reader.read_int32()
        _startaddress = reader.read_uint64()
        _parameter = reader.read_uint64()
        _threadhandle = random.randint(0, 0x10000)
        writer.write_int32(0)

    elif command == CECMD.CMD_GETABI:
        writer.write_int8(1)

    elif command == CECMD.CMD_STARTDEBUG:
        _handle = reader.read_int32()
        writer.write_int32(0)

    elif command == CECMD.CMD_WAITFORDEBUGEVENT:
        _handle = reader.read_int32()
        _timeout = reader.read_int32()
        writer.write_int32(0)

    elif command == CECMD.CMD_CONTINUEFROMDEBUGEVENT:
        _handle = reader.read_int32()
        _tid = reader.read_int32()
        _ignore = reader.read_int32()
        writer.write_int32(0)

    elif command == CECMD.CMD_SETBREAKPOINT:
        _handle = reader.read_int32()
        _tid = reader.read_int32()
        _debugreg = reader.read_int32()
        address = reader.read_uint64()
        _bptype = reader.read_int32()
        _bpsize = reader.read_int32()
        writer.write_int32(0)

    elif command == CECMD.CMD_REMOVEBREAKPOINT:
        _handle = reader.read_int32()
        _tid = reader.read_int32()
        _debugreg = reader.read_int32()
        _was_watchpoint = reader.read_int32()
        writer.write_int32(0)

    elif command == CECMD.CMD_GETTHREADCONTEXT:
        _handle = reader.read_int32()
        _tid = reader.read_int32()
        if parse(CEVERSION) < parse("7.4.2"):
            _type = reader.read_int32()
        writer.write_int32(1)
        if ARCH == 3:
            ns.sendall(b"\x00" * 8 * 34)
        else:
            pass

    elif command == CECMD.CMD_SETTHREADCONTEXT:
        if parse(CEVERSION) >= parse("7.4.2"):
            _handle = reader.read_int32()
            _tid = reader.read_int32()
            structsize = reader.read_int32()
            _context = ns.recv(structsize)
            writer.write_int32(0)
        else:
            print("SETTHREADCONTEXT not support.")

    elif command == CECMD.CMD_CHANGEMEMORYPROTECTION:
        _handle = reader.read_int32()
        address = reader.read_uint64()
        size = reader.read_int32()
        windowsprotection = reader.read_int32()
        ret = 0
        writer.write_int32(ret)
        writer.write_int32(windowsprotection)

    elif command == CECMD.CMD_GETOPTIONS:
        writer.write_int16(0)

    elif command == CECMD.CMD_OPENNAMEDPIPE:
        _pipename = reader.read_string16()
        _timeout = reader.read_uint32()
        pipehandle = random.randint(1, 0x10000)
        writer.write_int32(pipehandle)

    elif command == CECMD.CMD_PIPEREAD:
        pipehandle = reader.read_uint32()
        size = reader.read_uint32()
        _timeout = reader.read_uint32()

        mono_writer = mono_pipeserver.WRITER
        ret = mono_writer.read_message(size)
        writer.write_uint32(len(ret))
        ns.sendall(ret)

    elif command == CECMD.CMD_PIPEWRITE:
        pipehandle = reader.read_uint32()
        size = reader.read_uint32()
        _timeout = reader.read_uint32()
        buf = ns.recv(size)

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


def main_thread(conn, thread_count):
    while True:
        try:
            b = conn.recv(1)
            if b == b"":
                conn.close()
                print("Peer has disconnected")
                break
            command = unpack("<b", b)[0]
            ret = handler(conn, command, thread_count)
        except Exception:
            import traceback

            print("EXCEPTION:" + str(CECMD(command)))
            traceback.print_exc()
            conn.close()
            break
        if ret == -1:
            break


def ceserver(config):
    global VMM
    global ARCH
    global CEVERSION

    listen_host = config["general"]["listen_host"]
    listen_port = config["general"]["listen_port"]
    arch = config["general"]["arch"]
    ceversion = config["general"]["ceversion"]
    device = config["general"]["device"]
    VMM = memprocfs.Vmm(["-device", device])
    ARCH = arch
    CEVERSION = ceversion
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
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                # conn.settimeout(5000)
                thread_count += 1
                thread = threading.Thread(
                    target=main_thread,
                    args=([conn, thread_count]),
                    daemon=True,
                )
                thread.start()
            except socket.timeout:
                continue
