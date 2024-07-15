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
import requests
from struct import pack, unpack

import lz4.block
from packaging.version import parse

import java_pipeserver
import mono_pipeserver
from define import ARCHITECTURE, CECMD, MODE, OS, WinDef
from lldbauto import LLDBAutomation
from util import (
    BinaryReader,
    BinaryWriter,
    HandleManager,
    arch_to_number,
)


class Config:
    config = None
    mode = ""
    arch = ""
    ceverion = ""
    target_os = ""
    manual_parser = False
    java_info = False
    native_ceserver_ip = ""
    custom_symbol_loader = []
    debugserver_ip = ""
    custom_read_memory = False
    data_collector = ""
    listen_host = ""
    listen_port = 0

    @classmethod
    def load_config(cls, config):
        cls.config = config
        cls.mode = config["general"]["mode"]
        cls.arch = config["general"]["arch"]
        cls.ceversion = config["general"]["ceversion"]
        cls.target_os = config["general"]["target_os"]
        cls.manual_parser = config["extended_function"]["manual_parser"]
        cls.java_info = config["extended_function"]["java_info"]
        cls.native_server = config["supporter"]["native_server"]
        cls.native_server_ip = config["supporter"]["native_server_ip"]
        cls.custom_symbol_loader = config["extended_function"]["custom_symbol_loader"]
        cls.debugserver_ip = config["supporter"]["debugserver_ip"]
        cls.custom_read_memory = config["extended_function"]["custom_read_memory"]
        cls.data_collector = config["extended_function"]["data_collector"]
        cls.listen_host = config["general"]["listen_host"]
        cls.listen_port = config["general"]["listen_port"]

    @classmethod
    def get_config(cls):
        return cls.config


MEMORY_SNAPSHOT = []
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

RegionList = None
ModuleList = None
ModuleListIterator = 0


def readprocessmemory(address, size):
    index = bisect.bisect_left(MEMORY_SNAPSHOT, address, key=lambda x: x["address"])

    if (
        index > 0
        and MEMORY_SNAPSHOT[index - 1]["address"]
        <= address
        < MEMORY_SNAPSHOT[index - 1]["address"] + MEMORY_SNAPSHOT[index - 1]["size"]
    ):
        memory_region = MEMORY_SNAPSHOT[index - 1]
    elif (
        index < len(MEMORY_SNAPSHOT)
        and MEMORY_SNAPSHOT[index]["address"]
        <= address
        < MEMORY_SNAPSHOT[index]["address"] + MEMORY_SNAPSHOT[index]["size"]
    ):
        memory_region = MEMORY_SNAPSHOT[index]
    else:
        return False

    if address + size <= memory_region["address"] + memory_region["size"]:
        offset = address - memory_region["address"]
        return memory_region["data"][offset : offset + size]
    else:
        return False


def virtualqueryex(address):
    global RegionList
    if RegionList is None:
        RegionList = API.VirtualQueryExFull(WinDef.VQE_NOSHARED)
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
        protection = WinDef.PAGE_NOACCESS
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


def get_symbollist_from_file(filename, output):
    if Config.target_os in [OS.LINUX.value, OS.ANDROID.value] and Config.manual_parser:
        ret = SYMBOL_API.GetSymbolListFromFile(filename)
    else:
        ret = API.GetSymbolListFromFile(filename)
    if len(Config.custom_symbol_loader) > 0:
        for symbolfile, filepath in Config.custom_symbol_loader.items():
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
    is_debugserver = (
        Config.target_os == OS.IOS.value or Config.target_os == OS.MAC.value
    )
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
                if Config.arch == ARCHITECTURE.ARM64.value:
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
    global LLDB
    global REGISTER_INFO
    global WP_INFO_LIST
    global CONTINUE_QUEUE
    global PROCESSES
    global SESSION
    global PID
    global API
    global SYMBOL_API
    global MEMORY_SNAPSHOT

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
        if dw_flags & WinDef.TH32CS_SNAPMODULE == WinDef.TH32CS_SNAPMODULE:
            ret = module32first()
            while True:
                if ret:
                    modulename = ret[2].encode()
                    modulenamesize = len(modulename)
                    modulebase = int(ret[0], 16)
                    modulepart = 0
                    modulesize = ret[1]
                    if parse(Config.ceversion) >= parse("7.5.1"):
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
            if parse(Config.ceversion) >= parse("7.5.1"):
                tmp = pack("<iQIIII", 0, 0, 0, 0, 0, 0)
            else:
                tmp = pack("<iQIII", 0, 0, 0, 0, 0)
            bytecode = b"".join([bytecode, tmp])
            ns.sendall(bytecode)
        elif dw_flags & WinDef.TH32CS_SNAPTHREAD == WinDef.TH32CS_SNAPTHREAD:
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
            if Config.mode == MODE.ENUM.value:
                PROCESSES = DEVICE.enumerate_processes()
                process = PROCESSES.pop(0)
                if len(PROCESSES) == 0:
                    ret = 0
                else:
                    ret = 1
            else:
                ret = 1
        else:
            if Config.mode == MODE.ENUM.value:
                process = PROCESSES.pop(0)
                if len(PROCESSES) == 0:
                    ret = 0
                else:
                    ret = 1
            else:
                ret = 0
        if ret != 0:
            if Config.mode == MODE.ENUM.value:
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
            if parse(Config.ceversion) >= parse("7.5.1"):
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
            elif parse(Config.ceversion) >= parse("7.3.1"):
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
            if parse(Config.ceversion) >= parse("7.3.1"):
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
            if Config.native_server == "ceserver":
                writer2.write_uint8(CECMD.CMD_OPENPROCESS)
                writer2.write_int32(pid)
                processhandle = reader2.read_int32()
            else:
                # memory-server
                open_process_url = f"http://{Config.native_server_ip}/openprocess"
                open_process_payload = {"pid": pid}
                open_process_response = requests.post(
                    open_process_url, json=open_process_payload, proxies={}
                )
                if open_process_response.status_code == 200:
                    processhandle = HandleManager.create_handle()
                else:
                    processhandle = 0
        else:
            processhandle = HandleManager.create_handle()

        if Config.mode == MODE.ENUM.value:

            def on_message(message, data):
                print(message)

            SESSION = DEVICE.attach(pid)
            if Config.target_os == OS.WINDOWS.value:
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
            api.SetConfig(Config.get_config())
            symbol_api = 0
            if Config.target_os != OS.WINDOWS.value:
                script2 = SESSION.create_script(jscode2)
                script2.on("message", on_message)
                script2.load()
                symbol_api = script2.exports_sync
            PID = pid
            API = api
            SYMBOL_API = symbol_api
            if Config.data_collector == "mono" or Config.data_collector == "objc":
                mono_pipeserver.mono_init(SESSION, Config.data_collector)
            if Config.java_info:
                java_pipeserver.java_init(SESSION)
        print("Processhandle:" + str(processhandle))
        writer.write_int32(processhandle)

    elif command == CECMD.CMD_GETARCHITECTURE:
        if parse(Config.ceversion) >= parse("7.4.1"):
            handle = reader.read_int32()
        arch_number = arch_to_number(Config.arch)
        writer.write_int8(arch_number)

    elif command == CECMD.CMD_SET_CONNECTION_NAME:
        size = reader.read_int32()
        name = ns.recv(size).decode()
        # print(f"This thread[{thread_count}] is called {name}")

    elif command == CECMD.CMD_READPROCESSMEMORY:
        handle = reader.read_uint32()
        address = reader.read_uint64()
        size = reader.read_uint32()
        compress = reader.read_int8()
        if MEMORY_SNAPSHOT != []:
            ret = readprocessmemory(address, size)
            if ret:
                writer.write_int32(len(ret))
                ns.sendall(ret)
            else:
                writer.write_int32(0)
        else:
            if nc != 0:
                if Config.native_server == "ceserver":
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
                    # memory-server
                    read_memory_url = f"http://{Config.native_server_ip}/readmemory"
                    read_memory_payload = {"address": address, "size": size}
                    read_memory_response = requests.get(
                        read_memory_url, params=read_memory_payload, proxies={}
                    )
                    if read_memory_response.status_code == 200:
                        ret = read_memory_response.content
                    else:
                        ret = False
            else:
                ret = API.ReadProcessmemory(address, size)
            if compress == 0:
                if ret:
                    # iOS
                    if Config.custom_read_memory and Config.target_os == OS.IOS.value:
                        decompress_bytes = b""
                        tmp = ret
                        last_uncompressed = b""
                        # todo:bv4-
                        while True:
                            if (tmp[0:4] != b"bv41") or (tmp[0:4] == b"bv4$"):
                                break
                            uncompressed_size, compressed_size = unpack(
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
                    elif (
                        Config.custom_read_memory
                        and Config.target_os == OS.ANDROID.value
                    ):
                        uncompressed_size = unpack("<I", ret[-4:])[0]
                        decompress_bytes = lz4.block.decompress(
                            ret[:-4], uncompressed_size
                        )
                        ret = decompress_bytes
                    writer.write_int32(len(ret))
                    ns.sendall(ret)
                else:
                    writer.write_int32(0)
            else:
                if ret:
                    if nc != 0 and Config.native_server == "ceserver":
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
            elif address == 101:
                if _buf == b"\x01":
                    MAX_CHUNK_SIZE = 1024 * 1024 * 64  # 64 MB

                    def split_regions_if_necessary(regions):
                        split_regions = []
                        for region in regions:
                            address = region["address"]
                            size = region["size"]
                            if size > MAX_CHUNK_SIZE:
                                start = address
                                while size > 0:
                                    current_chunk_size = min(size, MAX_CHUNK_SIZE)
                                    split_regions.append(
                                        {"address": start, "size": current_chunk_size}
                                    )
                                    start += current_chunk_size
                                    size -= current_chunk_size
                            else:
                                split_regions.append({"address": address, "size": size})
                        return split_regions

                    MEMORY_SNAPSHOT = []
                    print("MEMORY_SNAPSHOT ENABLED")
                    # memory-server
                    regions = API.VirtualQueryExFull(0)
                    read_memory_multiple_url = (
                        f"http://{Config.native_server_ip}/readmemories"
                    )
                    read_memory_multiple_payload = split_regions_if_necessary(
                        [{"address": x[0], "size": x[1]} for x in regions]
                    )
                    read_memory_multiple_response = requests.post(
                        read_memory_multiple_url,
                        json=read_memory_multiple_payload,
                        proxies={},
                    )
                    if read_memory_multiple_response.status_code == 200:
                        ret = read_memory_multiple_response.content
                    else:
                        ret = False
                    if ret:
                        tmp = ret
                        for region in read_memory_multiple_payload:
                            address = region["address"]
                            size = region["size"]
                            is_success = unpack("<I", tmp[:4])[0]
                            if is_success == 1:
                                compressed_size = unpack("<I", tmp[4:8])[0] - 4
                                uncompressed_size = unpack("<I", tmp[8:12])[0]
                                decompress_bytes = lz4.block.decompress(
                                    tmp[12 : 12 + compressed_size],
                                    uncompressed_size=uncompressed_size,
                                )
                                tmp = tmp[12 + compressed_size :]
                                MEMORY_SNAPSHOT.append(
                                    {
                                        "address": address,
                                        "size": size,
                                        "uncompressed_size": uncompressed_size,
                                        "data": decompress_bytes,
                                    }
                                )
                            else:
                                tmp = tmp[4:]
                            if len(tmp) == 0:
                                break
                        print("MEMORY_SNAPSHOT SET")
                else:
                    print("MEMORY_SNAPSHOT DISABLED")
                    MEMORY_SNAPSHOT = []
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
        if parse(Config.ceversion) >= parse("7.5.1"):
            version = 6
            versionstring = "CHEATENGINE Network 2.3".encode()
        elif parse(Config.ceversion) >= parse("7.4.3"):
            version = 5
            versionstring = "CHEATENGINE Network 2.2".encode()
        elif parse(Config.ceversion) >= parse("7.4.2"):
            version = 4
            versionstring = "CHEATENGINE Network 2.2".encode()
        elif parse(Config.ceversion) >= parse("7.3.2"):
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
        if parse(Config.ceversion) >= parse("7.5.1"):
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
        windowsprotection = reader.read_uint32()
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
        target_ip = Config.debugserver_ip.split(":")[0]
        target_port = int(Config.debugserver_ip.split(":")[1])

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
        if parse(Config.ceversion) < parse("7.4.2"):
            _type = reader.read_int32()
        writer.write_int32(1)
        if Config.arch == ARCHITECTURE.ARM64.value:
            if parse(Config.ceversion) >= parse("7.4.2"):
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
        if parse(Config.ceversion) >= parse("7.4.2"):
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
        if windowsprotection == WinDef.PAGE_EXECUTE_READWRITE:
            newprotectionstr = "rwx"
        elif windowsprotection == WinDef.PAGE_EXECUTE_READ:
            newprotectionstr = "r-x"
        elif windowsprotection == WinDef.PAGE_EXECUTE:
            newprotectionstr = "--x"
        elif windowsprotection == WinDef.PAGE_READWRITE:
            newprotectionstr = "rw-"
        elif windowsprotection == WinDef.PAGE_READONLY:
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
    global SYMBOL_API
    global SESSION
    global DEVICE

    Config.load_config(config)

    PID = pid
    API = api
    SYMBOL_API = symbol_api
    DEVICE = device
    SESSION = session

    if (
        Config.data_collector == "mono" or Config.data_collector == "objc"
    ) and Config.mode != MODE.ENUM.value:
        mono_pipeserver.mono_init(session, Config.data_collector)
    if Config.java_info and Config.mode != MODE.ENUM.value:
        java_pipeserver.java_init(SESSION)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        thread_count = 0
        s.bind((Config.listen_host, Config.listen_port))
        s.listen(32)
        s.settimeout(1)
        while True:
            try:
                conn, addr = s.accept()
                print("accept", addr)
                native_client = 0
                if Config.native_server_ip != "":
                    if Config.native_server == "ceserver":
                        target_ip = Config.native_server_ip.split(":")[0]
                        target_port = Config.native_server_ip.split(":")[1]
                        native_client = socket.socket(
                            socket.AF_INET, socket.SOCK_STREAM
                        )
                        native_client.connect((target_ip, int(target_port)))
                    else:
                        # "memory-server"
                        native_client = socket.socket(
                            socket.AF_INET, socket.SOCK_STREAM
                        )

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
