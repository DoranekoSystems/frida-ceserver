from define import MONOPIPECMD
from util import PipeReadEmulator, PipeWriteEmulator

WriteByte = 1
WriteWord = 2
WriteDword = 3
WriteQword = 4
WriteUtf8String = 5
DecodeObject = 6

MONO_DATACOLLECTORVERSION = 20231214

PID = 0
API = 0
SESSION = 0
SCRIPT = 0

THREAD_STATES = {}


class ThreadState:
    def __init__(self, tid):
        self.is_command = True
        self.handler = None
        self.writer = PipeWriteEmulator()
        self.reader = PipeReadEmulator()
        self.tid = tid


def handler(command, state):
    tid = state.tid

    # print(str(MONOPIPECMD(command).name))
    if command == MONOPIPECMD.MONOCMD_INITMONO:
        API.InitMono(tid)
    elif command == MONOPIPECMD.MONOCMD_ISIL2CPP:
        API.IsIL2CPP(tid)
    elif command == MONOPIPECMD.MONOCMD_ENUMASSEMBLIES:
        API.EnumAssemblies(tid)
    elif command == MONOPIPECMD.MONOCMD_GETIMAGEFROMASSEMBLY:
        yield 0
        assembly = state.reader.read_uint64()
        API.GetImageFromAssembly(tid, assembly)
    elif command == MONOPIPECMD.MONOCMD_GETIMAGENAME:
        yield 0
        image = state.reader.read_uint64()
        API.GetImageName(tid, image)
    elif command == MONOPIPECMD.MONOCMD_ENUMCLASSESINIMAGE:
        yield 0
        image = state.reader.read_uint64()
        if image == 0:
            state.writer.write_uint32(0)
        API.EnumClassesInImage(tid, image)
    elif command == MONOPIPECMD.MONOCMD_ENUMDOMAINS:
        state.writer.write_uint32(1)
        domain = API.EnumDomains(tid)
        state.writer.write_uint64(domain)
    elif command == MONOPIPECMD.MONOCMD_ENUMMETHODSINCLASS:
        yield 0
        _class = state.reader.read_uint64()
        API.EnumMethodsInClass(tid, _class)
    elif command == MONOPIPECMD.MONOCMD_GETCLASSNESTINGTYPE:
        yield 0
        klass = state.reader.read_uint64()
        state.writer.write_uint64(0)
    elif command == MONOPIPECMD.MONOCMD_GETFULLTYPENAME:
        yield 0
        klass = state.reader.read_uint64()
        yield 0
        is_klass = state.reader.read_uint8()
        yield 0
        nameformat = state.reader.read_uint32()
        API.GetFullTypeName(tid, klass, is_klass, nameformat)
    elif command == MONOPIPECMD.MONOCMD_GETPARENTCLASS:
        yield 0
        klass = state.reader.read_uint64()
        API.GetParentClass(tid, klass)
    elif command == MONOPIPECMD.MONOCMD_GETCLASSNAME:
        yield 0
        klass = state.reader.read_uint64()
        API.GetClassName(tid, klass)
    elif command == MONOPIPECMD.MONOCMD_GETCLASSNAMESPACE:
        yield 0
        klass = state.reader.read_uint64()
        API.GetClassNameSpace(tid, klass)
    elif command == MONOPIPECMD.MONOCMD_GETCLASSIMAGE:
        yield 0
        klass = state.reader.read_uint64()
        API.GetClassImage(tid, klass)
    elif command == MONOPIPECMD.MONOCMD_ISCLASSGENERIC:
        yield 0
        klass = state.reader.read_uint64()
        API.IsClassGeneric(tid, klass)
    elif command == MONOPIPECMD.MONOCMD_GETSTATICFIELDADDRESSFROMCLASS:
        yield 0
        domain = state.reader.read_uint64()
        yield 0
        klass = state.reader.read_uint64()
        state.writer.write_uint64(0)
    elif command == MONOPIPECMD.MONOCMD_ENUMFIELDSINCLASS:
        yield 0
        klass = state.reader.read_uint64()
        API.EnumFieldsInClass(tid, klass)
    elif command == MONOPIPECMD.MONOCMD_GETMETHODSIGNATURE:
        yield 0
        method = state.reader.read_uint64()
        API.GetMethodSignature(tid, method)
    elif command == MONOPIPECMD.MONOCMD_GETSTATICFIELDVALUE:
        yield 0
        vtable = state.reader.read_uint64()
        yield 0
        field = state.reader.read_uint64()
        API.GetStaticFieldValue(tid, vtable, field)
    elif command == MONOPIPECMD.MONOCMD_SETSTATICFIELDVALUE:
        yield 0
        vtable = state.reader.read_uint64()
        yield 0
        field = state.reader.read_uint64()
        yield 0
        val = state.reader.read_uint64()
        API.SetStaticFieldValue(tid, vtable, field, val)
    elif command == MONOPIPECMD.MONOCMD_COMPILEMETHOD:
        yield 0
        method = state.reader.read_uint64()
        method_ptr = API.CompileMethod(tid, method)
        state.writer.write_uint64(method_ptr)
    elif command == MONOPIPECMD.MONOCMD_GETMONODATACOLLECTORVERSION:
        state.writer.write_uint32(MONO_DATACOLLECTORVERSION)
    elif command == MONOPIPECMD.MONOCMD_ENUMIMAGES:
        data = API.EnumImages(tid)
        state.writer.write_uint32(len(data))
        state.writer.write_byte_array(data)
    elif command == MONOPIPECMD.MONOCMD_ENUMCLASSESINIMAGEEX:
        yield 0
        image = state.reader.read_uint64()
        data = API.EnumClassesInImageEX(tid, image)
        state.writer.write_uint32(len(data))
        state.writer.write_byte_array(data)
    elif command == MONOPIPECMD.MONOCMD_GETFIELDCLASS:
        yield 0
        field = state.reader.read_uint64()
        API.GetFieldClass(tid, field)
    elif command == MONOPIPECMD.MONOCMD_ISCLASSVALUETYPE:
        yield 0
        klass = state.reader.read_uint64()
        API.IsValueTypeClass(tid, klass)
    elif command == MONOPIPECMD.MONOCMD_FILLOPTIONALFUNCTIONLIST:
        yield 0
        _mono_type_get_name_full = state.reader.read_uint64()
        state.writer.write_int8(1)
    elif command == MONOPIPECMD.MONOCMD_GETVTABLEFROMCLASS:
        yield 0
        state.reader.read_uint64()
        yield 0
        state.reader.read_uint64()
        yield 0
        state.writer.write_int32(0)
    else:
        pass
    yield 1


def mono_process(tid, buf):
    if tid not in THREAD_STATES:
        THREAD_STATES[tid] = ThreadState(tid)
    state = THREAD_STATES[tid]

    state.reader.write_message(buf)
    while state.reader.get_message_size() > 0:
        if state.is_command:
            try:
                state.is_command = False
                command = state.reader.read_uint8()
                state.handler = handler(command, state)
                ret = state.handler.__next__()
                if ret == 1:
                    state.is_command = True
            except Exception:
                import traceback

                print("EXCEPTION:" + str(MONOPIPECMD(command)))
                traceback.print_exc()
                return
            if ret == -1:
                return
        else:
            try:
                ret = state.handler.__next__()
                if ret == 1:
                    state.is_command = True
            except Exception:
                import traceback

                print("EXCEPTION:" + str(MONOPIPECMD(command)))
                traceback.print_exc()
                time.sleep(10)
                return


def on_message(message, data):
    if message["type"] == "send":
        tid = message["payload"]["tid"]
        _type = message["payload"]["info"][0]
        value = message["payload"]["info"][1]

        if tid not in THREAD_STATES:
            THREAD_STATES[tid] = ThreadState(tid)
        state = THREAD_STATES[tid]
        if _type == WriteByte:
            state.writer.write_uint8(value)
        elif _type == WriteWord:
            state.writer.write_uint16(value)
        elif _type == WriteDword:
            state.writer.write_uint32(value)
        elif _type == WriteQword:
            state.writer.write_uint64(value)
        elif _type == WriteUtf8String:
            state.writer.write_utf8_string(value)
        elif _type == DecodeObject:
            pass
    else:
        print(message)


def mono_init(session, data_collector):
    global API
    global SCRIPT
    if data_collector == "mono":
        filename = "mono_core.js"
    else:
        filename = "objc_core.js"
    with open(f"javascript/{filename}") as f:
        jscode = f.read()
    script = session.create_script(jscode)
    script.on("message", on_message)
    script.load()
    api = script.exports_sync
    API = api
    SCRIPT = script
