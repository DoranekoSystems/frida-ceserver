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

WRITER = PipeWriteEmulator()
READER = PipeReadEmulator()


def handler(command):
    # print(str(MONOPIPECMD(command).name))
    if command == MONOPIPECMD.MONOCMD_INITMONO:
        API.InitMono()
    elif command == MONOPIPECMD.MONOCMD_ISIL2CPP:
        API.IsIL2CPP()
    elif command == MONOPIPECMD.MONOCMD_ENUMASSEMBLIES:
        API.EnumAssemblies()
    elif command == MONOPIPECMD.MONOCMD_GETIMAGEFROMASSEMBLY:
        yield 0
        assembly = READER.read_uint64()
        API.GetImageFromAssembly(assembly)
    elif command == MONOPIPECMD.MONOCMD_GETIMAGENAME:
        yield 0
        image = READER.read_uint64()
        API.GetImageName(image)
    elif command == MONOPIPECMD.MONOCMD_ENUMCLASSESINIMAGE:
        yield 0
        image = READER.read_uint64()
        if image == 0:
            WRITER.write_uint32(0)
        API.EnumClassesInImage(image)
    elif command == MONOPIPECMD.MONOCMD_ENUMDOMAINS:
        WRITER.write_uint32(1)
        domain = API.EnumDomains()
        WRITER.write_uint64(domain)
    elif command == MONOPIPECMD.MONOCMD_ENUMMETHODSINCLASS:
        yield 0
        _class = READER.read_uint64()
        API.EnumMethodsInClass(_class)
    elif command == MONOPIPECMD.MONOCMD_GETCLASSNESTINGTYPE:
        yield 0
        klass = READER.read_uint64()
        WRITER.write_uint64(0)
    elif command == MONOPIPECMD.MONOCMD_GETFULLTYPENAME:
        yield 0
        klass = READER.read_uint64()
        yield 0
        is_klass = READER.read_uint8()
        yield 0
        nameformat = READER.read_uint32()
        API.GetFullTypeName(klass, is_klass, nameformat)
    elif command == MONOPIPECMD.MONOCMD_GETPARENTCLASS:
        yield 0
        klass = READER.read_uint64()
        API.GetParentClass(klass)
    elif command == MONOPIPECMD.MONOCMD_GETCLASSNAME:
        yield 0
        klass = READER.read_uint64()
        API.GetClassName(klass)
    elif command == MONOPIPECMD.MONOCMD_GETCLASSNAMESPACE:
        yield 0
        klass = READER.read_uint64()
        API.GetClassNameSpace(klass)
    elif command == MONOPIPECMD.MONOCMD_GETCLASSIMAGE:
        yield 0
        klass = READER.read_uint64()
        API.GetClassImage(klass)
    elif command == MONOPIPECMD.MONOCMD_ISCLASSGENERIC:
        yield 0
        klass = READER.read_uint64()
        API.IsClassGeneric(klass)
    elif command == MONOPIPECMD.MONOCMD_GETSTATICFIELDADDRESSFROMCLASS:
        yield 0
        domain = READER.read_uint64()
        yield 0
        klass = READER.read_uint64()
        WRITER.write_uint64(0)
    elif command == MONOPIPECMD.MONOCMD_ENUMFIELDSINCLASS:
        yield 0
        klass = READER.read_uint64()
        API.EnumFieldsInClass(klass)
    elif command == MONOPIPECMD.MONOCMD_GETMETHODSIGNATURE:
        yield 0
        method = READER.read_uint64()
        API.GetMethodSignature(method)
    elif command == MONOPIPECMD.MONOCMD_GETSTATICFIELDVALUE:
        yield 0
        vtable = READER.read_uint64()
        yield 0
        field = READER.read_uint64()
        API.GetStaticFieldValue(vtable, field)
    elif command == MONOPIPECMD.MONOCMD_SETSTATICFIELDVALUE:
        yield 0
        vtable = READER.read_uint64()
        yield 0
        field = READER.read_uint64()
        yield 0
        val = READER.read_uint64()
        API.SetStaticFieldValue(vtable, field, val)
    elif command == MONOPIPECMD.MONOCMD_COMPILEMETHOD:
        yield 0
        method = READER.read_uint64()
        method_ptr = API.CompileMethod(method)
        WRITER.write_uint64(method_ptr)
    elif command == MONOPIPECMD.MONOCMD_GETMONODATACOLLECTORVERSION:
        WRITER.write_uint32(MONO_DATACOLLECTORVERSION)
    elif command == MONOPIPECMD.MONOCMD_ENUMIMAGES:
        data = API.EnumImages()
        WRITER.write_uint32(len(data))
        WRITER.write_byte_array(data)
    elif command == MONOPIPECMD.MONOCMD_ENUMCLASSESINIMAGEEX:
        yield 0
        image = READER.read_uint64()
        data = API.EnumClassesInImageEX(image)
        WRITER.write_uint32(len(data))
        WRITER.write_byte_array(data)
    elif command == MONOPIPECMD.MONOCMD_GETFIELDCLASS:
        yield 0
        field = READER.read_uint64()
        API.GetFieldClass(field)
    elif command == MONOPIPECMD.MONOCMD_ISCLASSVALUETYPE:
        yield 0
        klass = READER.read_uint64()
        API.IsValueTypeClass(klass)
    elif command == MONOPIPECMD.MONOCMD_FILLOPTIONALFUNCTIONLIST:
        yield 0
        _mono_type_get_name_full = READER.read_uint64()
        WRITER.write_int8(1)
    else:
        pass
    yield 1


IS_COMMAND = True
HANDLER = 0


def mono_process(buf):
    global IS_COMMAND
    global HANDLER
    READER.write_message(buf)
    while READER.get_message_size() > 0:
        if IS_COMMAND:
            try:
                IS_COMMAND = False
                command = READER.read_uint8()
                HANDLER = handler(command)
                ret = HANDLER.__next__()
                if ret == 1:
                    IS_COMMAND = True
            except Exception:
                import traceback

                print("EXCEPTION:" + str(MONOPIPECMD(command)))
                traceback.print_exc()
                return
            if ret == -1:
                return
        else:
            try:
                ret = HANDLER.__next__()
                if ret == 1:
                    IS_COMMAND = True
            except Exception:
                import traceback

                print("EXCEPTION:" + str(MONOPIPECMD(command)))
                traceback.print_exc()
                return


def on_message(message, data):
    if message["type"] == "send":
        _type = message["payload"][0]
        value = message["payload"][1]
        if _type == WriteByte:
            WRITER.write_uint8(value)
        elif _type == WriteWord:
            WRITER.write_uint16(value)
        elif _type == WriteDword:
            WRITER.write_uint32(value)
        elif _type == WriteQword:
            WRITER.write_uint64(value)
        elif _type == WriteUtf8String:
            WRITER.write_utf8_string(value)
        elif _type == DecodeObject:
            pass
            # SCRIPT.post({"type": "input", "payload": decode(value)})
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
