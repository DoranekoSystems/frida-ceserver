from define import JAVAPIPECMD
from util import PipeReadEmulator, PipeWriteEmulator

WriteByte = 1
WriteWord = 2
WriteDword = 3
WriteQword = 4
WriteUtf8String = 5
DecodeObject = 6

PID = 0
API = 0
SESSION = 0
CLASSES_INFO = {}
CLASSES_INFO2 = {}


WRITER = PipeWriteEmulator()
READER = PipeReadEmulator()


def handler(command):
    global process_id
    global CLASSES_INFO
    global CLASSES_INFO2

    # print(str(JAVAPIPECMD(command)))
    if command == JAVAPIPECMD.JAVACMD_STARTCODECALLBACKS:
        pass

    elif command == JAVAPIPECMD.JAVACMD_GETCAPABILITIES:
        for i in range(15):
            WRITER.WriteInt8(1)

    elif command == JAVAPIPECMD.JAVACMD_GETLOADEDCLASSES:
        classes = API.GetLoadedClasses()
        WRITER.WriteInt32(len(classes))
        for _class in classes:
            name = _class[0]
            handle = int(_class[1], 16)
            WRITER.WriteInt64(handle)
            WRITER.WriteInt16(len(name))
            WRITER.WriteUtf8String(name)
            WRITER.WriteInt16(0)
            CLASSES_INFO[handle] = name
            CLASSES_INFO2[name] = handle

    elif command == JAVAPIPECMD.JAVACMD_GETCLASSMETHODS:
        yield 0
        handle = READER.ReadInt64()
        name = CLASSES_INFO[handle]
        try:
            methods = API.GetClassMethods(name)[0]["classes"][0]["methods"]
        except Exception:
            WRITER.WriteInt32(0)
            return
        WRITER.WriteInt32(len(methods))
        for i, method in enumerate(methods):
            WRITER.WriteInt64(i)
            WRITER.WriteInt16(len(method))
            WRITER.WriteUtf8String(method)
            WRITER.WriteInt16(0)
            WRITER.WriteInt16(0)

    elif command == JAVAPIPECMD.JAVACMD_GETCLASSFIELDS:
        yield 0
        handle = READER.ReadInt64()
        name = CLASSES_INFO[handle]
        fields = API.GetClassFields(name)
        WRITER.WriteInt32(len(fields))
        for i, field in enumerate(fields):
            WRITER.WriteInt64(i)
            WRITER.WriteInt16(len(field))
            WRITER.WriteUtf8String(field)
            WRITER.WriteInt16(0)
            WRITER.WriteInt16(0)

    elif command == JAVAPIPECMD.JAVACMD_GETIMPLEMENTEDINTERFACES:
        yield 0
        handle = READER.ReadInt64()
        WRITER.WriteInt32(0)

    elif command == JAVAPIPECMD.JAVACMD_GETSUPERCLASS:
        yield 0
        handle = READER.ReadInt64()
        name = CLASSES_INFO[handle]
        class_name = API.GetSuperClass(name)
        if class_name in CLASSES_INFO2:
            super_class_handle = CLASSES_INFO2[class_name]
        else:
            super_class_handle = 0
        WRITER.WriteInt64(super_class_handle)

    elif command == JAVAPIPECMD.JAVACMD_GETCLASSSIGNATURE:
        yield 0
        handle = READER.ReadInt64()
        name = CLASSES_INFO[handle]
        WRITER.WriteInt16(len(name))
        WRITER.WriteUtf8String(name)
        WRITER.WriteInt16(0)

    elif command == JAVAPIPECMD.JAVACMD_DEREFERENCELOCALOBJECT:
        yield 0
        _ = READER.ReadInt64()

    else:
        pass
    return 1


IS_COMMAND = True
HANDLER = 0


def java_process(buf):
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

                print("EXCEPTION:" + str(JAVAPIPECMD(command)))
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

                print("EXCEPTION:" + str(JAVAPIPECMD(command)))
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


def java_init(session):
    global API
    global SCRIPT

    with open("javascript/java_core.js") as f:
        jscode = f.read()
    script = session.create_script(jscode)
    script.on("message", on_message)
    script.load()
    api = script.exports_sync
    API = api
    SCRIPT = script
