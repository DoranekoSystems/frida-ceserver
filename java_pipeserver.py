from enum import IntEnum
from struct import pack, unpack

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


class CEPIPECMD(IntEnum):
    JAVACMD_STARTCODECALLBACKS = 0
    JAVACMD_STOPCODECALLBACKS = 1
    JAVACMD_GETLOADEDCLASSES = 2
    JAVACMD_DEREFERENCELOCALOBJECT = 3
    JAVACMD_GETCLASSMETHODS = 4
    JAVACMD_GETCLASSFIELDS = 5
    JAVACMD_GETIMPLEMENTEDINTERFACES = 6
    JAVAVMD_FINDREFERENCESTOOBJECT = 7
    JAVACMD_FINDJOBJECT = 8
    JAVACMD_GETCLASSSIGNATURE = 9
    JAVACMD_GETSUPERCLASS = 10
    JAVACMD_GETOBJECTCLASS = 11
    JAVACMD_GETCLASSDATA = 12
    JAVACMD_REDEFINECLASS = 13
    JAVACMD_FINDCLASS = 14
    JAVACMD_GETCAPABILITIES = 15
    JAVACMD_GETMETHODNAME = 16
    JAVACMD_INVOKEMETHOD = 17
    JAVACMD_FINDCLASSOBJECTS = 18
    JAVACMD_ADDTOBOOTSTRAPCLASSLOADERPATH = 19
    JAVACMD_ADDTOSYSTEMCLASSLOADERPATH = 20
    JAVACMD_PUSHLOCALFRAME = 21
    JAVACMD_POPLOCALFRAME = 22
    JAVACMD_GETFIELDDECLARINGCLASS = 23
    JAVACMD_GETFIELDSIGNATURE = 24
    JAVACMD_GETFIELD = 25
    JAVACMD_SETFIELD = 26
    JAVACMD_STARTSCAN = 27
    JAVACMD_REFINESCANRESULTS = 28
    JAVACMD_GETSCANRESULTS = 29
    JAVACMD_FINDWHATWRITES = 30
    JAVACMD_STOPFINDWHATWRITES = 31
    JAVACMD_GETMETHODDECLARINGCLASS = 32


class BinaryReader:
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


class BinaryWriter:
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


WRITER = BinaryWriter()
READER = BinaryReader()


def handler(command):
    global process_id
    global CLASSES_INFO
    global CLASSES_INFO2

    # print(str(CEPIPECMD(command)))
    if command == CEPIPECMD.JAVACMD_STARTCODECALLBACKS:
        pass

    elif command == CEPIPECMD.JAVACMD_GETCAPABILITIES:
        for i in range(15):
            WRITER.WriteInt8(1)

    elif command == CEPIPECMD.JAVACMD_GETLOADEDCLASSES:
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

    elif command == CEPIPECMD.JAVACMD_GETCLASSMETHODS:
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

    elif command == CEPIPECMD.JAVACMD_GETCLASSFIELDS:
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

    elif command == CEPIPECMD.JAVACMD_GETIMPLEMENTEDINTERFACES:
        yield 0
        handle = READER.ReadInt64()
        WRITER.WriteInt32(0)

    elif command == CEPIPECMD.JAVACMD_GETSUPERCLASS:
        yield 0
        handle = READER.ReadInt64()
        name = CLASSES_INFO[handle]
        class_name = API.GetSuperClass(name)
        if class_name in CLASSES_INFO2:
            super_class_handle = CLASSES_INFO2[class_name]
        else:
            super_class_handle = 0
        WRITER.WriteInt64(super_class_handle)

    elif command == CEPIPECMD.JAVACMD_GETCLASSSIGNATURE:
        yield 0
        handle = READER.ReadInt64()
        name = CLASSES_INFO[handle]
        WRITER.WriteInt16(len(name))
        WRITER.WriteUtf8String(name)
        WRITER.WriteInt16(0)

    elif command == CEPIPECMD.JAVACMD_DEREFERENCELOCALOBJECT:
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

                print("EXCEPTION:" + str(CEPIPECMD(command)))
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

                print("EXCEPTION:" + str(CEPIPECMD(command)))
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
