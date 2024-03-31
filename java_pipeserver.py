from enum import IntEnum
from struct import pack, unpack

import win32file
import win32pipe

WriteByte = 1
WriteWord = 2
WriteDWord = 3
WriteQWord = 4

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
    def __init__(self, pipe):
        self.pipe = pipe

    def ReadInt8(self):
        hr, result = win32file.ReadFile(self.pipe, 1)
        ret = unpack("<b", result)[0]
        return ret

    def ReadInt16(self):
        hr, result = win32file.ReadFile(self.pipe, 2)
        ret = unpack("<h", result)[0]
        return ret

    def ReadInt32(self):
        hr, result = win32file.ReadFile(self.pipe, 4)
        ret = unpack("<i", result)[0]
        return ret

    def ReadInt64(self):
        hr, result = win32file.ReadFile(self.pipe, 8)
        ret = unpack("<q", result)[0]
        return ret

    def ReadUInt8(self):
        hr, result = win32file.ReadFile(self.pipe, 1)
        ret = unpack("<B", result)[0]
        return ret

    def ReadUInt16(self):
        hr, result = win32file.ReadFile(self.pipe, 2)
        ret = unpack("<H", result)[0]
        return ret

    def ReadUInt32(self):
        hr, result = win32file.ReadFile(self.pipe, 4)
        ret = unpack("<I", result)[0]
        return ret

    def ReadUInt64(self):
        hr, result = win32file.ReadFile(self.pipe, 8)
        ret = unpack("<Q", result)[0]
        return ret


class BinaryWriter:
    def __init__(self, pipe):
        self.pipe = pipe

    def WriteInt8(self, number):
        i8 = pack("<b", number)
        win32file.WriteFile(self.pipe, i8)

    def WriteInt16(self, number):
        i16 = pack("<h", number)
        win32file.WriteFile(self.pipe, i16)

    def WriteInt32(self, number):
        i32 = pack("<i", number)
        win32file.WriteFile(self.pipe, i32)

    def WriteInt64(self, number):
        i64 = pack("<q", number)
        win32file.WriteFile(self.pipe, i64)

    def WriteUInt8(self, number):
        ui8 = pack("<B", number)
        win32file.WriteFile(self.pipe, ui8)

    def WriteUInt16(self, number):
        ui16 = pack("<H", number)
        win32file.WriteFile(self.pipe, ui16)

    def WriteUInt32(self, number):
        ui32 = pack("<I", number)
        win32file.WriteFile(self.pipe, ui32)

    def WriteUInt64(self, number):
        ui64 = pack("<Q", number)
        win32file.WriteFile(self.pipe, ui64)

    def WriteUtf8String(self, message):
        win32file.WriteFile(self.pipe, message.encode())


def handler(pipe, command):
    global process_id
    global CLASSES_INFO
    global CLASSES_INFO2

    reader = BinaryReader(pipe)
    writer = BinaryWriter(pipe)
    # print(str(CEPIPECMD(command)))
    if command == CEPIPECMD.JAVACMD_STARTCODECALLBACKS:
        pass

    elif command == CEPIPECMD.JAVACMD_GETCAPABILITIES:
        for i in range(15):
            writer.WriteInt8(1)

    elif command == CEPIPECMD.JAVACMD_GETLOADEDCLASSES:
        classes = API.GetLoadedClasses()
        writer.WriteInt32(len(classes))
        for _class in classes:
            name = _class[0]
            handle = int(_class[1], 16)
            writer.WriteInt64(handle)
            writer.WriteInt16(len(name))
            writer.WriteUtf8String(name)
            writer.WriteInt16(0)
            CLASSES_INFO[handle] = name
            CLASSES_INFO2[name] = handle

    elif command == CEPIPECMD.JAVACMD_GETCLASSMETHODS:
        handle = reader.ReadInt64()
        name = CLASSES_INFO[handle]
        try:
            methods = API.GetClassMethods(name)[0]["classes"][0]["methods"]
        except Exception:
            writer.WriteInt32(0)
            return
        writer.WriteInt32(len(methods))
        for i, method in enumerate(methods):
            writer.WriteInt64(i)
            writer.WriteInt16(len(method))
            writer.WriteUtf8String(method)
            writer.WriteInt16(0)
            writer.WriteInt16(0)

    elif command == CEPIPECMD.JAVACMD_GETCLASSFIELDS:
        handle = reader.ReadInt64()
        name = CLASSES_INFO[handle]
        fields = API.GetClassFields(name)
        writer.WriteInt32(len(fields))
        for i, field in enumerate(fields):
            writer.WriteInt64(i)
            writer.WriteInt16(len(field))
            writer.WriteUtf8String(field)
            writer.WriteInt16(0)
            writer.WriteInt16(0)

    elif command == CEPIPECMD.JAVACMD_GETIMPLEMENTEDINTERFACES:
        handle = reader.ReadInt64()
        writer.WriteInt32(0)

    elif command == CEPIPECMD.JAVACMD_GETSUPERCLASS:
        handle = reader.ReadInt64()
        name = CLASSES_INFO[handle]
        className = API.GetSuperClass(name)
        if className in CLASSES_INFO2:
            superclassHandle = CLASSES_INFO2[className]
        else:
            superclassHandle = 0
        writer.WriteInt64(superclassHandle)

    elif command == CEPIPECMD.JAVACMD_GETCLASSSIGNATURE:
        handle = reader.ReadInt64()
        name = CLASSES_INFO[handle]
        writer.WriteInt16(len(name))
        writer.WriteUtf8String(name)
        writer.WriteInt16(0)

    elif command == CEPIPECMD.JAVACMD_DEREFERENCELOCALOBJECT:
        _ = reader.ReadInt64()

    else:
        pass
    return 1


def main_thread(pipe):
    while True:
        try:
            command = READER.ReadUInt8()
            ret = handler(pipe, command)
        except Exception:
            import traceback

            print("EXCEPTION:" + str(CEPIPECMD(command)))
            traceback.print_exc()
            break
        if ret == -1:
            break


def on_message(message, data):
    print(message)


def pipeserver(pid, session):
    global PID
    global API
    global READER
    global WRITER

    with open("javascript/java_core.js") as f:
        jscode = f.read()
    script = session.create_script(jscode)
    script.on("message", on_message)
    script.load()
    api = script.exports

    PID = pid
    API = api

    pipe = win32pipe.CreateNamedPipe(
        "\\\\.\\pipe\\cejavadc_pid" + str(pid),
        win32pipe.PIPE_ACCESS_DUPLEX,
        win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
        1,
        256,
        256,
        0,
        None,
    )

    win32pipe.ConnectNamedPipe(pipe, None)
    print("Connect!")
    READER = BinaryReader(pipe)
    WRITER = BinaryWriter(pipe)
    main_thread(pipe)
