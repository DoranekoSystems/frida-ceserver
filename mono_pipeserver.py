import socket
import select
import sys
from struct import *
import zlib
import time
from enum import IntEnum, auto
import threading

WriteByte = 1
WriteWord = 2
WriteDword = 3
WriteQword = 4
WriteUtf8String = 5
DecodeObject = 6

MONO_DATACOLLECTORVERSION = 20221207

PID = 0
API = 0
SESSION = 0
SCRIPT = 0
DATA_COLLECTOR = 0


class CEPIPECMD(IntEnum):
    MONOCMD_INITMONO = 0
    MONOCMD_OBJECT_GETCLASS = 1
    MONOCMD_ENUMDOMAINS = 2
    MONOCMD_SETCURRENTDOMAIN = 3
    MONOCMD_ENUMASSEMBLIES = 4
    MONOCMD_GETIMAGEFROMASSEMBLY = 5
    MONOCMD_GETIMAGENAME = 6
    MONOCMD_ENUMCLASSESINIMAGE = 7
    MONOCMD_ENUMFIELDSINCLASS = 8
    MONOCMD_ENUMMETHODSINCLASS = 9
    MONOCMD_COMPILEMETHOD = 10

    MONOCMD_GETMETHODHEADER = 11
    MONOCMD_GETMETHODHEADER_CODE = 12
    MONOCMD_LOOKUPRVA = 13
    MONOCMD_GETJITINFO = 14
    MONOCMD_FINDCLASS = 15
    MONOCMD_FINDMETHOD = 16
    MONOCMD_GETMETHODNAME = 17
    MONOCMD_GETMETHODCLASS = 18
    MONOCMD_GETCLASSNAME = 19
    MONOCMD_GETCLASSNAMESPACE = 20
    MONOCMD_FREEMETHOD = 21
    MONOCMD_TERMINATE = 22
    MONOCMD_DISASSEMBLE = 23
    MONOCMD_GETMETHODSIGNATURE = 24
    MONOCMD_GETPARENTCLASS = 25
    MONOCMD_GETSTATICFIELDADDRESSFROMCLASS = 26
    MONOCMD_GETTYPECLASS = 27
    MONOCMD_GETARRAYELEMENTCLASS = 28
    MONOCMD_FINDMETHODBYDESC = 29
    MONOCMD_INVOKEMETHOD = 30
    MONOCMD_LOADASSEMBLY = 31
    MONOCMD_GETFULLTYPENAME = 32
    MONOCMD_OBJECT_NEW = 33
    MONOCMD_OBJECT_INIT = 34
    MONOCMD_GETVTABLEFROMCLASS = 35
    MONOCMD_GETMETHODPARAMETERS = 36
    MONOCMD_ISCLASSGENERIC = 37
    MONOCMD_ISIL2CPP = 38
    MONOCMD_FILLOPTIONALFUNCTIONLIST = 39
    MONOCMD_GETSTATICFIELDVALUE = 40
    MONOCMD_SETSTATICFIELDVALUE = 41
    MONOCMD_GETCLASSIMAGE = 42
    MONOCMD_FREE = 43
    MONOCMD_GETIMAGEFILENAME = 44
    MONOCMD_GETCLASSNESTINGTYPE = 45
    MONOCMD_LIMITEDCONNECTION = 46
    MONOCMD_GETMONODATACOLLECTORVERSION = 47


class BinaryReader:
    def __init__(self):
        self.index = 0
        self.read_message = b""

    def ReadInt8(self):
        result = self.read_message[self.index : self.index + 1]
        ret = unpack("<b", result)[0]
        self.read_message = self.read_message[self.index + 1 :]
        return ret

    def ReadInt16(self):
        result = self.read_message[self.index : self.index + 2]
        ret = unpack("<h", result)[0]
        self.read_message = self.read_message[self.index + 2 :]
        return ret

    def ReadInt32(self):
        result = self.read_message[self.index : self.index + 4]
        ret = unpack("<i", result)[0]
        self.read_message = self.read_message[self.index + 4 :]
        return ret

    def ReadInt64(self):
        result = self.read_message[self.index : self.index + 8]
        ret = unpack("<q", result)[0]
        self.read_message = self.read_message[self.index + 8 :]
        return ret

    def ReadUInt8(self):
        result = self.read_message[self.index : self.index + 1]
        ret = unpack("<B", result)[0]
        self.read_message = self.read_message[self.index + 1 :]
        return ret

    def ReadUInt16(self):
        result = self.read_message[self.index : self.index + 2]
        ret = unpack("<H", result)[0]
        self.read_message = self.read_message[self.index + 2 :]
        return ret

    def ReadUInt32(self):
        result = self.read_message[self.index : self.index + 4]
        ret = unpack("<I", result)[0]
        self.read_message = self.read_message[self.index + 4 :]
        return ret

    def ReadUInt64(self):
        result = self.read_message[self.index : self.index + 8]
        ret = unpack("<Q", result)[0]
        self.read_message = self.read_message[self.index + 8 :]
        return ret

    def WriteMessage(self, message):
        self.read_message += message


class BinaryWriter:
    def __init__(self):
        self.write_message = b""

    def WriteInt8(self, number):
        i8 = pack("<b", number)
        self.write_message += i8

    def WriteInt16(self, number):
        i16 = pack("<h", number)
        self.write_message += i16

    def WriteInt32(self, number):
        i32 = pack("<i", number)
        self.write_message += i32

    def WriteInt64(self, number):
        i64 = pack("<q", number)
        self.write_message += i64

    def WriteUInt8(self, number):
        ui8 = pack("<B", number)
        self.write_message += ui8

    def WriteUInt16(self, number):
        ui16 = pack("<H", number)
        self.write_message += ui16

    def WriteUInt32(self, number):
        ui32 = pack("<I", number)
        self.write_message += ui32

    def WriteUInt64(self, number):
        ui64 = pack("<Q", number)
        self.write_message += ui64

    def WriteUtf8String(self, message):
        self.write_message += message.encode()

    def ReadMessage(self, size):
        ret = self.write_message[0:size]
        self.write_message = self.write_message[size:]
        return ret


WRITER = BinaryWriter()
READER = BinaryReader()
API = 0


def handler(command):
    # print(str(CEPIPECMD(command)))
    if command == CEPIPECMD.MONOCMD_INITMONO:
        API.InitMono()
    elif command == CEPIPECMD.MONOCMD_ISIL2CPP:
        API.IsIL2CPP()
    elif command == CEPIPECMD.MONOCMD_ENUMASSEMBLIES:
        API.EnumAssemblies()
    elif command == CEPIPECMD.MONOCMD_GETIMAGEFROMASSEMBLY:
        yield 0
        assembly = READER.ReadUInt64()
        API.GetImageFromAssembly(assembly)
    elif command == CEPIPECMD.MONOCMD_GETIMAGENAME:
        yield 0
        image = READER.ReadUInt64()
        API.GetImageName(image)
    elif command == CEPIPECMD.MONOCMD_ENUMCLASSESINIMAGE:
        yield 0
        image = READER.ReadUInt64()
        if image == 0:
            WRITER.WriteUInt32(0)
        API.EnumClassesInImage(image)
    elif command == CEPIPECMD.MONOCMD_ENUMDOMAINS:
        WRITER.WriteUInt32(1)
        domain = API.EnumDomains()
        WRITER.WriteUInt64(domain)
    elif command == CEPIPECMD.MONOCMD_ENUMMETHODSINCLASS:
        yield 0
        _class = READER.ReadUInt64()
        API.EnumMethodsInClass(_class)
    elif command == CEPIPECMD.MONOCMD_GETCLASSNESTINGTYPE:
        yield 0
        klass = READER.ReadUInt64()
        WRITER.WriteUInt64(0)
    elif command == CEPIPECMD.MONOCMD_GETFULLTYPENAME:
        yield 0
        klass = READER.ReadUInt64()
        yield 0
        isKlass = READER.ReadUInt8()
        yield 0
        nameformat = READER.ReadUInt32()
        API.GetFullTypeName(klass, isKlass, nameformat)
    elif command == CEPIPECMD.MONOCMD_GETPARENTCLASS:
        yield 0
        klass = READER.ReadUInt64()
        API.GetParentClass(klass)
    elif command == CEPIPECMD.MONOCMD_GETCLASSNAME:
        yield 0
        klass = READER.ReadUInt64()
        API.GetClassName(klass)
    elif command == CEPIPECMD.MONOCMD_GETCLASSNAMESPACE:
        yield 0
        klass = READER.ReadUInt64()
        API.GetClassNameSpace(klass)
    elif command == CEPIPECMD.MONOCMD_GETCLASSIMAGE:
        yield 0
        klass = READER.ReadUInt64()
        API.GetClassImage(klass)
    elif command == CEPIPECMD.MONOCMD_ISCLASSGENERIC:
        yield 0
        klass = READER.ReadUInt64()
        API.IsClassGeneric(klass)
    elif command == CEPIPECMD.MONOCMD_GETSTATICFIELDADDRESSFROMCLASS:
        yield 0
        domain = READER.ReadUInt64()
        yield 0
        klass = READER.ReadUInt64()
        WRITER.WriteUInt64(0)
    elif command == CEPIPECMD.MONOCMD_ENUMFIELDSINCLASS:
        yield 0
        klass = READER.ReadUInt64()
        API.EnumFieldsInClass(klass)
    elif command == CEPIPECMD.MONOCMD_GETMETHODSIGNATURE:
        yield 0
        method = READER.ReadUInt64()
        API.GetMethodSignature(method)
    elif command == CEPIPECMD.MONOCMD_GETSTATICFIELDVALUE:
        yield 0
        vtable = READER.ReadUInt64()
        yield 0
        field = READER.ReadUInt64()
        API.GetStaticFieldValue(vtable, field)
    elif command == CEPIPECMD.MONOCMD_SETSTATICFIELDVALUE:
        yield 0
        vtable = READER.ReadUInt64()
        yield 0
        field = READER.ReadUInt64()
        yield 0
        val = READER.ReadUInt64()
        API.SetStaticFieldValue(vtable, field, val)
    elif command == CEPIPECMD.MONOCMD_COMPILEMETHOD:
        yield 0
        method = READER.ReadUInt64()
        methodPtr = API.CompileMethod(method)
        WRITER.WriteUInt64(methodPtr)
    elif command == CEPIPECMD.MONOCMD_GETMONODATACOLLECTORVERSION:
        WRITER.WriteUInt32(MONO_DATACOLLECTORVERSION)
    else:
        pass
    yield 1


IS_COMMAND = True
HANDLER = 0


def mono_process(buf):
    global IS_COMMAND
    global HANDLER
    READER.WriteMessage(buf)
    if IS_COMMAND:
        try:
            IS_COMMAND = False
            command = READER.ReadUInt8()
            HANDLER = handler(command)
            ret = HANDLER.__next__()
            if ret == 1:
                IS_COMMAND = True
        except:
            import traceback

            print("EXCEPTION:" + str(CEPIPECMD(command)))
            traceback.print_exc()
            return
        if ret == -1:
            return
        return
    else:
        ret = HANDLER.__next__()
        if ret == 1:
            IS_COMMAND = True


def on_message(message, data):
    if message["type"] == "send":
        _type = message["payload"][0]
        value = message["payload"][1]
        if _type == WriteByte:
            WRITER.WriteUInt8(value)
        elif _type == WriteWord:
            WRITER.WriteUInt16(value)
        elif _type == WriteDword:
            WRITER.WriteUInt32(value)
        elif _type == WriteQword:
            WRITER.WriteUInt64(value)
        elif _type == WriteUtf8String:
            WRITER.WriteUtf8String(value)
        elif _type == DecodeObject:
            pass
            # SCRIPT.post({"type": "input", "payload": decode(value)})
    else:
        print(message)


def mono_init(session, data_collector):
    global API
    global SCRIPT
    global DATA_COLLECTOR
    if data_collector == "mono":
        filename = "mono_core.js"
    else:
        filename = "objc_core.js"
    DATA_COLLECTOR = data_collector
    with open(f"javascript/{filename}") as f:
        jscode = f.read()
    script = session.create_script(jscode)
    script.on("message", on_message)
    script.load()
    api = script.exports
    API = api
    SCRIPT = script
