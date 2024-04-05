from enum import IntEnum
from struct import pack, unpack

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
    MONOCMD_GETFIELDCLASS = 27
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
    MONOCMD_NEWSTRING = 48
    MONOCMD_ENUMIMAGES = 49
    MONOCMD_ENUMCLASSESINIMAGEEX = 50
    MONOCMD_ISCLASSENUM = 51
    MONOCMD_ISCLASSVALUETYPE = 52
    MONOCMD_ISCLASSISSUBCLASSOF = 53
    MONOCMD_ARRAYELEMENTSIZE = 54
    MONOCMD_GETCLASSTYPE = 55
    MONOCMD_GETCLASSOFTYPE = 56
    MONOCMD_GETTYPEOFMONOTYPE = 57
    MONOCMD_GETREFLECTIONTYPEOFCLASSTYPE = 58
    MONOCMD_GETREFLECTIONMETHODOFMONOMETHOD = 59
    MONOCMD_MONOOBJECTUNBOX = 60
    MONOCMD_MONOARRAYNEW = 61
    MONOCMD_ENUMINTERFACESOFCLASS = 62


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
API = 0


def handler(command):
    # print(str(CEPIPECMD(command).name))
    if command == CEPIPECMD.MONOCMD_INITMONO:
        API.InitMono()
    elif command == CEPIPECMD.MONOCMD_ISIL2CPP:
        API.IsIL2CPP()
    elif command == CEPIPECMD.MONOCMD_ENUMASSEMBLIES:
        API.EnumAssemblies()
    elif command == CEPIPECMD.MONOCMD_GETIMAGEFROMASSEMBLY:
        yield 0
        assembly = READER.read_uint64()
        API.GetImageFromAssembly(assembly)
    elif command == CEPIPECMD.MONOCMD_GETIMAGENAME:
        yield 0
        image = READER.read_uint64()
        API.GetImageName(image)
    elif command == CEPIPECMD.MONOCMD_ENUMCLASSESINIMAGE:
        yield 0
        image = READER.read_uint64()
        if image == 0:
            WRITER.write_uint32(0)
        API.EnumClassesInImage(image)
    elif command == CEPIPECMD.MONOCMD_ENUMDOMAINS:
        WRITER.write_uint32(1)
        domain = API.EnumDomains()
        WRITER.write_uint64(domain)
    elif command == CEPIPECMD.MONOCMD_ENUMMETHODSINCLASS:
        yield 0
        _class = READER.read_uint64()
        API.EnumMethodsInClass(_class)
    elif command == CEPIPECMD.MONOCMD_GETCLASSNESTINGTYPE:
        yield 0
        klass = READER.read_uint64()
        WRITER.write_uint64(0)
    elif command == CEPIPECMD.MONOCMD_GETFULLTYPENAME:
        yield 0
        klass = READER.read_uint64()
        yield 0
        is_klass = READER.read_uint8()
        yield 0
        nameformat = READER.read_uint32()
        API.GetFullTypeName(klass, is_klass, nameformat)
    elif command == CEPIPECMD.MONOCMD_GETPARENTCLASS:
        yield 0
        klass = READER.read_uint64()
        API.GetParentClass(klass)
    elif command == CEPIPECMD.MONOCMD_GETCLASSNAME:
        yield 0
        klass = READER.read_uint64()
        API.GetClassName(klass)
    elif command == CEPIPECMD.MONOCMD_GETCLASSNAMESPACE:
        yield 0
        klass = READER.read_uint64()
        API.GetClassNameSpace(klass)
    elif command == CEPIPECMD.MONOCMD_GETCLASSIMAGE:
        yield 0
        klass = READER.read_uint64()
        API.GetClassImage(klass)
    elif command == CEPIPECMD.MONOCMD_ISCLASSGENERIC:
        yield 0
        klass = READER.read_uint64()
        API.IsClassGeneric(klass)
    elif command == CEPIPECMD.MONOCMD_GETSTATICFIELDADDRESSFROMCLASS:
        yield 0
        domain = READER.read_uint64()
        yield 0
        klass = READER.read_uint64()
        WRITER.write_uint64(0)
    elif command == CEPIPECMD.MONOCMD_ENUMFIELDSINCLASS:
        yield 0
        klass = READER.read_uint64()
        API.EnumFieldsInClass(klass)
    elif command == CEPIPECMD.MONOCMD_GETMETHODSIGNATURE:
        yield 0
        method = READER.read_uint64()
        API.GetMethodSignature(method)
    elif command == CEPIPECMD.MONOCMD_GETSTATICFIELDVALUE:
        yield 0
        vtable = READER.read_uint64()
        yield 0
        field = READER.read_uint64()
        API.GetStaticFieldValue(vtable, field)
    elif command == CEPIPECMD.MONOCMD_SETSTATICFIELDVALUE:
        yield 0
        vtable = READER.read_uint64()
        yield 0
        field = READER.read_uint64()
        yield 0
        val = READER.read_uint64()
        API.SetStaticFieldValue(vtable, field, val)
    elif command == CEPIPECMD.MONOCMD_COMPILEMETHOD:
        yield 0
        method = READER.read_uint64()
        method_ptr = API.CompileMethod(method)
        WRITER.write_uint64(method_ptr)
    elif command == CEPIPECMD.MONOCMD_GETMONODATACOLLECTORVERSION:
        WRITER.write_uint32(MONO_DATACOLLECTORVERSION)
    elif command == CEPIPECMD.MONOCMD_ENUMIMAGES:
        data = API.EnumImages()
        WRITER.write_uint32(len(data))
        WRITER.write_byte_array(data)
    elif command == CEPIPECMD.MONOCMD_ENUMCLASSESINIMAGEEX:
        yield 0
        image = READER.read_uint64()
        data = API.EnumClassesInImageEX(image)
        WRITER.write_uint32(len(data))
        WRITER.write_byte_array(data)
    elif command == CEPIPECMD.MONOCMD_GETFIELDCLASS:
        yield 0
        field = READER.read_uint64()
        API.GetFieldClass(field)
    elif command == CEPIPECMD.MONOCMD_ISCLASSVALUETYPE:
        yield 0
        klass = READER.read_uint64()
        API.IsValueTypeClass(klass)
    elif command == CEPIPECMD.MONOCMD_FILLOPTIONALFUNCTIONLIST:
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
    api = script.exports_sync
    API = api
    SCRIPT = script
