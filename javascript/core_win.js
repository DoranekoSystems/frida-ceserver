const MEM_COMMIT = 4096;
const MEM_RESERVE = 8192;
const MEM_RELEASE = 32768;
const MEM_MAPPED = 262144;
const MEM_PRIVATE = 131072;

const PAGE_NOACCESS = 1;
const PAGE_READONLY = 2;
const PAGE_READWRITE = 4;
const PAGE_WRITECOPY = 8;
const PAGE_EXECUTE = 16;
const PAGE_EXECUTE_READ = 32;
const PAGE_EXECUTE_READWRITE = 64;

const PROT_READ = 1;
const PROT_WRITE = 2;
const PROT_EXEC = 4;

const MAP_SHARED = 1;
const MAP_PRIVATE = 2;
const MAP_ANONYMOUS = 32;

function ProtectionStringToType(protectionstring) {
  if (protectionstring.indexOf('s') != -1) return MEM_MAPPED;
  else return MEM_PRIVATE;
}

function ProtectionStringToProtection(protectionstring) {
  var w, x;

  if (protectionstring.indexOf('x') != -1) x = true;
  else x = false;

  if (protectionstring.indexOf('w') != -1) w = true;
  else w = false;

  if (x) {
    //executable
    if (w) return PAGE_EXECUTE_READWRITE;
    else return PAGE_EXECUTE_READ;
  } else {
    //not executable
    if (w) return PAGE_READWRITE;
    else return PAGE_READONLY;
  }
}

var moduleList = null;
var moduleListIterator = 0;
var moduleSize = 0;
var regionList = Process.enumerateRanges('r--');
var allocList = {};

const PS = Process.pointerSize;
const is64Bit = PS == 8 ? true : false;

/*speedhack*/
var hookFlag = false;

var speedMultiplier = 1;
var initialOffset = 0;
var initialTime = 0;
var initialOffset64 = 0;
var initialTime64 = 0;
var initialOffsetTC64 = 0;
var initialTimeTC64 = 0;

var GetTickCount_isReal = false;
var GetTickCount64_isReal = false;
var QueryPerformanceCounter_isReal = false;

var GetTickCountPtr = Module.findExportByName('kernel32.dll', 'GetTickCount');
var GetTickCount = new NativeFunction(GetTickCountPtr, 'uint', []);
var GetTickCount64Ptr = Module.findExportByName('kernel32.dll', 'GetTickCount64');
if (GetTickCount64Ptr != null) {
  var GetTickCount64 = new NativeFunction(GetTickCount64Ptr, 'uint64', []);
}
var QueryPerformanceCounterPtr = Module.findExportByName('kernel32.dll', 'QueryPerformanceCounter');
var QueryPerformanceCounter = new NativeFunction(QueryPerformanceCounterPtr, 'bool', ['pointer']);

function speedhackVersion_GetTickCount() {
  var currentTime = GetTickCount();
  if (GetTickCount_isReal) {
    return currentTime;
  }
  var result = Math.trunc((currentTime - initialTime) * speedMultiplier) + initialOffset;
  return result;
}

function speedhackVersion_GetTickCount64() {
  var currentTime = GetTickCount64();
  if (GetTickCount64_isReal) {
    return currentTime;
  }
  var result = Math.trunc((currentTime - initialTimeTC64) * speedMultiplier) + initialOffsetTC64;
  return result;
}

function speedhackVersion_QueryPerformanceCounter(x) {
  var currentTime64Ptr = Memory.alloc(8);
  var result = QueryPerformanceCounter(currentTime64Ptr);
  var currentTime64 = currentTime64Ptr.readS64();
  if (QueryPerformanceCounter_isReal) {
    x.writeS64(currentTime64);
    return result;
  }
  var newX = Math.trunc((currentTime64 - initialTime64) * speedMultiplier) + initialOffset64;
  x.writeS64(newX);

  return result;
}

function speedhack_initializeSpeed(speed) {
  initialOffset = speedhackVersion_GetTickCount();

  GetTickCount_isReal = true;
  initialTime = GetTickCount();
  GetTickCount_isReal = false;

  var initialOffset64Ptr = Memory.alloc(8);
  var initialTime64Ptr = Memory.alloc(8);
  speedhackVersion_QueryPerformanceCounter(initialOffset64Ptr);

  QueryPerformanceCounter_isReal = true;
  QueryPerformanceCounter(initialTime64Ptr);
  QueryPerformanceCounter_isReal = false;

  initialOffset64 = initialOffset64Ptr.readS64();
  initialTime64 = initialTime64Ptr.readS64();

  if (GetTickCount64Ptr != null) {
    initialOffsetTC64 = speedhackVersion_GetTickCount64();

    GetTickCount64_isReal = true;
    initialTimeTC64 = GetTickCount64();
    GetTickCount64_isReal = false;
  }

  speedMultiplier = speed;
}

Module.load('Dbghelp.dll');

var GetCurrentProcessPtr = Module.findExportByName(null, 'GetCurrentProcess');
var GetCurrentProcess = new NativeFunction(GetCurrentProcessPtr, 'int', []);
var SymInitializePtr = Module.findExportByName(null, 'SymInitialize');
var SymInitialize = new NativeFunction(SymInitializePtr, 'int', ['int', 'int', 'int']);
var SymCleanupPtr = Module.findExportByName(null, 'SymCleanup');
var SymCleanup = new NativeFunction(SymCleanupPtr, 'int', ['int']);
var SymLoadModule64Ptr = Module.findExportByName(null, 'SymLoadModule64');
var SymLoadModule64 = new NativeFunction(SymLoadModule64Ptr, 'uint64', [
  'int',
  'pointer',
  'pointer',
  'pointer',
  'int',
  'int',
]);
var SymEnumSymbolsPtr = Module.findExportByName(null, 'SymEnumSymbols');
var SymEnumSymbols = new NativeFunction(SymEnumSymbolsPtr, 'int', [
  'int',
  'uint64',
  'pointer',
  'pointer',
  'pointer',
]);

rpc.exports = {
  setconfig: function (config) {},
  getinfo: function () {
    var GetCurrentProcessIdPtr = Module.findExportByName(null, 'GetCurrentProcessId');
    var GetCurrentProcessId = new NativeFunction(GetCurrentProcessIdPtr, 'int', []);
    var pid = GetCurrentProcessId();
    var arch = Process.arch;
    var info = { pid: pid, arch: arch };
    return info;
  },
  readprocessmemory: function (address, size) {
    try {
      if (ptr(address).isNull() == false) {
        return Memory.readByteArray(ptr(address), size);
      } else {
        return false;
      }
    } catch (e) {
      return false;
    }
  },
  writeprocessmemory: function (address, buffer) {
    try {
      if (ptr(address).isNull() == false) {
        Memory.protect(ptr(address), buffer.length, 'rwx');
        return Memory.writeByteArray(ptr(address), buffer, buffer.length);
      } else {
        return false;
      }
    } catch (e) {
      console.log(e);
      return false;
    }
  },
  enummodules: function () {
    return Process.enumerateModules();
  },
  module32first: function () {
    moduleList = Process.enumerateModules();
    moduleListIterator = 0;
    moduleSize = Object.keys(moduleList).length;
    var base = moduleList[0].base;
    var size = moduleList[0].size;
    var name = moduleList[0].name;
    moduleListIterator += 1;
    return [base, size, name];
  },
  module32next: function () {
    if (moduleSize > moduleListIterator) {
      var base = moduleList[moduleListIterator].base;
      var size = moduleList[moduleListIterator].size;
      var name = moduleList[moduleListIterator].name;
      moduleListIterator += 1;
      return [base, size, name];
    } else {
      return false;
    }
  },
  virtualqueryex: function (address) {
    var regionSize = Object.keys(regionList).length;
    var lpAddress = address;
    for (var i = 0; i < regionSize; i++) {
      var start = parseInt(regionList[i].base);
      var end = parseInt(regionList[i].base) + parseInt(regionList[i].size);
      if (lpAddress < end) {
        if (start <= lpAddress) {
          var base = lpAddress;
          var size = regionList[i].size;
          var protection = ProtectionStringToProtection(regionList[i].protection);
          var type = ProtectionStringToType(regionList[i].protection);
          var filename = '';
          try {
            filename = regionList[i].file.path;
          } catch (e) {}
          return [base, size, protection, type, filename];
        } else {
          var base = lpAddress;
          var size = start - lpAddress;
          var protection = PAGE_NOACCESS;
          var type = 0;
          var filename = '';
          try {
            filename = regionList[i].file.path;
          } catch (e) {}
          return [base, size, protection, type, filename];
        }
        break;
      }
    }
    return false;
  },
  virtualqueryexfull: function () {
    regionList = Process.enumerateRanges('r--');
    var regionSize = Object.keys(regionList).length;
    var regionInfos = [];
    for (var i = 0; i < regionSize; i++) {
      var baseaddress = parseInt(regionList[i].base);
      var size = parseInt(regionList[i].size);
      var protection = ProtectionStringToProtection(regionList[i].protection);
      var type = ProtectionStringToType(regionList[i].protection);
      var filename = '';
      try {
        filename = regionList[i].file.path;
      } catch (e) {}
      regionInfos.push([baseaddress, size, protection, type, filename]);
    }
    return regionInfos;
  },
  getsymbollistfromfile: function (name) {
    if (!is64Bit) {
      var module = Process.getModuleByName(name);
      var symbols = module.enumerateSymbols();
      var symbollist = [];
      for (var i = 0; i < symbols.length; i++) {
        var baseaddress = symbols[i].address;
        if (baseaddress <= 0) continue;
        baseaddress = baseaddress - module.base;
        var size = symbols[i].size;
        if (size == null) {
          size = 1;
        }
        var type = symbols[i].type;
        var name = symbols[i].name;
        if (type == 'function') {
          type = 0;
          symbollist.push([baseaddress, size, type, name]);
        }
      }
      return symbollist;
    }
    var symbollist = [];
    var callbackFunction = new NativeCallback(
      (p, size, p2) => {
        var type = parseInt(p.add(0x04).readUInt());
        var baseaddress = parseInt(p.add(0x38).readU64()) - BaseOfDll;
        var name = p.add(0x54).readUtf8String();
        symbollist.push([baseaddress, size, type, name]);
        return 1;
      },
      'int',
      ['pointer', 'int', 'pointer']
    );
    var hProcess = GetCurrentProcess();
    var BaseOfDll;
    var Mask = Memory.allocUtf8String('*');
    var _status;

    _status = SymInitialize(hProcess, 0, 0);
    if (_status == 0) {
      return;
    }

    var path = Process.getModuleByName(name).path;
    BaseOfDll = SymLoadModule64(hProcess, ptr(0), Memory.allocUtf8String(path), ptr(0), 0, 0);
    if (BaseOfDll == 0) {
      console.log('SymInitialize Error!');
      SymCleanup(hProcess);
      return;
    }

    if (SymEnumSymbols(hProcess, BaseOfDll, Mask, callbackFunction, ptr(0))) {
      //console.log('SymEnumSymbols succeeded');
    } else {
      // SymEnumSymbols failed
      console.log('SymEnumSymbols failed: %d\n');
    }

    SymCleanup(hProcess);
    return symbollist;
  },
  extalloc: function (preferedBase, size) {
    var VirtualAllocPtr = Module.findExportByName(null, 'VirtualAlloc');
    var VirtualAlloc = new NativeFunction(VirtualAllocPtr, 'pointer', [
      'pointer',
      'int',
      'int',
      'int',
    ]);
    var _ptr = VirtualAlloc(ptr(preferedBase), size, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    var addressPtr = VirtualAlloc(_ptr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    var address = parseInt(addressPtr);
    return address;
  },
  extfree: function (address, size) {
    var VirtualFreePtr = Module.findExportByName(null, 'VirtualFree');
    var VirtualFree = new NativeFunction(VirtualFreePtr, 'int', ['pointer', 'int', 'int']);
    var result = VirtualFree(ptr(address), size, MEM_RELEASE);
    return result;
  },
  extsetspeed: function (speed) {
    speedhack_initializeSpeed(speed);

    if (hookFlag == false) {
      Interceptor.replace(
        GetTickCountPtr,
        new NativeCallback(speedhackVersion_GetTickCount, 'uint', [])
      );
      if (GetTickCount64Ptr != null) {
        Interceptor.replace(
          GetTickCount64Ptr,
          new NativeCallback(speedhackVersion_GetTickCount64, 'uint64', [])
        );
      }
      Interceptor.replace(
        QueryPerformanceCounterPtr,
        new NativeCallback(speedhackVersion_QueryPerformanceCounter, 'int', ['pointer'])
      );
      hookFlag = true;
    }

    return 1;
  },
  extloadmodule: function (modulepath) {
    Module.load(modulepath);
    return 1;
  },
  extcreatethread: function (startaddress, parameter) {
    var CreateThreadPtr = Module.findExportByName(null, 'CreateThread');
    var CreateThread = new NativeFunction(CreateThreadPtr, 'int', [
      'int',
      'int',
      'pointer',
      'pointer',
      'int',
      'pointer',
    ]);
    var dwThreadId = Memory.alloc(4);
    var hThread = CreateThread(0, 0, ptr(startaddress), ptr(parameter), 0, dwThreadId);
    if (hThread == 0) return 0;
    else return 1;
  },
  extchangememoryprotection: function (address, size, protectionstring) {
    var ret = Memory.protect(ptr(address), size, protectionstring);
    return ret;
  },
  getthreadlist: function () {
    var threads = Process.enumerateThreads();
    var idlist = [];
    for (var i = 0; i < threads.length; i++) {
      idlist.push(parseInt(threads[i].id));
    }
    return idlist;
  },
};
