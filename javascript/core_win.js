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

var fix_module_size = false;
var java_dissect = false;
rpc.exports = {
  setconfig: function (config) {},
  getinfo: function () {
    var pid = Process.pid;
    var info = { pid: pid };
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
      regionInfos.push([baseaddress, size, protection, type]);
    }
    return regionInfos;
  },
  getsymbollistfromfile: function (name) {
    try {
      var module = Process.getModuleByName(name);
    } catch (e) {
      return false;
    }
    var symbols = module.enumerateSymbols();
    var symbollist = [];
    for (var i = 0; i < symbols.length; i++) {
      var baseaddress = symbols[i].address;
      if (baseaddress <= 0) continue;
      baseaddress = baseaddress - module.base;
      var size = symbols[i].size;
      var type = symbols[i].type;
      var name = symbols[i].name;
      if (type == 'function') {
        type = 0;
        symbollist.push([baseaddress, size, type, name]);
      }
    }
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
};
