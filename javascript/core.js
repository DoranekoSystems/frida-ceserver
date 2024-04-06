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

const VQE_PAGEDONLY = 1;
const VQE_DIRTYONLY = 2;
const VQE_NOSHARED = 4;

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

/*speedhack*/
var hookFlag = false;

var initialclock = new Array(10);
for (let y = 0; y < 10; y++) {
  initialclock[y] = {
    result: 0,
    initialoffset: { tv_sec: 0, tv_nsec: 0 },
    initialtime: { tv_sec: 0, tv_nsec: 0 },
  };
}

var initial_offset_tod_tv = { tv_sec: 0, tv_usec: 0 };
var initial_time_tod_tv = { tv_sec: 0, tv_usec: 0 };

var speedmultiplier = 1.0;
const PS = Process.pointerSize;

var coreLibraryName = '';
if (Process.platform == 'darwin') {
  coreLibraryName = 'libSystem.B.dylib';
} else {
  coreLibraryName = null;
}

var clock_gettimePtr = Module.findExportByName(coreLibraryName, 'clock_gettime');
var clock_gettime = new NativeFunction(clock_gettimePtr, 'int', ['int', 'pointer']);
var gettimeofdayPtr = Module.findExportByName(coreLibraryName, 'gettimeofday');
var gettimeofday = new NativeFunction(gettimeofdayPtr, 'int', ['pointer', 'pointer']);

var clock_gettime_isReal = false;
var gettimeofday_isReal = false;

function speedhack_initializeSpeed(speed) {
  var temptv = Memory.alloc(PS * 2);
  gettimeofday(temptv, ptr(0));
  initial_offset_tod_tv.tv_sec = temptv.readUInt();
  initial_offset_tod_tv.tv_usec = temptv.add(PS).readUInt();
  gettimeofday_isReal = true;
  gettimeofday(temptv, ptr(0));
  gettimeofday_isReal = false;
  initial_time_tod_tv.tv_sec = temptv.readUInt();
  initial_time_tod_tv.tv_usec = temptv.add(PS).readUInt();

  var i;
  for (i = 0; i <= 9; i++) {
    var temptp = Memory.alloc(PS * 3);
    clock_gettime(i, temptp);
    initialclock[i].initialoffset.tv_sec = temptp.readUInt();
    initialclock[i].initialoffset.tv_nsec = temptp.add(PS).readUInt();
    clock_gettime_isReal = true;
    initialclock[i].result = clock_gettime(i, temptp);
    clock_gettime_isReal = false;
    initialclock[i].initialtime.tv_sec = temptp.readUInt();
    initialclock[i].initialtime.tv_nsec = temptp.add(PS).readUInt();
  }

  speedmultiplier = speed;
}

function clock_gettimeHook() {
  Interceptor.attach(clock_gettimePtr, {
    onEnter: function (args) {
      this.clk_id = parseInt(args[0]);
      this.currenttp = args[1];
    },
    onLeave: function (retValue) {
      if (clock_gettime_isReal) return;
      var clk_id = this.clk_id;
      var currenttp = this.currenttp;

      if (this.clk_id <= 9 && initialclock[clk_id].result == 0) {
        var temptp = { tv_sec: 0, tv_nsec: 0 };
        temptp.tv_sec = currenttp.readUInt() - initialclock[clk_id].initialtime.tv_sec;
        temptp.tv_nsec = currenttp.add(PS).readUInt() - initialclock[clk_id].initialtime.tv_nsec;

        if (temptp.tv_nsec < 0) {
          temptp.tv_nsec += 1000000000;
          temptp.tv_sec--;
        }

        var newsec_double = temptp.tv_sec * speedmultiplier;

        var newnsec = Math.floor(temptp.tv_nsec * speedmultiplier);
        var newsec = Math.floor(newsec_double);

        newnsec += Math.floor((newsec_double - Math.floor(newsec_double)) * 1000000000.0);

        newsec += initialclock[clk_id].initialoffset.tv_sec;
        newnsec += initialclock[clk_id].initialoffset.tv_nsec;

        newsec += newnsec / 1000000000;
        newnsec = newnsec % 1000000000;

        if (newnsec < 0) {
          newnsec += 1000000000;
          newsec--;
        }
        newsec = Math.floor(newsec);
        try {
          currenttp.writeUInt(newsec);
          currenttp.add(PS).writeUInt(newnsec);
        } catch (err) {
          console.log(err);
        }
      }
    },
  });
}

function gettimeofdayHook() {
  Interceptor.attach(gettimeofdayPtr, {
    onEnter: function (args) {
      this.tv = args[0];
      this.tz = args[1];
    },
    onLeave: function (retValue) {
      if (gettimeofday_isReal) return;
      var currenttv = this.tv;

      var temptv = { tv_sec: 0, tv_usec: 0 };
      temptv.tv_sec = currenttv.readUInt() - initial_time_tod_tv.tv_sec;
      temptv.tv_usec = currenttv.add(PS).readUInt() - initial_time_tod_tv.tv_usec;

      if (temptv.tv_usec < 0) {
        temptv.tv_usec += 1000000;
        temptv.tv_sec--;
      }

      var newsec_double = temptv.tv_sec * speedmultiplier;

      var newusec = Math.floor(temptv.tv_usec * speedmultiplier);
      var newsec = Math.floor(newsec_double);

      newusec += Math.floor((newsec_double - Math.floor(newsec_double)) * 1000000);

      newsec += initial_offset_tod_tv.tv_sec;
      newusec += initial_offset_tod_tv.tv_usec;

      newsec += newusec / 1000000;
      newusec = newusec % 1000000;

      if (newusec < 0) {
        newusec += 1000000;
        newsec--;
      }

      newsec = Math.floor(newsec);

      currenttv.writeUInt(newsec);
      currenttv.add(PS).writeUInt(newusec);
    },
  });
}

var statPtr = Module.findExportByName(coreLibraryName, 'stat');
var stat = null;
if (statPtr != null) {
  stat = new NativeFunction(statPtr, 'int', ['pointer', 'pointer']);
}

function getRealFileSize(filename) {
  //not support
  if (stat == null) return -1;
  var statStructPtr = Memory.alloc(512);
  var ret = stat(Memory.allocUtf8String(filename), statStructPtr);
  if (ret == -1) return -1;
  var sizeOffset = 0;
  if (Process.platform == 'darwin') {
    sizeOffset = 0x60;
  } else {
    sizeOffset = 0x30;
  }
  var size = statStructPtr.add(sizeOffset).readUInt();
  return size;
}

const COMPRESSION_LZ4 = 0x100;
const COMPRESSION_LZ4_RAW = 0x101;
const COMPRESSION_ZLIB = 0x205;
const COMPRESSION_LZMA = 0x306;
const COMPRESSION_LZFSE = 0x801;
const COMPRESSION_BROTLI = 0xb02;

var mach_task_self;
var mach_vm_read_overwrite;
var compression_encode_buffer;

var process_vm_readv;
var process_vm_writev;
var LZ4_compress_default;
var LZ4_compressBound;
var LZ4_compress_fast;

var g_Buffer;
var g_dstBuffer;
var g_Task;
var g_Mutex = true;

//Up to 1 threads can be handled simultaneously
const g_bufferSize = 16384 * 1024;
const g_maxThread = 1;
g_Buffer = Memory.alloc(g_bufferSize * g_maxThread);
g_dstBuffer = Memory.alloc(g_bufferSize * g_maxThread);

function ReadProcessMemory_Init() {
  //iOS
  if (target_os == 'ios') {
    var mach_task_selfPtr = Module.findExportByName(null, 'mach_task_self');
    var mach_vm_read_overwritePtr = Module.findExportByName(null, 'mach_vm_read_overwrite');

    mach_task_self = new NativeFunction(mach_task_selfPtr, 'pointer', []);
    mach_vm_read_overwrite = new NativeFunction(mach_vm_read_overwritePtr, 'int', [
      'pointer',
      'long',
      'int',
      'pointer',
      'pointer',
    ]);

    var compression_encode_bufferPtr = Module.findExportByName(null, 'compression_encode_buffer');
    compression_encode_buffer = new NativeFunction(compression_encode_bufferPtr, 'int', [
      'pointer',
      'int',
      'pointer',
      'int',
      'pointer',
      'int',
    ]);
    g_Task = mach_task_self();
  }
  //Android
  else {
    Module.load('liblz4.so');

    var LZ4_compress_defaultPtr = Module.findExportByName('liblz4.so', 'LZ4_compress_default');
    LZ4_compress_default = new NativeFunction(LZ4_compress_defaultPtr, 'int', [
      'pointer',
      'pointer',
      'int',
      'int',
    ]);
    var LZ4_compress_fastPtr = Module.findExportByName('liblz4.so', 'LZ4_compress_fast');
    LZ4_compress_fast = new NativeFunction(LZ4_compress_fastPtr, 'int', [
      'pointer',
      'pointer',
      'int',
      'int',
      'int',
    ]);
    var LZ4_compressBoundPtr = Module.findExportByName('liblz4.so', 'LZ4_compressBound');
    LZ4_compressBound = new NativeFunction(LZ4_compressBoundPtr, 'int', ['int']);
    var process_vm_readvPtr = Module.findExportByName(null, 'process_vm_readv');
    process_vm_readv = new NativeFunction(process_vm_readvPtr, 'int', [
      'int',
      'pointer',
      'int',
      'pointer',
      'int',
      'int',
    ]);
  }
}

var loop_count = 0;
function ReadProcessMemory_Custom(address, size) {
  loop_count++;
  var start_offset = (loop_count % g_maxThread) * g_bufferSize;
  //iOS
  if (Process.platform == 'darwin') {
    var size_out = Memory.alloc(8);
    mach_vm_read_overwrite(g_Task, address, size, g_Buffer.add(start_offset), size_out);
    if (size_out.readUInt() == 0) {
      return false;
    } else {
      var compress_size = compression_encode_buffer(
        g_dstBuffer.add(start_offset),
        size,
        g_Buffer.add(start_offset),
        size,
        ptr(0),
        COMPRESSION_LZ4
      );
      var ret = ArrayBuffer.wrap(g_dstBuffer.add(start_offset), compress_size);
      return ret;
    }
  }
  //Android
  else {
    var local = Memory.alloc(32);
    var remote = Memory.alloc(32);
    local.writePointer(g_Buffer.add(start_offset));
    local.add(PS).writeUInt(size);
    remote.writePointer(ptr(address));
    remote.add(PS).writeUInt(size);
    var size_out = process_vm_readv(Process.id, local, 1, remote, 1, 0);
    if (size_out == -1) {
      return false;
    } else {
      var dstCapacity = LZ4_compressBound(size_out);
      var compress_size = LZ4_compress_default(
        g_Buffer.add(start_offset),
        g_dstBuffer.add(start_offset),
        size_out,
        dstCapacity
      );
      var ret = ArrayBuffer.wrap(g_dstBuffer.add(start_offset), compress_size + 4);
      g_dstBuffer.add(start_offset + compress_size).writeUInt(size_out);
      return ret;
    }
  }
}

var custom_read_memory = false;
var fix_module_size = false;
var java_info = false;
var data_collector = '';
var target_os = '';
rpc.exports = {
  setconfig: function (config) {
    custom_read_memory = config['extended_function']['custom_read_memory'];
    fix_module_size = config['extended_function']['fix_module_size'];
    java_info = config['extended_function']['java_info'];
    data_collector = config['extended_function']['data_collector'];
    target_os = config['general']['target_os'];
    if (custom_read_memory && ['android', 'ios'].indexOf(target_os != -1)) {
      ReadProcessMemory_Init();
      console.log('ReadProcessMemory_Custom Enabled!!');
    }
  },
  getinfo: function () {
    var pid = Process.id;
    var arch = Process.arch;
    var info = { pid: pid, arch: arch };
    return info;
  },
  readprocessmemory: function (address, size) {
    try {
      if (ptr(address).isNull() == false) {
        if (custom_read_memory && ['android', 'ios'].indexOf(target_os) != -1) {
          var ret = ReadProcessMemory_Custom(address, size);
        } else {
          var ret = Memory.readByteArray(ptr(address), size);
        }
        return ret;
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
    var moduleList = Process.enumerateModules();
    if (java_info) {
      moduleList.push({ base: '0xcececece', size: 0, name: 'jvm.dll' });
      moduleList.push({ base: '0xecececec', size: 0, name: 'CEJVMTI.dll' });
    }
    if (data_collector == 'mono' || data_collector == 'objc') {
      moduleList.push({
        base: '0xcececece',
        size: 0x40000,
        name: 'libmono-datacollector-dummy.so',
      });
    }
    return moduleList;
  },
  module32first: function () {
    moduleList = Process.enumerateModules();
    if (java_info) {
      moduleList.push({ base: '0xcececece', size: 0, name: 'jvm.dll' });
      moduleList.push({ base: '0xecececec', size: 0, name: 'CEJVMTI.dll' });
    }
    if (data_collector == 'mono' || data_collector == 'objc') {
      moduleList.push({
        base: '0xcececece',
        size: 0x40000,
        name: 'libmono-datacollector-dummy.so',
      });
    }
    moduleListIterator = 0;
    moduleSize = Object.keys(moduleList).length;
    var base = moduleList[0].base;
    var size = moduleList[0].size;
    var name = moduleList[0].name;
    if (fix_module_size) {
      var path = moduleList[0].path;
      var real_size = getRealFileSize(path);
      if (real_size > size) size = real_size;
    }
    moduleListIterator += 1;
    return [base, size, name];
  },
  module32next: function () {
    if (moduleSize > moduleListIterator) {
      var base = moduleList[moduleListIterator].base;
      var size = moduleList[moduleListIterator].size;
      var name = moduleList[moduleListIterator].name;
      if (fix_module_size) {
        var path = moduleList[moduleListIterator].path;
        var real_size = getRealFileSize(path);
        if (real_size > size) size = real_size;
      }
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
  virtualqueryexfull: function (flags) {
    var noshared = flags & VQE_NOSHARED;
    regionList = Process.enumerateRanges('r--');
    var regionSize = Object.keys(regionList).length;
    var regionInfos = [];
    for (var i = 0; i < regionSize; i++) {
      var baseaddress = parseInt(regionList[i].base);
      var size = parseInt(regionList[i].size);
      // size = size - (size % 0x1000);
      var protection = ProtectionStringToProtection(regionList[i].protection);
      var type = ProtectionStringToType(regionList[i].protection);
      if (protection == PAGE_NOACCESS) {
        continue;
      } else if (type == MEM_MAPPED) {
        if (noshared != 0) continue;
      }
      var filename = '';
      try {
        filename = regionList[i].file.path;
      } catch (e) {}
      regionInfos.push([baseaddress, size, protection, type, filename]);
    }
    return regionInfos;
  },
  getsymbollistfromfile: function (name) {
    try {
      var module = Process.getModuleByName(name);
    } catch (e) {
      return false;
    }
    var symbols;
    if (Process.platform == 'linux') {
      symbols = module.enumerateSymbols();
    } else {
      symbols = module.enumerateExports();
    }
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
      //for speedhack
      if (Process.platform == 'linux' || Process.platform == 'darwin') {
        if (name.indexOf('clock_gettime') != -1) {
          name = name.replace('clock_gettime', '___clock_gettime');
        } else if (name.indexOf('gettimeofday') != -1) {
          name = name.replace('gettimeofday', '___gettimeofday');
        }
      }
      if (type == 'function') {
        type = 0;
        symbollist.push([baseaddress, size, type, name]);
      }
    }
    return symbollist;
  },
  extalloc: function (preferedBase, size) {
    if (allocList[preferedBase]) return preferedBase;
    var mmapPtr = Module.findExportByName(null, 'mmap');
    var mmap = new NativeFunction(mmapPtr, 'pointer', [
      'pointer',
      'int',
      'int',
      'int',
      'int',
      'int',
    ]);
    var ret = mmap(
      ptr(preferedBase),
      size,
      PROT_READ | PROT_WRITE | PROT_EXEC,
      MAP_PRIVATE | MAP_ANONYMOUS,
      -1,
      0
    );
    var address = parseInt(ret);
    if (address != -1) {
      allocList[address] = size;
    }
    return address;
  },
  extfree: function (address, size) {
    var psize = 0;
    var result = 0;
    if (size == 0) {
      if (allocList[address]) {
        psize = allocList[address];
        delete allocList[address];
      } else {
        psize = 0;
      }
    }
    if (psize != 0) {
      var munmapPtr = Module.findExportByName(null, 'munmap');
      var munmap = new NativeFunction(munmapPtr, 'pointer', ['pointer', 'int']);
      var ret = munmap(ptr(address), psize);
      result = parseInt(ret);
      if (result == -1) result = 0;
      else result = 1;
    } else {
      result = 0;
    }
    return result;
  },
  extsetspeed: function (speed) {
    speedhack_initializeSpeed(speed);

    if (hookFlag == false) {
      clock_gettimeHook();
      gettimeofdayHook();
      hookFlag = true;
    }

    return 1;
  },
  extloadmodule: function (modulepath) {
    Module.load(modulepath);
    return 1;
  },
  extcreatethread: function (startaddress, parameter) {
    var pthread_createPtr = Module.findExportByName(null, 'pthread_create');
    var pthread_create = new NativeFunction(pthread_createPtr, 'pointer', [
      'pointer',
      'int',
      'pointer',
      'pointer',
    ]);
    var zero_ptr = Memory.alloc(4);
    var ret = pthread_create(zero_ptr, 0, ptr(startaddress), ptr(parameter));
    return 1;
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
