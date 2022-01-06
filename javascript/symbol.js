const PT_TYPE_NAME = {
  0: 'NULL',
  1: 'LOAD',
  2: 'DYNAMIC',
  3: 'INTERP',
  4: 'NOTE',
  5: 'SHLIB',
  6: 'PHDR',
  0x60000000: 'LOOS',
  0x6474e550: 'PT_GNU_EH_FRAME',
  0x6474e551: 'PT_GNU_STACK',
  0x6474e552: 'PT_GNU_RELO',
  0x6fffffff: 'HIOS',
  0x70000000: 'LOPROC',
  0x7fffffff: 'HIPROC',
};

const SH_TYPE_NAME = {
  0: 'NULL',
  1: 'PROGBITS',
  2: 'SYMTAB',
  3: 'STRTAB',
  4: 'RELA',
  5: 'HASH',
  6: 'DYNAMIC',
  7: 'NOTE',
  8: 'NOBITS',
  9: 'REL',
  10: 'SHLIB',
  11: 'DYNSYM',
  14: 'INIT_ARRAY',
  15: 'FINI_ARRAY',
  16: 'PREINIT_ARRAY',
  17: 'GROUP',
  18: 'SYMTAB_SHNDX',
  19: 'RELR',
  0x60000000: 'LOOS',
  0x60000001: 'ANDROID_REL',
  0x60000002: 'ANDROID_RELA',
  0x6fff4c00: 'LLVM_ORDTAB',
  0x6fff4c01: 'LLVM_LINKER_OPTIONS',
  0x6fff4c02: 'LLVM_CALL_GRAPH_PROFILE',
  0x6fff4c03: 'LLVM_ADDRSIG',
  0x6fff4c04: 'LLVM_DEPENDENT_LIBRARIES',
  0x6fffff00: 'ANDROID_RELR',
  0x6ffffff5: 'GNU_ATTRIBUTES',
  0x6fffffff: 'GNU_VERSYM',
  0x6ffffff6: 'GNU_HASH',
  0x6ffffffd: 'GNU_VERDEF',
  0x6ffffffe: 'GNU_VERNEED',
  0x70000000: 'LOPROC',
  0x7fffffff: 'HIPROC',
  0x80000000: 'LOUSER',
  0xffffffff: 'HIUSER',
};

const fopenImpl = initializeNativeFunction('fopen', 'pointer', ['pointer', 'pointer']);
const fcloseImpl = initializeNativeFunction('fclose', 'int', ['pointer']);
const fseekImpl = initializeNativeFunction('fseek', 'int', ['pointer', 'int', 'int']);
const freadImpl = initializeNativeFunction('fread', 'uint32', ['pointer', 'int', 'int', 'pointer']);

class ElfHeader {
  e_ident;
  e_type;
  e_machine;
  e_version;
  e_entry;
  e_phoff;
  e_shoff;
  e_flags;
  e_ehsize;
  e_phentsize;
  e_phnum;
  e_shentsize;
  e_shnum;
  e_shstrndx;
  s_size;

  constructor(buffer) {
    this.e_ident = [];
    for (let i = 0; i < 0x10; i++) {
      this.e_ident.push(buffer.add(i).readU8());
    }

    this.e_type = buffer.add(0x10).readU16();
    this.e_machine = buffer.add(0x12).readU16();
    this.e_version = buffer.add(0x14).readU32();

    let pos = 0;
    if (this.e_ident[4] === 1) {
      // ELFCLASS32
      this.e_entry = buffer.add(0x18).readU32();
      this.e_phoff = buffer.add(0x1c).readU32();
      this.e_shoff = buffer.add(0x20).readU32();
      pos = 0x24;
    } else if (this.e_ident[4] === 2) {
      //ELFCLASS64
      this.e_entry = buffer.add(0x18).readU64().toNumber();
      this.e_phoff = buffer.add(0x20).readU64().toNumber();
      this.e_shoff = buffer.add(0x28).readU64().toNumber();
      pos = 0x30;
    } else {
      this.e_entry = 0;
      this.e_phoff = 0;
      this.e_shoff = 0;
    }

    this.e_flags = buffer.add(pos).readU32();
    this.e_ehsize = buffer.add(pos + 0x4).readU16();
    this.e_phentsize = buffer.add(pos + 0x6).readU16();
    this.e_phnum = buffer.add(pos + 0x8).readU16();
    this.e_shentsize = buffer.add(pos + 0xa).readU16();
    this.e_shnum = buffer.add(pos + 0xc).readU16();
    this.e_shstrndx = buffer.add(pos + 0xe).readU16();
    this.s_size = pos + 0x10;
  }
}

class ElFProgamHeader {
  p_type;
  p_offset;
  p_vaddr;
  p_paddr;
  p_filesz;
  p_memsz;
  p_flags;
  p_align;

  constructor(buffer, is64bit) {
    this.p_type = buffer.readU32();
    if (!is64bit) {
      this.p_offset = buffer.add(0x4).readU32();
      this.p_vaddr = buffer.add(0x8).readU32();
      this.p_paddr = buffer.add(0xc).readU32();
      this.p_filesz = buffer.add(0x10).readU32();
      this.p_memsz = buffer.add(0x14).readU32();
      this.p_flags = buffer.add(0x18).readU32();
      this.p_align = buffer.add(0x1c).readU32();
    } else {
      this.p_flags = buffer.add(0x4).readU32();
      this.p_offset = buffer.add(0x8).readU64().toNumber();
      this.p_vaddr = buffer.add(0x10).readU64().toNumber();
      this.p_paddr = buffer.add(0x18).readU64().toNumber();
      this.p_filesz = buffer.add(0x20).readU64().toNumber();
      this.p_memsz = buffer.add(0x28).readU64().toNumber();
      this.p_align = buffer.add(0x30).readU64().toNumber();
    }
  }
}

class ElfSectionHeader {
  name;
  sh_name;
  sh_type;
  sh_flags;
  sh_addr;
  sh_offset;
  sh_size;
  sh_link;
  sh_info;
  sh_addralign;
  sh_entsize;
  data = [];

  constructor(buffer, is64bit) {
    this.name = '';
    this.sh_name = buffer.add(0x0).readU32();
    this.sh_type = buffer.add(0x4).readU32();
    if (!is64bit) {
      this.sh_flags = buffer.add(0x8).readU32();
      this.sh_addr = buffer.add(0xc).readU32();
      this.sh_offset = buffer.add(0x10).readU32();
      this.sh_size = buffer.add(0x14).readU32();
      this.sh_link = buffer.add(0x18).readU32();
      this.sh_info = buffer.add(0x1c).readU32();
      this.sh_addralign = buffer.add(0x20).readU32();
      this.sh_entsize = buffer.add(0x24).readU32();
    } else {
      this.sh_flags = buffer.add(0x8).readU64().toNumber();
      this.sh_addr = buffer.add(0x10).readU64().toNumber();
      this.sh_offset = buffer.add(0x18).readU64().toNumber();
      this.sh_size = buffer.add(0x20).readU64().toNumber();
      this.sh_link = buffer.add(0x28).readU32();
      this.sh_info = buffer.add(0x2c).readU32();
      this.sh_addralign = buffer.add(0x30).readU64().toNumber();
      this.sh_entsize = buffer.add(0x38).readU64().toNumber();
    }
  }
}

function allocateRw(size) {
  const pt = Memory.alloc(size);
  Memory.protect(pt, size, 'rw-');
  return pt;
}

function fclose(fd) {
  if (fcloseImpl) {
    return fcloseImpl(fd);
  }
  return NULL;
}

function fopen(filePath, perm) {
  const filePathPtr = Memory.allocUtf8String(filePath);
  const p = Memory.allocUtf8String(perm);
  if (fopenImpl) {
    return fopenImpl(filePathPtr, p);
  }
  return NULL;
}

function fread(pt, size, nmemb, stream) {
  if (freadImpl) {
    return freadImpl(pt, size, nmemb, stream);
  }

  return 0;
}

function fseek(stream, offset, whence) {
  if (fseekImpl) {
    return fseekImpl(stream, offset, whence);
  }
  return 0;
}

function initializeNativeFunction(fname, retType, argTypes) {
  const p = Module.findExportByName(null, fname);
  if (p !== null) {
    return new NativeFunction(p, retType, argTypes);
  }
  return null;
}

function Elf32(f, eh) {
  //console.log('ELF32!');
  var symbollist = [];
  var b = allocateRw(eh.e_shentsize * eh.e_shnum);
  fseek(f, eh.e_shoff, 0);
  fread(b, 1, eh.e_shentsize * eh.e_shnum, f);
  for (var i = 0; i < eh.e_shnum; i++) {
    var sectionHeader = new ElfSectionHeader(b.add(eh.e_shentsize * i), false);
    if (
      SH_TYPE_NAME[sectionHeader.sh_type] == 'DYNSYM' ||
      SH_TYPE_NAME[sectionHeader.sh_type] == 'SYMTAB'
    ) {
      var symbolTable = allocateRw(sectionHeader.sh_size);
      fseek(f, sectionHeader.sh_offset, 0);
      fread(symbolTable, 1, sectionHeader.sh_size, f);
      var maxindex = sectionHeader.sh_size / 16;

      var tmp = new ElfSectionHeader(b.add(eh.e_shentsize * sectionHeader.sh_link), false);
      var stringTable = allocateRw(tmp.sh_size);
      if (SH_TYPE_NAME[tmp.sh_type] == 'STRTAB') {
        fseek(f, tmp.sh_offset, 0);
        fread(stringTable, 1, tmp.sh_size, f);
      } else {
        console.log('Not a string table');
      }

      for (var j = 0; j < maxindex; j++) {
        var st_name = symbolTable.add(16 * j).readU32();
        var st_value = symbolTable.add(16 * j + 4).readU32();
        var st_size = symbolTable.add(16 * j + 8).readU32();
        var st_info = symbolTable.add(16 * j + 13).readU8();

        if (st_value > 0) {
          var name = stringTable.add(st_name).readUtf8String();
          symbollist.push([st_value, st_size, st_info, name]);
        }
      }
    }
  }
  return symbollist;
}

function Elf64(f, eh) {
  //console.log('ELF64!');
  var symbollist = [];
  var b = allocateRw(eh.e_shentsize * eh.e_shnum);
  fseek(f, eh.e_shoff, 0);
  fread(b, 1, eh.e_shentsize * eh.e_shnum, f);
  for (var i = 0; i < eh.e_shnum; i++) {
    var sectionHeader = new ElfSectionHeader(b.add(eh.e_shentsize * i), true);
    if (
      SH_TYPE_NAME[sectionHeader.sh_type] == 'DYNSYM' ||
      SH_TYPE_NAME[sectionHeader.sh_type] == 'SYMTAB'
    ) {
      var symbolTable = allocateRw(sectionHeader.sh_size);
      fseek(f, sectionHeader.sh_offset, 0);
      fread(symbolTable, 1, sectionHeader.sh_size, f);
      var maxindex = sectionHeader.sh_size / 24;

      var tmp = new ElfSectionHeader(b.add(eh.e_shentsize * sectionHeader.sh_link), true);
      var stringTable = allocateRw(tmp.sh_size);
      if (SH_TYPE_NAME[tmp.sh_type] == 'STRTAB') {
        fseek(f, tmp.sh_offset, 0);
        fread(stringTable, 1, tmp.sh_size, f);
      } else {
        console.log('Not a string table');
      }

      for (var j = 0; j < maxindex; j++) {
        var st_name = symbolTable.add(24 * j).readU32();
        var st_value = symbolTable.add(24 * j + 8).readU32();
        var st_size = symbolTable.add(24 * j + 16).readU32();
        var st_info = symbolTable.add(24 * j + 5).readU8();

        if (st_value > 0) {
          var name = stringTable.add(st_name).readUtf8String();
          symbollist.push([st_value, st_size, st_info, name]);
        }
      }
    }
  }
  return symbollist;
}

function GetSymbolListFromFile(filename) {
  try {
    var path = Process.getModuleByName(filename).path;
  } catch (e) {
    return -1;
  }
  console.log(path);
  var f = fopen(path, 'r');
  if (f == 0) return -1;
  var b = allocateRw(0x40);
  fread(b, 1, 0x40, f);
  var eh = new ElfHeader(b);
  if (eh.e_ident.slice(0, 4).toString() == '127,69,76,70') {
    //console.log('ELF!');
    if (eh.e_ident[4] == 1) {
      return Elf32(f, eh);
    } else {
      return Elf64(f, eh);
    }
  } else {
    return -1;
  }
}

rpc.exports = {
  getsymbollistfromfile: function (name) {
    var symbols = GetSymbolListFromFile(name);
    if (symbols == -1) {
      return false;
    } else {
      return symbols;
    }
  },
};
