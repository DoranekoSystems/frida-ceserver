function dump(pointer, length) {
  var buf = Memory.readByteArray(pointer, length);
  console.log(
    hexdump(buf, {
      offset: 0,
      length: length,
      header: true,
      ansi: true,
    })
  );
}

const MONO_TYPE_NAME_FORMAT_IL = 0;
const MONO_TYPE_NAME_FORMAT_REFLECTION = 1;
const MONO_TYPE_NAME_FORMAT_FULL_NAME = 2;
const MONO_TYPE_NAME_FORMAT_ASSEMBLY_QUALIFIED = 3;

const CMD_WriteByte = 1;
const CMD_WriteWord = 2;
const CMD_WriteDword = 3;
const CMD_WriteQword = 4;
const CMD_WriteUtf8String = 5;

var il2cpp = true;

function WriteByte(value) {
  send([CMD_WriteByte, value]);
}
function WriteWord(value) {
  send([CMD_WriteWord, value]);
}
function WriteDword(value) {
  send([CMD_WriteDword, value]);
}
function WriteQword(value) {
  send([CMD_WriteQword, value]);
}
function WriteUtf8String(message) {
  send([CMD_WriteUtf8String, message]);
}

var coreLibraryName = '';
var hMono = 0;
if (Process.platform == 'linux') {
  coreLibraryName = 'libil2cpp.so';
  hMono = Process.getModuleByName(coreLibraryName).base;
} else if (Process.platform == 'windows') {
  coreLibraryName = 'GameAssembly.dll';
  hMono = Process.getModuleByName(coreLibraryName).base;
} else {
  coreLibraryName = null;
  hMono = 1;
}

var g_freePtr = Module.findExportByName(coreLibraryName, 'g_free');

if (!g_freePtr) g_freePtr = Module.findExportByName(coreLibraryName, 'il2cpp_unity_g_free');

var mono_freePtr = Module.findExportByName(coreLibraryName, 'il2cpp_free');

var mono_get_root_domainPtr = Module.findExportByName(coreLibraryName, 'il2cpp_get_root_domain');
var mono_thread_attachPtr = Module.findExportByName(coreLibraryName, 'il2cpp_thread_attach');
var mono_thread_attach = new NativeFunction(mono_thread_attachPtr, 'pointer', ['pointer']);

var mono_thread_detachPtr = Module.findExportByName(coreLibraryName, 'il2cpp_thread_detach');

var mono_object_get_classPtr = Module.findExportByName(coreLibraryName, 'il2cpp_object_get_class');

var mono_domain_foreachPtr = Module.findExportByName(coreLibraryName, 'il2cpp_domain_foreach');
var mono_domain_setPtr = Module.findExportByName(coreLibraryName, 'il2cpp_domain_set');
var mono_domain_getPtr = Module.findExportByName(coreLibraryName, 'il2cpp_domain_get');
var mono_domain_get = new NativeFunction(mono_domain_getPtr, 'pointer', []);

var mono_assembly_foreachPtr = Module.findExportByName(coreLibraryName, 'il2cpp_assembly_foreach');
var mono_assembly_get_imagePtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_assembly_get_image'
);
var mono_assembly_get_image = new NativeFunction(mono_assembly_get_imagePtr, 'pointer', [
  'pointer',
]);

var mono_image_get_assemblyPtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_image_get_assembly'
);

var mono_image_get_namePtr = Module.findExportByName(coreLibraryName, 'il2cpp_image_get_name');
var mono_image_get_name = new NativeFunction(mono_image_get_namePtr, 'pointer', ['pointer']);

var mono_image_get_table_infoPtr = Module.findExportByName(
  coreLibraryName,
  'mono_image_get_table_info'
);
var mono_image_rva_mapPtr = Module.findExportByName(coreLibraryName, 'il2cpp_image_rva_map');

var mono_table_info_get_rowsPtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_table_info_get_rows'
);
var mono_metadata_decode_row_colPtr = Module.findExportByName(
  null,
  'il2cpp_metadata_decode_row_col'
);
var mono_metadata_string_heapPtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_metadata_string_heap'
);

var mono_class_getPtr = Module.findExportByName(coreLibraryName, 'il2cpp_class_get');
var mono_class_from_typePtr = Module.findExportByName(coreLibraryName, 'il2cpp_class_from_type');
var mono_class_from_type = new NativeFunction(mono_class_from_typePtr, 'pointer', ['pointer']);

var mono_class_from_typerefPtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_class_from_typeref'
);
var mono_class_name_from_tokenPtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_class_name_from_token'
);
var mono_class_from_name_casePtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_class_from_name_case'
);
var mono_class_from_namePtr = Module.findExportByName(coreLibraryName, 'il2cpp_class_from_name');
var mono_class_get_namePtr = Module.findExportByName(coreLibraryName, 'il2cpp_class_get_name');
var mono_class_get_name = new NativeFunction(mono_class_get_namePtr, 'pointer', ['pointer']);

var mono_class_get_namespacePtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_class_get_namespace'
);
var mono_class_get_namespace = new NativeFunction(mono_class_get_namespacePtr, 'pointer', [
  'pointer',
]);

var mono_class_get_methodsPtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_class_get_methods'
);
var mono_class_get_methods = new NativeFunction(mono_class_get_methodsPtr, 'pointer', [
  'pointer',
  'pointer',
]);

var mono_class_get_method_from_namePtr = Module.findExportByName(
  null,
  'il2cpp_class_get_method_from_name'
);
var mono_class_get_fieldsPtr = Module.findExportByName(coreLibraryName, 'il2cpp_class_get_fields');
var mono_class_get_fields = new NativeFunction(mono_class_get_fieldsPtr, 'pointer', [
  'pointer',
  'pointer',
]);

var mono_class_get_parentPtr = Module.findExportByName(coreLibraryName, 'il2cpp_class_get_parent');
var mono_class_get_parent = new NativeFunction(mono_class_get_parentPtr, 'pointer', ['pointer']);

var mono_class_get_imagePtr = Module.findExportByName(coreLibraryName, 'il2cpp_class_get_image');
var mono_class_get_image = new NativeFunction(mono_class_get_imagePtr, 'pointer', ['pointer']);

var mono_class_is_genericPtr = Module.findExportByName(coreLibraryName, 'il2cpp_class_is_generic');
var mono_class_is_generic = new NativeFunction(mono_class_is_genericPtr, 'bool', ['pointer']);

var mono_class_is_valuetypePtr = null;
var mono_class_is_valuetype = null;
try {
  mono_class_is_valuetypePtr = Module.findExportByName(
    coreLibraryName,
    'il2cpp_class_is_valuetype'
  );
} catch (e) {
  mono_class_is_valuetype = new NativeFunction(mono_class_is_valuetypePtr, 'int', ['pointer']);
}

var mono_class_vtablePtr = Module.findExportByName(coreLibraryName, 'il2cpp_class_vtable');
var mono_class_from_mono_typePtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_class_from_mono_type'
);
var mono_class_get_element_classPtr = Module.findExportByName(
  null,
  'il2cpp_class_get_element_class'
);
var mono_class_instance_sizePtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_class_instance_size'
);

var mono_class_num_fieldsPtr = Module.findExportByName(coreLibraryName, 'il2cpp_class_num_fields');
var mono_class_num_methodsPtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_class_num_methods'
);

var mono_field_get_namePtr = Module.findExportByName(coreLibraryName, 'il2cpp_field_get_name');
var mono_field_get_name = new NativeFunction(mono_field_get_namePtr, 'pointer', ['pointer']);

var mono_field_get_typePtr = Module.findExportByName(coreLibraryName, 'il2cpp_field_get_type');
var mono_field_get_type = new NativeFunction(mono_field_get_typePtr, 'pointer', ['pointer']);

var mono_field_get_parentPtr = Module.findExportByName(coreLibraryName, 'il2cpp_field_get_parent');
var mono_field_get_parent = new NativeFunction(mono_field_get_parentPtr, 'pointer', ['pointer']);

var mono_field_get_offsetPtr = Module.findExportByName(coreLibraryName, 'il2cpp_field_get_offset');
var mono_field_get_offset = new NativeFunction(mono_field_get_offsetPtr, 'int32', ['pointer']);

var mono_field_get_flagsPtr = Module.findExportByName(coreLibraryName, 'il2cpp_field_get_flags');
var mono_field_get_flags = new NativeFunction(mono_field_get_flagsPtr, 'int', ['pointer']);

var mono_type_get_namePtr = Module.findExportByName(coreLibraryName, 'il2cpp_type_get_name');
var mono_type_get_name = new NativeFunction(mono_type_get_namePtr, 'pointer', ['pointer']);

var mono_type_get_typePtr = Module.findExportByName(coreLibraryName, 'il2cpp_type_get_type');
var mono_type_get_type = new NativeFunction(mono_type_get_typePtr, 'int', ['pointer']);

var mono_type_get_name_fullPtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_type_get_name_full'
);

var mono_method_get_namePtr = Module.findExportByName(coreLibraryName, 'il2cpp_method_get_name');
var mono_method_get_name = new NativeFunction(mono_method_get_namePtr, 'pointer', ['pointer']);

var mono_method_get_classPtr = Module.findExportByName(coreLibraryName, 'il2cpp_method_get_class');
var mono_method_get_headerPtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_method_get_header'
);
var mono_method_signaturePtr = Module.findExportByName(coreLibraryName, 'il2cpp_method_signature');
var mono_method_get_param_namesPtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_method_get_param_names'
);

var mono_method_get_flagsPtr = Module.findExportByName(coreLibraryName, 'il2cpp_method_get_flags');
var mono_method_get_flags = new NativeFunction(mono_method_get_flagsPtr, 'int', ['pointer', 'int']);

var mono_signature_get_descPtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_signature_get_desc'
);
var mono_signature_get_paramsPtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_signature_get_params'
);
var mono_signature_get_param_countPtr = Module.findExportByName(
  null,
  'il2cpp_signature_get_param_count'
);
var mono_signature_get_return_typePtr = Module.findExportByName(
  null,
  'il2cpp_signature_get_return_type'
);

var mono_compile_methodPtr = Module.findExportByName(coreLibraryName, 'il2cpp_compile_method');
var mono_free_methodPtr = Module.findExportByName(coreLibraryName, 'il2cpp_free_method');
var mono_jit_info_table_findPtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_jit_info_table_find'
);
var mono_jit_info_get_methodPtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_jit_info_get_method'
);
var mono_jit_info_get_code_startPtr = Module.findExportByName(
  null,
  'il2cpp_jit_info_get_code_start'
);
var mono_jit_info_get_code_sizePtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_jit_info_get_code_size'
);
var mono_jit_execPtr = Module.findExportByName(coreLibraryName, 'il2cpp_jit_exec');

var mono_method_header_get_codePtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_method_header_get_code'
);
var mono_disasm_codePtr = Module.findExportByName(coreLibraryName, 'il2cpp_disasm_code');

var mono_vtable_get_static_field_dataPtr = Module.findExportByName(
  null,
  'il2cpp_vtable_get_static_field_data'
);

var mono_method_desc_newPtr = Module.findExportByName(coreLibraryName, 'il2cpp_method_desc_new');
var mono_method_desc_from_methodPtr = Module.findExportByName(
  null,
  'il2cpp_method_desc_from_method'
);
var mono_method_desc_freePtr = Module.findExportByName(coreLibraryName, 'il2cpp_method_desc_free');

var mono_string_newPtr = Module.findExportByName(coreLibraryName, 'il2cpp_string_new');
var mono_string_to_utf8Ptr = Module.findExportByName(coreLibraryName, 'il2cpp_string_to_utf8');
var mono_array_newPtr = Module.findExportByName(coreLibraryName, 'il2cpp_array_new');
var mono_value_boxPtr = Module.findExportByName(coreLibraryName, 'il2cpp_value_box');
var mono_object_unboxPtr = Module.findExportByName(coreLibraryName, 'il2cpp_object_unbox');
var mono_object_newPtr = Module.findExportByName(coreLibraryName, 'il2cpp_object_new');

var mono_class_get_typePtr = Module.findExportByName(coreLibraryName, 'il2cpp_class_get_type');
var mono_class_get_type = new NativeFunction(mono_class_get_typePtr, 'pointer', ['pointer']);

var mono_method_desc_search_in_imagePtr = Module.findExportByName(
  null,
  'il2cpp_method_desc_search_in_image'
);
var mono_runtime_invokePtr = Module.findExportByName(coreLibraryName, 'il2cpp_runtime_invoke');
var mono_runtime_object_initPtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_runtime_object_init'
);

var mono_assembly_name_newPtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_assembly_name_new'
);
var mono_assembly_loadedPtr = Module.findExportByName(coreLibraryName, 'il2cpp_assembly_loaded');
var mono_assembly_openPtr = Module.findExportByName(coreLibraryName, 'il2cpp_assembly_open');
var mono_image_openPtr = Module.findExportByName(coreLibraryName, 'il2cpp_image_open');
var mono_image_get_filenamePtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_image_get_filename'
);

var mono_class_get_nesting_typePtr = Module.findExportByName(
  coreLibraryName,
  'mono_class_get_nesting_type'
);

var il2cpp_field_static_get_valuePtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_field_static_get_value'
);
var il2cpp_field_static_get_value = new NativeFunction(il2cpp_field_static_get_valuePtr, 'void', [
  'pointer',
  'pointer',
]);

var il2cpp_field_static_set_valuePtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_field_static_set_value'
);
var il2cpp_field_static_set_value = new NativeFunction(il2cpp_field_static_set_valuePtr, 'void', [
  'pointer',
  'pointer',
]);

var il2cpp_domain_get_assembliesPtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_domain_get_assemblies'
);
var il2cpp_domain_get_assemblies = new NativeFunction(il2cpp_domain_get_assembliesPtr, 'pointer', [
  'pointer',
  'pointer',
]);

var il2cpp_image_get_class_countPtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_image_get_class_count'
);
var il2cpp_image_get_class_count = new NativeFunction(il2cpp_image_get_class_countPtr, 'uint32', [
  'pointer',
]);

var il2cpp_image_get_classPtr = Module.findExportByName(coreLibraryName, 'il2cpp_image_get_class');
var il2cpp_image_get_class = new NativeFunction(il2cpp_image_get_classPtr, 'pointer', [
  'pointer',
  'uint',
]);

var il2cpp_type_get_namePtr = Module.findExportByName(coreLibraryName, 'il2cpp_type_get_name');
var il2cpp_type_get_name = new NativeFunction(il2cpp_type_get_namePtr, 'pointer', ['pointer']);

var il2cpp_type_get_assembly_qualified_namePtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_type_get_assembly_qualified_name'
);

var il2cpp_method_get_param_countPtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_method_get_param_count'
);
var il2cpp_method_get_param_count = new NativeFunction(il2cpp_method_get_param_countPtr, 'uint8', [
  'pointer',
]);

var il2cpp_method_get_param_namePtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_method_get_param_name'
);
var il2cpp_method_get_param_name = new NativeFunction(il2cpp_method_get_param_namePtr, 'pointer', [
  'pointer',
  'uint32',
]);

var il2cpp_method_get_paramPtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_method_get_param'
);
var il2cpp_method_get_param = new NativeFunction(il2cpp_method_get_paramPtr, 'pointer', [
  'pointer',
  'uint32',
]);

var il2cpp_method_get_return_typePtr = Module.findExportByName(
  coreLibraryName,
  'il2cpp_method_get_return_type'
);
var il2cpp_method_get_return_type = new NativeFunction(
  il2cpp_method_get_return_typePtr,
  'pointer',
  ['pointer']
);

var il2cpp_class_from_typePtr = Module.findExportByName(coreLibraryName, 'il2cpp_class_from_type');
var il2cpp_string_charsPtr = Module.findExportByName(coreLibraryName, 'il2cpp_string_chars');

// var mono_selfthread = mono_thread_attach(mono_domain_get());

function InitMono() {
  WriteQword(parseInt(hMono));
}

function EnumAssemblies() {
  var nrofassemblies = Memory.alloc(4);
  var assemblies = il2cpp_domain_get_assemblies(mono_domain_get(), nrofassemblies);

  WriteDword(parseInt(nrofassemblies.readU32()));
  for (var i = 0; i < parseInt(nrofassemblies.readU32()); i++)
    WriteQword(parseInt(assemblies.add(i * 8).readU64()));
}

function GetImageFromAssembly(assembly) {
  var image = mono_assembly_get_image(ptr(assembly));
  WriteQword(parseInt(image));
}

function EnumClassesInImage(image) {
  var count = il2cpp_image_get_class_count(ptr(image));
  WriteDword(count);
  for (var i = 0; i < count; i++) {
    var c = il2cpp_image_get_class(ptr(image), i);
    WriteQword(parseInt(c));
    if (parseInt(c) != 0) {
      var name = mono_class_get_name(c).readUtf8String();
      WriteWord(name.length);
      WriteUtf8String(name);

      name = mono_class_get_namespace(c).readUtf8String();
      WriteWord(name.length);
      WriteUtf8String(name);
    }
  }
}

function EnumMethodsInClass(_class) {
  var iter = Memory.alloc(8);

  while (true) {
    var method = mono_class_get_methods(ptr(_class), iter);
    WriteQword(parseInt(method));

    if (parseInt(method) != 0) {
      var name;
      var flags;

      name = mono_method_get_name(method).readUtf8String();
      flags = mono_method_get_flags(method, 0);

      WriteWord(name.length);
      WriteUtf8String(name);
      WriteDword(flags);
    } else {
      break;
    }
  }
}

function GetFullTypeName(klass, isKlass, nameformat) {
  var ptype = klass && isKlass ? mono_class_get_type(ptr(klass)) : ptr(klass);
  if (ptype) {
    var fullname = il2cpp_type_get_name(ptype).readUtf8String();

    if (fullname != '') {
      WriteWord(fullname.length);
      WriteUtf8String(fullname);
    } else {
      console.log('ERROR');
    }
  } else {
    WriteWord(0);
  }
}

function GetParentClass(klass) {
  var parent = 0;
  if (klass) parent = mono_class_get_parent(ptr(klass));

  WriteQword(parseInt(parent));
}

function GetClassName(klass) {
  var classname = mono_class_get_name(ptr(klass)).readUtf8String();
  WriteWord(classname.length);
  WriteUtf8String(classname);
}

function GetClassNameSpace(klass) {
  var classnamespace = mono_class_get_namespace(ptr(klass)).readUtf8String();
  WriteWord(classnamespace.length);
  WriteUtf8String(classnamespace);
}

function GetClassImage(klass) {
  var image = mono_class_get_image(ptr(klass));
  WriteQword(parseInt(image));
}

function IsClassGeneric(klass) {
  WriteByte(mono_class_is_generic(ptr(klass)));
}

function EnumFieldsInClass(klass) {
  var iter = Memory.alloc(8);
  while (true) {
    var field = mono_class_get_fields(ptr(klass), iter);
    WriteQword(parseInt(field));
    if (parseInt(field) != 0) {
      var fieldtype = mono_field_get_type(field);
      WriteQword(parseInt(fieldtype));
      WriteDword(parseInt(mono_type_get_type(fieldtype)));
      WriteQword(parseInt(mono_field_get_parent(field)));
      WriteDword(mono_field_get_offset(field));
      WriteDword(mono_field_get_flags(field));

      var name = mono_field_get_name(field).readUtf8String();
      var type = mono_type_get_name(fieldtype).readUtf8String();

      WriteWord(name.length);
      WriteUtf8String(name);

      WriteWord(type.length);
      WriteUtf8String(type);
    } else {
      break;
    }
  }
}

function GetMethodSignature(method) {
  var paramcount = il2cpp_method_get_param_count(ptr(method));

  WriteByte(paramcount);

  for (var i = 0; i < paramcount; i++) {
    var name = il2cpp_method_get_param_name(ptr(method), i).readUtf8String();
    WriteByte(name.length);
    WriteUtf8String(name);
  }

  for (var i = 0; i < paramcount; i++) {
    var type = il2cpp_method_get_param(ptr(method), i);
    var name = il2cpp_type_get_name(type).readUtf8String();
    WriteWord(name.length);
    WriteUtf8String(name);
  }

  var type = il2cpp_method_get_return_type(ptr(method));
  var name = il2cpp_type_get_name(type).readUtf8String();
  WriteByte(name.length);
  WriteUtf8String(name);
}

function GetStaticFieldValue(vtable, field) {
  var val = Memory.alloc(8);

  il2cpp_field_static_get_value(ptr(field), val);
  WriteQword(parseInt(val.readU64()));
}

function SetStaticFieldValue(vtable, field, value) {
  var tmp = Memory.alloc(8);
  tmp.writeU64(value);
  il2cpp_field_static_set_value(ptr(field), tmp);
}

function GetImageName(image) {
  var p = mono_image_get_name(ptr(image));
  var s = p.readUtf8String();

  WriteWord(s.length);
  WriteUtf8String(s);
}

function EnumImages() {
  var nrofassemblies = Memory.alloc(4);
  var assemblies = il2cpp_domain_get_assemblies(mono_domain_get(), nrofassemblies);
  var reply = Memory.alloc(1000000);
  var reply_pos = 0;
  for (var i = 0; i < parseInt(nrofassemblies.readU32()); i++) {
    var p = parseInt(assemblies.add(i * 8).readU64());
    var image = mono_assembly_get_image(ptr(p));
    reply.add(reply_pos).writeU64(parseInt(image));
    reply_pos += 8;
    var name = mono_image_get_name(image).readUtf8String();
    var len = name.length;
    if (len > 512) len = 512;
    reply.add(reply_pos).writeU16(len);
    reply_pos += 2;
    reply.add(reply_pos).writeUtf8String(name);
    reply_pos += len;
  }
  return reply.readByteArray(reply_pos);
}

function EnumClassesInImagex(image) {
  var count = il2cpp_image_get_class_count(ptr(image));
  var reply = Memory.alloc(1000000);
  var reply_pos = 0;
  reply.add(reply_pos).writeU32(count);
  reply_pos += 4;
  for (var i = 0; i < count; i++) {
    var c = il2cpp_image_get_class(ptr(image), i);
    reply.add(reply_pos).writeU64(parseInt(c));
    reply_pos += 8;
    if (parseInt(c) != 0) {
      var parent = mono_class_get_parent(c);
      reply.add(reply_pos).writeU64(parseInt(parent));
      reply_pos += 8;
      var nestingtype = 0;
      reply.add(reply_pos).writeU64(parseInt(nestingtype));
      reply_pos += 8;
      var name = mono_class_get_name(c).readUtf8String();
      var sl = name.length;
      reply.add(reply_pos).writeU16(sl);
      reply_pos += 2;
      reply.add(reply_pos).writeUtf8String(name);
      reply_pos += sl;
      var ns = mono_class_get_namespace(c).readUtf8String();
      sl = ns.length;
      reply.add(reply_pos).writeU16(sl);
      reply_pos += 2;
      reply.add(reply_pos).writeUtf8String(ns);
      reply_pos += sl;
      var fullname = GetFullTypeNameStr(c, 1, MONO_TYPE_NAME_FORMAT_REFLECTION);
      sl = fullname.length;
      reply.add(reply_pos).writeU16(sl);
      reply_pos += 2;
      reply.add(reply_pos).writeUtf8String(fullname);
      reply_pos += sl;
    } else {
      reply_pos += 22;
    }
  }
  return reply.readByteArray(reply_pos);
}

function GetFullTypeNameStr(klass, isKlass, nameformat) {
  var ptype = mono_class_get_type(ptr(klass));
  if (parseInt(ptype) != 0) {
    try {
      var fullname = il2cpp_type_get_name(ptype);
      return fullname.readUtf8String();
    } catch (e) {
      console.log(e);
      return 'exception';
    }
  } else {
    return '<invalid ptype>';
  }
}

function GetFieldClass(field) {
  var type = field ? mono_field_get_type(ptr(field)) : 0;
  var klass = type ? mono_class_from_type(type) : 0;
  WriteQword(parseInt(klass));
}

function IsValueTypeClass(klass) {
  if (mono_class_is_valuetype != null) {
    var flag = mono_class_is_valuetype(ptr(klass));
    WriteByte(flag);
  } else {
    WriteByte(0);
  }
}

rpc.exports = {
  initmono: function () {
    InitMono();
  },
  isil2cpp: function () {
    var value = 0;
    if (il2cpp) value = 1;
    WriteByte(value);
  },
  enumassemblies: function () {
    EnumAssemblies();
  },
  getimagefromassembly: function (assembly) {
    GetImageFromAssembly(assembly);
  },
  getimagename: function (image) {
    GetImageName(image);
  },
  enumclassesinimage: function (image) {
    EnumClassesInImage(image);
  },
  enumdomains: function () {
    return parseInt(mono_domain_get());
  },
  enummethodsinclass: function (_class) {
    EnumMethodsInClass(_class);
  },
  getfulltypename: function (klass, isKlass, nameformat) {
    GetFullTypeName(klass, isKlass, nameformat);
  },
  getparentclass: function (klass) {
    GetParentClass(klass);
  },
  getclassname: function (klass) {
    GetClassName(klass);
  },
  getclassnamespace: function (klass) {
    GetClassNameSpace(klass);
  },
  getclassimage: function (klass) {
    GetClassImage(klass);
  },
  isclassgeneric: function (klass) {
    IsClassGeneric(klass);
  },
  enumfieldsinclass: function (klass) {
    EnumFieldsInClass(klass);
  },
  getmethodsignature: function (method) {
    GetMethodSignature(method);
  },
  getstaticfieldvalue: function (vtable, field) {
    GetStaticFieldValue(vtable, field);
  },
  setstaticfieldvalue: function (vtable, field, value) {
    SetStaticFieldValue(vtable, field, value);
  },
  compilemethod: function (method) {
    return parseInt(ptr(method).readU64());
  },
  enumimages: function () {
    return EnumImages();
  },
  enumclassesinimageex: function (image) {
    return EnumClassesInImagex(image);
  },
  getfieldclass: function (field) {
    GetFieldClass(field);
  },
  isvaluetypeclass: function (klass) {
    return IsValueTypeClass(klass);
  },
  getinfo: function () {
    var pid = Process.id;
    var info = { pid: pid };
    return info;
  },
};
