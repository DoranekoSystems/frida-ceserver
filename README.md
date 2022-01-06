# frida-ceserver

Cross-platform frida-based ceserver.  
Support for Android/iOS/Linux.

Original by Dark Byte.

# Usage

Install python library.

```
pip install packaging
pip install pywin32
```

Install frida on iOS.

```
python main.py Cydia

# or

python main.py com.saurik.Cydia
```

Then, connect to the Cheat Engine in network mode.

The debugger is not available!

![img](https://user-images.githubusercontent.com/56913432/120924433-baa86600-c70e-11eb-8794-ab5c28ec50b6.png)

# Extended function

### Run the frida javascript code from within AutoAssembler.

If a string is written to an address between 0 and 100, it will be interpreted as frida javascript code and executed.  
The address is also mapped to a script number.  
If you write "UNLOAD" with the same number, the script will be canceled.

```
{$lua}
[enable]
local jscode = [[
console.log("HELLO,WORLD!");
]]
writeString(0,jscode)
[disable]
writeString(0,[[UNLOAD]])
```

# BinUtils

### ARM64 Disassembler/Assembler

By default, Cheat Engine does not implement the ARM64 disassembler.  
This can be supported by using the extension BinUtils.  
Download android-ndk, change path_to_android_ndk in the script below to the destination and put it in the autorun folder.  
Select View->BinUtils->ARM64 BinUtils to change the disassembly to ARM64.

```
local arm64config={}
arm64config.Name="ARM64"
arm64config.Description="BinUtils"
arm64config.Architecture="aarch64"
arm64config.Path=[[path_to_android_ndk\toolchains\aarch64-linux-android-4.9\prebuilt\windows-x86_64\bin]]
arm64config.Prefix="aarch64-linux-android-"
registerBinUtil(arm64config)
```

# Config

### target

If you specify it, you don't need to specify the name of the target app in the argument.

### targetOS

`0`:Linux  
`1`:Android  
`2`:iOS

### mode

spawn is only valid for mobile device.  
`0`:spawn  
`1`:attach

### arch

`0`:i386  
`1`:x86_64  
`2`:arm  
`3`:aarch64

### fix_module_size

It is not possible to get the exact size of some modules in iOS.  
In this case, the module size will be corrected to the actual file size in order to get a larger module size.  
`true`:Enable the above function  
`false`:Disable the above function

### ceversion

Specify the version of the cheat engine itself.  
Since the part related to communication between the main unit and the ceserver differs depending on the version, the setting is necessary.

### manualParser

Valid for linux/android.  
Uses almost the same parsing of elf files as the original ceserver.

### javaDissect

Valid for android/iOS.  
Only 「Dissect Java classes」 are valid.The edit method is not supported.  
For iOS, analyze Objective-C.  
![img](https://user-images.githubusercontent.com/96031346/148321374-ee8e51de-268a-468d-8b1e-ee17c7e6e4ca.png)

# Credits

iGio90:[frida-elf](https://github.com/iGio90/frida-elf)

```
Copyright (c) 2019 Giovanni (iGio90) Rocca

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
