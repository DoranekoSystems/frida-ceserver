# frida-ceserver

frida based ceserver.Fusion of cheat engine and frida.  

Original by Dark Byte.

# Support Platforms

## Host OS
- Windows
- Mac(Newer than CE 7.4.2)

## Target OS

### Memory Analyzing

- iOS
- android
- linux
- windows
- mac

### Debugger

Implements lldb and gdb based debugger.  
Support for `「Find out what accesses/writes this address」` only.

- iOS(aarch64)
- android(aarch64)

# Usage

Install python library.

```
# windows

pip install -r requirements.txt

# mac

pip install -r requirements_mac.txt
```

Install frida on iOS.

```
python main.py Cydia

# or

python main.py com.saurik.Cydia

# or

python main.py -p ProcessId
```

Then, connect to the Cheat Engine in network mode.

The debugger is currently under development!

![img](https://user-images.githubusercontent.com/56913432/120924433-baa86600-c70e-11eb-8794-ab5c28ec50b6.png)

# wiki

[BinUtils](https://github.com/DoranekoSystems/frida-ceserver/wiki/BinUtils 'BinUtils')

[Config](https://github.com/DoranekoSystems/frida-ceserver/wiki/Config 'Config')

[Debugger](https://github.com/DoranekoSystems/frida-ceserver/wiki/Debugger 'Debugger')

[Extended function](https://github.com/DoranekoSystems/frida-ceserver/wiki/Extended-function 'Extended function')

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
