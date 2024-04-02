from enum import Enum


class OS(Enum):
    LINUX = "linux"
    ANDROID = "android"
    IOS = "ios"
    WINDOWS = "windows"
    MAC = "mac"


class MODE(Enum):
    SPAWN = "spawn"
    ATTACH = "attach"
    ENUM = "enum"


class ARCHITECTURE(Enum):
    IA32 = "ia32"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"
