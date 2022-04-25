import os
import sys
from enum import Enum, auto


class OS(Enum):
    LINUX = "linux"
    ANDROID = "android"
    IOS = "ios"
    WINDOWS = "windows"
    MAC = "mac"


class MODE(Enum):
    SPAWN = "spawn"
    ATTACH = "attach"
