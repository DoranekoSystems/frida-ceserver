import os
import sys
from enum import IntEnum, auto


class OS(IntEnum):
    LINUX = 0
    ANDROID = 1
    IOS = 2
    WINDOWS = 3


class MODE(IntEnum):
    SPAWN = 0
    ATTACH = 1
