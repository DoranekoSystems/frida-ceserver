#
#   textmode.py     WJ116
#
#   Copyright 2016 by Walter de Jong <walter@heiho.net>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""classes and routines for text mode screens"""

import curses
import os
import re
import sys
import time
import traceback

# the main video object
VIDEO = None

# the curses stdscr
STDSCR = None

# color codes
(BLACK, BLUE, GREEN, CYAN, RED, MAGENTA, YELLOW, WHITE) = range(0, 8)
BOLD = 8

# list of curses color codes
# initialized during init() (because curses is crazy; it doesn't have
# any of it's static constants/symbols until you initialize it)
CURSES_COLORS = None
CURSES_COLORPAIRS = {}
CURSES_COLORPAIR_IDX = 0
# user wants colors
WANT_COLORS = True
# terminal can do color at all
HAS_COLORS = False

LM_HLINE = 1
LM_VLINE = 2
LM_ASCII = 4
LINEMODE = LM_HLINE | LM_VLINE
CURSES_LINES = None

# curses key codes get translated to strings by getch()
# There is no support for F-keys! Functions keys are evil on Macs
KEY_ESC = "ESC"
KEY_RETURN = "RETURN"
KEY_TAB = "TAB"
KEY_BTAB = "BTAB"
KEY_LEFT = "LEFT"
KEY_RIGHT = "RIGHT"
KEY_UP = "UP"
KEY_DOWN = "DOWN"
KEY_PAGEUP = "PAGEUP"
KEY_PAGEDOWN = "PAGEDOWN"
KEY_HOME = "HOME"
KEY_END = "END"
KEY_DEL = "DEL"
KEY_BS = "BS"

KEY_TABLE = {
    "0x1b": KEY_ESC,
    "0x0a": KEY_RETURN,
    "0x0d": KEY_RETURN,
    "0x09": KEY_TAB,
    "0x161": KEY_BTAB,
    "0x102": KEY_DOWN,
    "0x103": KEY_UP,
    "0x104": KEY_LEFT,
    "0x105": KEY_RIGHT,
    "0x152": KEY_PAGEDOWN,
    "0x153": KEY_PAGEUP,
    "0x106": KEY_HOME,
    "0x168": KEY_END,
    "0x14a": KEY_DEL,
    "0x107": KEY_BS,
    "0x7f": KEY_BS,
}

REGEX_HOTKEY = re.compile(r".*<((Ctrl-)?[!-~])>.*$")

# window stack
STACK = None

# debug messages
DEBUG_LOG = []

# program states
# these enums are all negative; cursor choices are positive (inc. 0)
# FIXME cleanup app codes list, use the shorter codes
(
    RETURN_TO_PREVIOUS,
    GOTO_MENUBAR,
    MENU_LEFT,
    MENU_RIGHT,
    MENU_CLOSE,
    CANCEL,
    ENTER,
    BACK,
    NEXT,
    EXIT,
    QUIT,
) = range(-1, -12, -1)


def debug(msg):
    """keep message in debug log"""

    DEBUG_LOG.append(msg)


def dump_debug():
    """dump out the debug log"""

    global DEBUG_LOG

    for msg in DEBUG_LOG:
        print(msg)

    DEBUG_LOG = []


class ScreenBuf:
    """base class for screen buffers
    It basically implements a monochrome screenbuf in which
    colors are ignored. You should however use either
    MonoScreenBuf or ColorScreenBuf and not directly instantiate
    this ScreenBuf class

    The text buffer holds one byte per character in 7 bits ASCII
    If the 8th bit is set, it is a special character (eg. a curses line)
    """

    # codepage defines the character set
    # the original charset of as IBM PC VGA screen was cp437
    # but it gives me artifacts now (prints '$' signs, which could be a bug?)
    # so use latin_1 or cp1252
    # Note: we must use single-byte character encoding because we use a bytearray
    # (which is a bad choice in today's world, but ScreenBuf mimics VGA)
    CODEPAGE = "cp1252"

    def __init__(self, w, h):
        """initialize"""

        assert w > 0
        assert h > 0

        self.w = w
        self.h = h

        self.textbuf = bytearray(w * h)

    def __getitem__(self, idx):
        """Returns tuple: (ch, color) at idx
        idx may be an offset or tuple: (x, y) position

        Raises IndexError, ValueError on invalid index
        """

        if isinstance(idx, int):
            offset = idx

        elif isinstance(idx, tuple):
            x, y = idx
            offset = self.w * y + x

        else:
            raise ValueError("invalid argument")

        ch = self.textbuf[offset]
        if ch == 0:
            # blank
            ch = " "
        elif ch > 0x7F:
            # special curses character
            ch &= 0x7F
            ch |= 0x400000
        else:
            # make string
            ch = chr(ch)

        return ch, 0

    def __setitem__(self, idx, value):
        """put tuple: (ch, color) at idx
        idx may be an offset or tuple: (x, y) position

        Raises IndexError, ValueError on invalid index
        or ValueError on invalid value
        """

        ch, _ = value

        if isinstance(ch, str):
            ch = ord(ch)
        elif ch > 0x400000:
            # special curses character
            ch &= 0x7F
            ch |= 0x80

        if isinstance(idx, int):
            offset = idx

        elif isinstance(idx, tuple):
            x, y = idx
            offset = self.w * y + x

        else:
            raise ValueError("invalid argument")

        self.textbuf[offset] = ch

    def puts(self, x, y, msg, color=0):
        """write message into buffer at x, y"""

        offset = self.w * y + x
        w = len(msg)
        self.textbuf[offset : offset + w] = bytes(msg, ScreenBuf.CODEPAGE)

    def hline(self, x, y, w, ch, color=0):
        """repeat character horizontally"""

        if isinstance(ch, str):
            ch = ord(ch)
        elif ch > 0x400000:
            # special curses character
            ch &= 0x7F
            ch |= 0x80

        offset = self.w * y + x
        self.textbuf[offset : offset + w] = bytes(chr(ch) * w, ScreenBuf.CODEPAGE)

    def vline(self, x, y, h, ch, color=0):
        """repeat character horizontally"""

        if isinstance(ch, str):
            ch = ord(ch)
        elif ch > 0x400000:
            # special curses character
            ch &= 0x7F
            ch |= 0x80

        offset = self.w * y + x
        for _ in range(0, h):
            self.textbuf[offset] = ch
            offset += self.w

    def memmove(self, dst_idx, src_idx, num):
        """copy num bytes at src_idx to dst_idx"""

        dst2 = dst_idx + num
        src2 = src_idx + num
        self.textbuf[dst_idx:dst2] = self.textbuf[src_idx:src2]

    def copyrect(self, dx, dy, src, sx=0, sy=0, sw=0, sh=0):
        """copy src rect sx,sy,sw,sh to dest self at dx,dy"""

        assert isinstance(src, ScreenBuf)
        assert dx >= 0
        assert dy >= 0
        assert sx >= 0
        assert sy >= 0

        if sw == 0:
            sw = src.w
        if sh == 0:
            sh = src.h

        if sw > self.w:
            sw = self.w
        if sh > self.h:
            sh = self.h

        assert sw > 0
        assert sh > 0

        # local function
        def copyline(dst, dx, dy, src, sx, sy, sw):
            """copy line at sx,sy to dest dx,dy"""

            si = sy * src.w + sx
            di = dy * dst.w + dx
            dst.textbuf[di : di + sw] = src.textbuf[si : si + sw]

        # copy rect by copying line by line
        for j in range(0, sh):
            copyline(self, dx, dy + j, src, sx, sy + j, sw)


class MonoScreenBuf(ScreenBuf):
    """monochrome screen buffer has no colors"""


class ColorScreenBuf(ScreenBuf):
    """a color screen buffer consist of two planes:
    a text buffer and a color buffer
    The text buffer holds one byte per character in 7 bits ASCII
    If the 8th bit is set, it is a special character (eg. a curses line)
    The color buffer holds one byte per color
    encoded as (bg << 4) | bold | fg
    """

    # There are some asserts, but in general,
    # ScreenBuf shouldn't care about buffer overruns or clipping
    # because  a) that's a bug   b) performance   c) handled by class Video

    def __init__(self, w, h):
        """initialize"""

        super().__init__(w, h)

        self.colorbuf = bytearray(w * h)

    def __getitem__(self, idx):
        """Returns tuple: (ch, color) at idx
        idx may be an offset or tuple: (x, y) position

        Raises IndexError, ValueError on invalid index
        """

        if isinstance(idx, int):
            offset = idx

        elif isinstance(idx, tuple):
            x, y = idx
            offset = self.w * y + x

        else:
            raise ValueError("invalid argument")

        ch = self.textbuf[offset]
        if ch == 0:
            # blank
            ch = " "
        elif ch > 0x7F:
            # special curses character
            ch &= 0x7F
            ch |= 0x400000
        else:
            # make string
            ch = chr(ch)

        color = self.colorbuf[offset]
        return ch, color

    def __setitem__(self, idx, value):
        """put tuple: (ch, color) at idx
        idx may be an offset or tuple: (x, y) position

        Raises IndexError, ValueError on invalid index
        or ValueError on invalid value
        """

        ch, color = value

        if isinstance(ch, str):
            ch = ord(ch)
        elif ch > 0x400000:
            # special curses character
            ch &= 0x7F
            ch |= 0x80

        if isinstance(idx, int):
            offset = idx

        elif isinstance(idx, tuple):
            x, y = idx
            offset = self.w * y + x

        else:
            raise ValueError("invalid argument")
        try:
            self.textbuf[offset] = ch
        except:
            pass
        self.colorbuf[offset] = color

    def puts(self, x, y, msg, color):  # pylint: disable=signature-differs
        """write message into buffer at x, y"""

        offset = self.w * y + x
        w = len(msg)
        self.textbuf[offset : offset + w] = bytes(msg, ScreenBuf.CODEPAGE)
        self.colorbuf[offset : offset + w] = bytes(chr(color) * w, ScreenBuf.CODEPAGE)

    def hline(self, x, y, w, ch, color):  # pylint: disable=signature-differs
        """repeat character horizontally"""
        if isinstance(ch, str):
            ch = ord(ch)
        elif ch > 0x400000:
            # special curses character
            ch &= 0x7F
            ch |= 0x80
        offset = self.w * y + x
        self.textbuf[offset : offset + w] = (
            chr(ch) * w
        ).encode()  # bytes(chr(ch) * w, ScreenBuf.CODEPAGE)
        self.colorbuf[offset : offset + w] = bytes(chr(color) * w, ScreenBuf.CODEPAGE)

    def vline(self, x, y, h, ch, color):  # pylint: disable=signature-differs
        """repeat character horizontally"""

        if isinstance(ch, str):
            ch = ord(ch)
        elif ch > 0x400000:
            # special curses character
            ch &= 0x7F
            ch |= 0x80

        offset = self.w * y + x
        for _ in range(0, h):
            try:
                self.textbuf[offset] = ch
            except:
                pass
            self.colorbuf[offset] = color
            offset += self.w

    def memmove(self, dst_idx, src_idx, num):
        """copy num bytes at src_idx to dst_idx"""

        dst2 = dst_idx + num
        src2 = src_idx + num
        self.textbuf[dst_idx:dst2] = self.textbuf[src_idx:src2]
        self.colorbuf[dst_idx:dst2] = self.colorbuf[src_idx:src2]

    def copyrect(self, dx, dy, src, sx=0, sy=0, sw=0, sh=0):
        """copy src rect sx,sy,sw,sh to dest self at dx,dy"""

        assert isinstance(src, ScreenBuf)
        assert dx >= 0
        assert dy >= 0
        assert sx >= 0
        assert sy >= 0

        if sw == 0:
            sw = src.w
        if sh == 0:
            sh = src.h

        if sw > self.w:
            sw = self.w
        if sh > self.h:
            sh = self.h

        assert sw > 0
        assert sh > 0

        # local function
        def copyline(dst, dx, dy, src, sx, sy, sw):
            """copy line at sx,sy to dest dx,dy"""

            si = sy * src.w + sx
            di = dy * dst.w + dx
            dst.textbuf[di : di + sw] = src.textbuf[si : si + sw]
            dst.colorbuf[di : di + sw] = src.colorbuf[si : si + sw]

        # copy rect by copying line by line
        for j in range(0, sh):
            copyline(self, dx, dy + j, src, sx, sy + j, sw)


class Rect:
    """represents a rectangle"""

    def __init__(self, x, y, w, h):
        """initialize"""

        assert w > 0
        assert h > 0

        self.x = x
        self.y = y
        self.w = w
        self.h = h

    def __str__(self):
        """Returns string representation"""

        return "{{{}, {}, {}, {}}}".format(self.x, self.y, self.w, self.h)

    def copy(self):
        """Returns a copy"""

        return Rect(self.x, self.y, self.w, self.h)

    def clamp(self, x, y):
        """Returns clamped tuple: x, y"""

        if x < self.x:
            x = self.x
        if x > self.x + self.w:
            x = self.x + self.w
        if y < self.y:
            y = self.y
        if y > self.y + self.h:
            y = self.y + self.h

        return x, y

    # Note: the clipping methods work with relative coordinates
    # and don't care about the position of the Rect
    # ie. they don't use self.x, self.y
    # To obtain the absolute clipping coordinates, translate
    # the result by rect.x, rect.y

    def clip_point(self, x, y):
        """clip point at relative x, y against rect
        Returns True if point is in the rect;
        if True then the point is visible
        """

        return 0 <= x < self.w and 0 <= y < self.h

    def clip_hline(self, x, y, w):
        """clip horizontal line against rect
        If visible, returns clipped tuple: True, x, y, w
        """

        if (
            x + w < 0 or x >= self.w or y < 0 or y >= self.h
        ):  # pylint: disable=chained-comparison
            return False, -1, -1, -1

        if x < 0:
            w += x
            x = 0

        if x + w > self.w:
            w = self.w - x

        return True, x, y, w

    def clip_vline(self, x, y, h):
        """clip vertical line against rect
        If visible, returns clipped tuple: True, x, y, h
        """

        if (
            x < 0 or x >= self.w or y + h < 0 or y >= self.h
        ):  # pylint: disable=chained-comparison
            return False, -1, -1, -1

        if y < 0:
            h += y
            y = 0

        if y + h > self.h:
            h = self.h - y

        return True, x, y, h

    def clip_rect(self, x, y, w, h):
        """clip rectangle against rect
        If visible, returns clipped tuple: True, x, y, w, h
        """

        if (
            x + w < 0 or x >= self.w or y + h < 0 or y >= self.h
        ):  # pylint: disable=chained-comparison
            return False, -1, -1, -1, -1

        if x < 0:
            w += x
            x = 0

        if x + w > self.w:
            w = self.w - x

        if y < 0:
            h += y
            y = 0

        if y + h > self.h:
            h = self.h - y

        return True, x, y, w, h


class Video:
    """text mode video"""

    def __init__(self):
        """initialize"""

        if STDSCR is None:
            init_curses()

        self.h, self.w = STDSCR.getmaxyx()
        if HAS_COLORS:
            self.screenbuf = ColorScreenBuf(self.w, self.h)
        else:
            self.screenbuf = MonoScreenBuf(self.w, self.h)

        self.rect = Rect(0, 0, self.w, self.h)
        self.color = video_color(WHITE, BLACK, bold=False)
        self.curses_color = curses_color(WHITE, BLACK, bold=False)

    def set_color(self, fg, bg=None, bold=True, alt=False):
        """set current color
        Returns the combined color code
        """

        self.color = video_color(fg, bg, bold)
        self.curses_color = curses_color(fg, bg, bold, alt)
        return self.color

    def putch(self, x, y, ch, color=-1, alt=False):
        """put character at x, y"""

        # clipping
        if not self.rect.clip_point(x, y):
            return

        if color == -1:
            color = self.color
            attr = self.curses_color
        else:
            attr = curses_color(color, alt=alt)

        self.screenbuf[x, y] = (ch, color)
        self.curses_putch(x, y, ch, attr)

    def puts(self, x, y, msg, color=-1, alt=False):
        """write message at x, y"""

        visible, cx, cy, cw = self.rect.clip_hline(x, y, len(msg))
        if not visible:
            return

        # clip message
        if x < 0:
            msg = msg[-x:]
            if not msg:
                return

        if len(msg) > cw:
            msg = msg[:cw]
            if not msg:
                return

        if color == -1:
            color = self.color
            attr = self.curses_color
        else:
            attr = curses_color(color, alt=alt)

        self.screenbuf.puts(cx, cy, msg, color)
        self.curses_puts(cx, cy, msg, attr)

    def curses_putch(self, x, y, ch, attr=None, alt=False):
        """put character into the curses screen x, y"""

        # curses.addch() has issues with drawing in the right bottom corner
        # because it wants to scroll, but it can't
        # curses.insch() messes up the screen royally, because it inserts
        # the character and pushes the remainder of the line forward
        # Both aren't ideal to work with, but we _can_ use insch()
        # at the end of screen
        # Note that it doesn't matter whether you use scrollok() or not

        if attr is None:
            attr = self.curses_color

        if y >= self.h - 1 and x >= self.w - 1:
            STDSCR.insch(y, x, ch, attr)
        else:
            STDSCR.addch(y, x, ch, attr)

    def curses_puts(self, x, y, msg, attr=None):
        """print message into the curses screen at x, y"""

        # curses.addstr() has issues with drawing in the right bottom corner
        # because it wants to scroll, but it can't
        # curses.insstr() messes up the screen royally, because it inserts text
        # and pushes the remainder of the line forward
        # Both aren't ideal to work with, but we _can_ use insstr()
        # at the end of screen
        # Note that it doesn't matter whether you use scrollok() or not

        if attr is None:
            attr = self.curses_color

        if y >= self.h - 1 and x + len(msg) >= self.w:
            STDSCR.insstr(y, x, msg, attr)
        else:
            STDSCR.addstr(y, x, msg, attr)

    def hline(self, x, y, w, ch, color=-1, alt=False):
        """draw horizontal line at x, y"""

        visible, x, y, w = self.rect.clip_hline(x, y, w)
        if not visible:
            return

        if color == -1:
            color = self.color
            attr = self.curses_color
        else:
            attr = curses_color(color, alt=alt)

        self.screenbuf.hline(x, y, w, ch, color)
        if isinstance(ch, str):
            ch = ord(ch)
        STDSCR.hline(y, x, ch, w, attr)

    def vline(self, x, y, h, ch, color=-1, alt=False):
        """draw vertical line at x, y"""

        visible, x, y, h = self.rect.clip_vline(x, y, h)
        if not visible:
            return

        if color == -1:
            color = self.color
            attr = self.curses_color
        else:
            attr = curses_color(color, alt=alt)

        self.screenbuf.vline(x, y, h, ch, color)
        if isinstance(ch, str):
            ch = ord(ch)
        STDSCR.vline(y, x, ch, h, attr)

    def hsplit(self, x, y, w, ch, color=-1, alt=False):
        """draw a horizontal split"""

        self.hline(x + 1, y, w - 2, curses.ACS_HLINE, color, alt)
        # put tee characters on the sides
        self.putch(x, y, curses.ACS_LTEE, color, alt)
        self.putch(x + w - 1, y, curses.ACS_RTEE, color, alt)

    def vsplit(self, x, y, h, ch, color=-1, alt=False):
        """draw a vertical split"""

        self.vline(x, y + 1, h - 2, curses.ACS_VLINE, color, alt)
        # put tee characters on the sides
        self.putch(x, y, curses.ACS_TTEE, color, alt)
        self.putch(x, y + h - 1, curses.ACS_BTEE, color, alt)

    def fillrect(self, x, y, w, h, color=-1, alt=False):
        """draw rectangle at x, y"""

        visible, x, y, w, h = self.rect.clip_rect(x, y, w, h)
        if not visible:
            return

        if color == -1:
            color = self.color
            attr = self.curses_color
        else:
            attr = curses_color(color, alt=alt)

        for j in range(0, h):
            self.screenbuf.hline(x, y + j, w, " ", color)
            STDSCR.hline(y + j, x, " ", w, attr)

    def border(self, x, y, w, h, color=-1, alt=False):
        """draw rectangle border"""

        visible, cx, cy, cw, ch = self.rect.clip_rect(x, y, w, h)
        if not visible:
            return

        if color == -1:
            color = self.color
            attr = self.curses_color
        else:
            attr = curses_color(color, alt=alt)

        # top
        if 0 <= y < self.h:
            self.screenbuf.hline(cx, y, cw, curses.ACS_HLINE, color)
            STDSCR.hline(y, cx, curses.ACS_HLINE, cw, attr)

        # left
        if 0 <= x < self.w:
            self.screenbuf.vline(x, cy, ch, curses.ACS_VLINE, color)
            STDSCR.vline(cy, x, curses.ACS_VLINE, ch, attr)

        # right
        rx = x + w - 1
        if 0 <= rx < self.w:
            self.screenbuf.vline(rx, cy, ch, curses.ACS_VLINE, color)
            STDSCR.vline(cy, rx, curses.ACS_VLINE, ch, attr)

        # bottom
        by = y + h - 1
        if 0 <= by < self.h:
            self.screenbuf.hline(cx, by, cw, curses.ACS_HLINE, color)
            STDSCR.hline(by, cx, curses.ACS_HLINE, cw, attr)

        # top left corner
        if self.rect.clip_point(x, y):
            self.screenbuf[x, y] = (curses.ACS_ULCORNER, color)
            self.curses_putch(x, y, curses.ACS_ULCORNER, attr)

        # bottom left corner
        if self.rect.clip_point(x, by):
            self.screenbuf[x, by] = (curses.ACS_LLCORNER, color)
            self.curses_putch(x, by, curses.ACS_LLCORNER, attr)

        # top right corner
        if self.rect.clip_point(rx, y):
            self.screenbuf[rx, y] = (curses.ACS_URCORNER, color)
            self.curses_putch(rx, y, curses.ACS_URCORNER, attr)

        # bottom right corner
        if self.rect.clip_point(rx, by):
            self.screenbuf[rx, by] = (curses.ACS_LRCORNER, color)
            self.curses_putch(rx, by, curses.ACS_LRCORNER, attr)

    def color_putch(self, x, y, color=-1, alt=False):
        """put color at x, y"""

        if not self.rect.clip_point(x, y):
            return

        if color == -1:
            color = self.color
            attr = self.curses_color
        else:
            attr = curses_color(color, alt=alt)

        # get the character and redraw with color
        offset = self.w * y + x
        ch, _ = self.screenbuf[offset]
        self.screenbuf[offset] = (ch, color)
        if isinstance(ch, str):
            ch = ord(ch)
        self.curses_putch(x, y, ch, attr)

    def color_hline(self, x, y, w, color=-1, alt=False):
        """draw horizontal color line"""

        visible, x, y, w = self.rect.clip_hline(x, y, w)
        if not visible:
            return

        if color == -1:
            color = self.color
            attr = self.curses_color
        else:
            attr = curses_color(color, alt=alt)

        # get the character and redraw with color
        offset = self.w * y + x
        for i in range(0, w):
            ch, _ = self.screenbuf[offset]
            self.screenbuf[offset] = (ch, color)
            offset += 1
            if isinstance(ch, str):
                ch = ord(ch)
            self.curses_putch(x + i, y, ch, attr)

    def color_vline(self, x, y, h, color=-1, alt=False):
        """draw vertical colored line"""

        visible, x, y, h = self.rect.clip_vline(x, y, h)
        if not visible:
            return

        if color == -1:
            color = self.color
            attr = self.curses_color
        else:
            attr = curses_color(color, alt=alt)

        # get the character and redraw with color
        offset = self.w * y + x
        for j in range(0, h):
            ch, _ = self.screenbuf[offset]
            self.screenbuf[offset] = (ch, color)
            offset += self.w
            if isinstance(ch, str):
                ch = ord(ch)
            self.curses_putch(x, y + j, ch, attr)

    def getrect(self, x, y, w, h):
        """Returns ScreenBuf object with copy of x,y,w,h
        or None if outside clip area
        """

        visible, x, y, w, h = self.rect.clip_rect(x, y, w, h)
        if not visible:
            return None

        if HAS_COLORS:
            copy = ColorScreenBuf(w, h)
        else:
            copy = MonoScreenBuf(w, h)

        copy.copyrect(0, 0, self.screenbuf, x, y, w, h)
        return copy

    def putrect(self, x, y, buf):
        """Put ScreenBuf buf at x, y"""

        if buf is None:
            return

        assert isinstance(buf, ScreenBuf)

        # we assume buf was created by getrect()
        # therefore we can safely assume it is already clipped right
        # but do clamp to (0,0) to get rid of negative coordinates
        x, y = self.rect.clamp(x, y)
        if not self.rect.clip_point(x, y):
            return

        self.screenbuf.copyrect(x, y, buf, 0, 0, buf.w, buf.h)
        # update the curses screen
        prev_color = None
        offset = self.w * y + x
        for j in range(0, buf.h):
            for i in range(0, buf.w):
                ch, color = self.screenbuf[offset]
                if isinstance(ch, str):
                    ch = ord(ch)

                if color != prev_color:
                    # only reset attr when the color did change
                    prev_color = color
                    attr = curses_color(color)

                offset += 1
                self.curses_putch(x + i, y + j, ch, attr)
            offset += self.w - buf.w

    def clear_screen(self):
        """clear the screen"""

        self.fillrect(0, 0, self.w, self.h, video_color(WHITE, BLACK))


class ColorSet:
    """collection of colors"""

    def __init__(self, fg=WHITE, bg=BLACK, bold=False):
        """initialize"""

        self.text = video_color(fg, bg, bold)
        self.border = self.text
        self.title = self.text
        self.cursor = reverse_video(self.text)
        self.status = self.text
        self.scrollbar = self.text
        self.shadow = video_color(BLACK, BLACK, True)

        # not all views use these, but set them anyway
        self.button = self.text
        self.buttonhotkey = self.text
        self.activebutton = self.text
        self.activebuttonhotkey = self.text

        self.menu = self.text
        self.menuhotkey = self.text
        self.activemenu = self.text
        self.activemenuhotkey = self.text

        self.prompt = self.text
        self.invisibles = self.text


class Window:
    """represents a window"""

    OPEN = 1
    SHOWN = 2
    FOCUS = 4

    def __init__(self, x, y, w, h, colors, title=None, border=True, shadow=True):
        """initialize"""

        self.frame = Rect(x, y, w, h)
        self.colors = colors
        self.title = title
        self.has_border = border
        self.has_shadow = shadow

        # bounds is the inner area; for view content
        if border:
            self.bounds = Rect(x + 1, y + 1, w - 2, h - 2)
        else:
            self.bounds = self.frame.copy()

        # rect is the outer area; larger because of shadow
        if self.has_shadow:
            self.rect = Rect(x, y, w + 2, h + 1)
        else:
            self.rect = self.frame.copy()

        self.background = None
        self.flags = 0

    def save_background(self):
        """save the background"""

        self.background = VIDEO.getrect(
            self.rect.x, self.rect.y, self.rect.w, self.rect.h
        )

    def restore_background(self):
        """restore the background"""

        VIDEO.putrect(self.rect.x, self.rect.y, self.background)

    def open(self):
        """open the window"""

        if self.flags & Window.OPEN:
            return

        self.flags |= Window.OPEN
        self.save_background()

    def close(self):
        """close the window"""

        if not self.flags & Window.OPEN:
            return

        self.hide()
        self.flags &= ~Window.OPEN

    def show(self):
        """open the window"""

        self.open()

        if self.flags & Window.SHOWN:
            return

        self.flags |= Window.SHOWN
        self.front()

    def hide(self):
        """hide the window"""

        if not self.flags & Window.SHOWN:
            return

        self.restore_background()
        self.flags &= ~(Window.SHOWN | Window.FOCUS)
        STACK.remove(self)
        # we have a new top-level window
        win = STACK.top()
        if win is not None:
            win.draw()
            win.gain_focus()

    def gain_focus(self):
        """event: we got focus"""

        self.flags |= Window.FOCUS
        self.draw_cursor()

    def lose_focus(self):
        """event: focus lost"""

        self.flags &= ~Window.FOCUS
        self.draw_cursor()

    def front(self):
        """bring window to front"""

        win = STACK.top()
        if win is not self:
            if win is not None:
                win.lose_focus()

            STACK.front(self)
            self.draw()
            self.gain_focus()

    def back(self):
        """bring window to back"""

        self.lose_focus()
        STACK.back(self)
        # we have a new top-level window
        win = STACK.top()
        if win is not None:
            win.draw()
            win.gain_focus()

    def resize_event(self):
        """the terminal was resized"""

        # override this method
        # This method should only change coordinates;
        # a redraw will be called automatically
        # pass

    def draw(self):
        """draw the window"""

        if not self.flags & Window.SHOWN:
            return

        if self.has_border:
            VIDEO.fillrect(
                self.frame.x + 1,
                self.frame.y + 1,
                self.frame.w - 2,
                self.frame.h - 2,
                self.colors.text,
            )
            VIDEO.border(
                self.frame.x,
                self.frame.y,
                self.frame.w,
                self.frame.h,
                self.colors.border,
            )
        else:
            VIDEO.fillrect(
                self.frame.x, self.frame.y, self.frame.w, self.frame.h, self.colors.text
            )

        # draw frame shadow
        self.draw_shadow()

        # draw title
        if self.title is not None:
            title = " " + self.title + " "
            x = (self.frame.w - len(title)) // 2
            VIDEO.puts(self.frame.x + x, self.frame.y, title, self.colors.title)

    def draw_shadow(self):
        """draw shadow for frame rect"""

        if not self.has_shadow:
            return

        if not self.flags & Window.SHOWN:
            return

        # right side shadow vlines
        VIDEO.color_vline(
            self.frame.x + self.frame.w,
            self.frame.y + 1,
            self.frame.h,
            self.colors.shadow,
        )
        VIDEO.color_vline(
            self.frame.x + self.frame.w + 1,
            self.frame.y + 1,
            self.frame.h,
            self.colors.shadow,
        )
        # bottom shadow hline
        VIDEO.color_hline(
            self.frame.x + 2,
            self.frame.y + self.frame.h,
            self.frame.w,
            self.colors.shadow,
        )

    def draw_cursor(self):
        """draw cursor"""

        # override this method

    #        if self.flags & Window.FOCUS:
    #            ...
    #        else:
    #            ...
    # pass

    def putch(self, x, y, ch, color=-1, alt=False):
        """put character in window"""

        if not self.bounds.clip_point(x, y):
            return

        if color == -1:
            color = self.colors.text

        VIDEO.putch(self.bounds.x + x, self.bounds.y + y, ch, color, alt)

    def puts(self, x, y, msg, color=-1, alt=False):
        """print message in window
        Does not clear to end of line
        """

        if not self.flags & Window.SHOWN:
            return

        # do window clipping
        visible, cx, cy, cw = self.bounds.clip_hline(x, y, len(msg))
        if not visible:
            return

        # clip message
        if x < 0:
            msg = msg[-x:]
            if not msg:
                return

        if len(msg) > cw:
            msg = msg[:cw]
            if not msg:
                return

        if color == -1:
            color = self.colors.text

        VIDEO.puts(self.bounds.x + cx, self.bounds.y + cy, msg, color, alt)

    def cputs(self, x, y, msg, color=-1, alt=False):
        """print message in window
        Clear to end of line
        """

        if not self.flags & Window.SHOWN:
            return

        # starts out the same as puts(), but then clears to EOL

        # do window clipping
        visible, cx, cy, cw = self.bounds.clip_hline(x, y, len(msg))
        if not visible:
            return

        # clip message
        if x < 0:
            msg = msg[-x:]

        if len(msg) > cw:
            msg = msg[:cw]

        if color == -1:
            color = self.colors.text

        if len(msg) > 0:
            VIDEO.puts(self.bounds.x + cx, self.bounds.y + cy, msg, color, alt)

        # clear to end of line
        l = len(msg)
        w_eol = self.bounds.w - l - cx
        if w_eol > 0:
            clear_eol = " " * w_eol
            VIDEO.puts(
                self.bounds.x + cx + l, self.bounds.y + cy, clear_eol, color, alt
            )

    def color_putch(self, x, y, color=-1, alt=False):
        """put color byte in window"""

        if not self.bounds.clip_point(x, y):
            return

        if color == -1:
            color = self.colors.text

        VIDEO.color_putch(self.bounds.x + x, self.bounds.y + y, color, alt)


class TextWindow(Window):
    """a window for displaying text"""

    def __init__(
        self,
        x,
        y,
        w,
        h,
        colors,
        title=None,
        border=True,
        text=None,
        tabsize=4,
        scrollbar=True,
        status=True,
    ):
        """initialize"""

        super().__init__(x, y, w, h, colors, title, border)
        if text is None:
            self.text = []
        else:
            self.text = text
        self.tabsize = tabsize

        self.top = 0
        self.cursor = 0
        self.xoffset = 0

        if status:
            self.status = ""
        else:
            self.status = None

        if scrollbar:
            self.scrollbar = True
            self.scrollbar_y = 0
            self.scrollbar_h = 0
            self.init_scrollbar()
        else:
            self.scrollbar = None

    def load(self, filename):
        """load text file
        Raises OSError on error
        """

        with open(filename) as f:
            self.text = f.readlines()

        # strip newlines
        self.text = [x.rstrip() for x in self.text]

        if self.title is not None:
            self.title = os.path.basename(filename)

        if self.scrollbar is not None:
            self.init_scrollbar()

        # do a full draw because we loaded new text
        self.draw()

    def draw(self):
        """draw the window"""

        if not self.flags & Window.SHOWN:
            return

        super().draw()
        self.draw_text()
        self.draw_scrollbar()
        self.draw_statusbar()

    def draw_text(self):
        """draws the text content"""

        y = 0
        while y < self.bounds.h:
            if y == self.cursor:
                # draw_cursor() will be called by Window.show()
                pass
            else:
                try:
                    self.printline(y)
                except IndexError:
                    break

            y += 1

    def draw_cursor(self):
        """redraw the cursor line"""

        if self.flags & Window.FOCUS:
            color = self.colors.cursor
            alt = True
        else:
            color = -1
            alt = False
        self.printline(self.cursor, color, alt)

        self.update_statusbar(
            " {},{} ".format(self.top + self.cursor + 1, self.xoffset + 1)
        )

    def clear_cursor(self):
        """erase the cursor"""

        self.printline(self.cursor)

    def printline(self, y, color=-1, alt=False):
        """print a single line"""

        try:
            line = self.text[self.top + y]
        except IndexError:
            # draw empty line
            self.cputs(0, y, "", color)
        else:
            # replace tabs by spaces
            # This is because curses will display them too big
            line = line.replace("\t", " " * self.tabsize)
            # take x-scrolling into account
            line = line[self.xoffset :]
            self.cputs(0, y, line, color, alt)

    def init_scrollbar(self):
        """initalize scrollbar"""

        if self.has_border and len(self.text) > 0:
            factor = float(self.bounds.h) // len(self.text)
            self.scrollbar_h = int(factor * self.bounds.h + 0.5)
            if self.scrollbar_h < 1:
                self.scrollbar_h = 1
            if self.scrollbar_h > self.bounds.h:
                self.scrollbar_h = self.bounds.h

    #            self.update_scrollbar()

    def update_scrollbar(self):
        """update scrollbar position"""

        if (
            self.scrollbar is None
            or not self.has_border
            or self.scrollbar_h <= 0
            or not self.text
        ):
            return

        old_y = self.scrollbar_y

        factor = float(self.bounds.h) // len(self.text)
        new_y = int((self.top + self.cursor) * factor + 0.5)
        if old_y != new_y:
            self.clear_scrollbar()
            self.scrollbar_y = new_y
            self.draw_scrollbar()

    def clear_scrollbar(self):
        """erase scrollbar"""

        if self.scrollbar is None or not self.has_border or self.scrollbar_h <= 0:
            return

        y = self.scrollbar_y - self.scrollbar_h // 2
        if y < 0:
            y = 0
        if y > self.bounds.h - self.scrollbar_h:
            y = self.bounds.h - self.scrollbar_h

        VIDEO.vline(
            self.frame.x + self.frame.w - 1,
            self.bounds.y + y,
            self.scrollbar_h,
            curses.ACS_VLINE,
            self.colors.border,
        )

    def draw_scrollbar(self):
        """draw scrollbar"""

        if self.scrollbar is None or not self.has_border or self.scrollbar_h <= 0:
            return

        y = self.scrollbar_y - self.scrollbar_h // 2
        if y < 0:
            y = 0
        if y > self.bounds.h - self.scrollbar_h:
            y = self.bounds.h - self.scrollbar_h

        VIDEO.vline(
            self.frame.x + self.frame.w - 1,
            self.bounds.y + y,
            self.scrollbar_h,
            curses.ACS_CKBOARD,
            self.colors.scrollbar,
        )

    def update_statusbar(self, msg):
        """update the statusbar"""

        if self.status is None or msg == self.status:
            return

        if len(msg) < len(self.status):
            # clear the statusbar
            w = len(self.status) - len(msg)
            x = self.bounds.w - 1 - len(self.status)
            if x < 0:
                x = 0
                w = self.bounds.w
            VIDEO.hline(
                self.bounds.x + x,
                self.frame.y + self.frame.h - 1,
                w,
                curses.ACS_HLINE,
                self.colors.border,
            )

        self.status = msg
        self.draw_statusbar()

    def draw_statusbar(self):
        """draw statusbar"""

        if self.status is None:
            return

        x = self.bounds.w - 1 - len(self.status)
        if x < 0:
            x = 0

        msg = self.status
        if len(msg) > self.bounds.w:
            msg = msg[self.bounds.w :]

        VIDEO.puts(
            self.bounds.x + x, self.bounds.y + self.bounds.h, msg, self.colors.status
        )

    def move_up(self):
        """move up"""

        if self.cursor > 0:
            self.clear_cursor()
            self.cursor -= 1
        else:
            self.scroll_up()

        self.update_scrollbar()
        self.draw_cursor()

    def move_down(self):
        """move down"""

        if not self.text or self.cursor >= len(self.text) - 1:
            return

        if self.cursor < self.bounds.h - 1:
            self.clear_cursor()
            self.cursor += 1
        else:
            self.scroll_down()

        self.update_scrollbar()
        self.draw_cursor()

    def move_left(self):
        """move left"""

        if self.xoffset > 0:
            self.xoffset -= 4
            if self.xoffset < 0:
                self.xoffset = 0
            self.draw_text()
        self.draw_cursor()

    def move_right(self):
        """move right"""

        max_xoffset = 500
        if self.xoffset < max_xoffset:
            self.xoffset += 4
            self.draw_text()
        self.draw_cursor()

    def scroll_up(self):
        """scroll up one line"""

        old_top = self.top
        self.top -= 1
        if self.top < 0:
            self.top = 0

        if self.top != old_top:
            self.draw_text()

    def scroll_down(self):
        """scroll down one line"""

        old_top = self.top
        self.top += 1
        if self.top > len(self.text) - self.bounds.h:
            self.top = len(self.text) - self.bounds.h
            if self.top < 0:
                self.top = 0

        if self.top != old_top:
            self.draw_text()

    def pageup(self):
        """scroll one page up"""

        old_top = self.top
        old_cursor = new_cursor = self.cursor

        if old_cursor == self.bounds.h - 1:
            new_cursor = 0
        else:
            self.top -= self.bounds.h - 1
            if self.top < 0:
                self.top = 0
                new_cursor = 0

        if self.top != old_top:
            self.cursor = new_cursor
            self.draw_text()
        elif old_cursor != new_cursor:
            self.clear_cursor()
            self.cursor = new_cursor

        self.update_scrollbar()
        self.draw_cursor()

    def pagedown(self):
        """scroll one page down"""

        old_top = self.top
        old_cursor = new_cursor = self.cursor

        if old_cursor == 0:
            new_cursor = self.bounds.h - 1
        else:
            self.top += self.bounds.h - 1
            if self.top > len(self.text) - self.bounds.h:
                self.top = len(self.text) - self.bounds.h
                if self.top < 0:
                    self.top = 0
                new_cursor = self.bounds.h - 1
                if new_cursor >= len(self.text):
                    new_cursor = len(self.text) - 1
                    if new_cursor < 0:
                        new_cursor = 0

        if self.top != old_top:
            self.cursor = new_cursor
            self.draw_text()
        elif old_cursor != new_cursor:
            self.clear_cursor()
            self.cursor = new_cursor

        self.update_scrollbar()
        self.draw_cursor()

    def goto_top(self):
        """go to top of document"""

        old_top = self.top
        old_cursor = new_cursor = self.cursor
        old_xoffset = self.xoffset

        self.top = self.xoffset = new_cursor = 0
        if old_top != self.top or old_xoffset != self.xoffset:
            self.cursor = new_cursor
            self.draw_text()
        elif old_cursor != new_cursor:
            self.clear_cursor()
            self.cursor = new_cursor

        self.update_scrollbar()
        self.draw_cursor()

    def goto_bottom(self):
        """go to bottom of document"""

        old_top = self.top
        old_cursor = new_cursor = self.cursor
        old_xoffset = self.xoffset

        self.top = len(self.text) - self.bounds.h
        if self.top < 0:
            self.top = 0

        new_cursor = self.bounds.h - 1
        if new_cursor >= len(self.text):
            new_cursor = len(self.text) - 1
            if new_cursor < 0:
                new_cursor = 0

        self.xoffset = 0

        if self.top != old_top or old_xoffset != self.xoffset:
            self.cursor = new_cursor
            self.draw_text()
        elif old_cursor != new_cursor:
            self.clear_cursor()
            self.cursor = new_cursor

        self.update_scrollbar()
        self.draw_cursor()

    def runloop(self):
        """run main input loop for this view
        Returns a new program state code
        """

        while True:
            key = getch()

            if key == KEY_ESC:
                self.lose_focus()
                return GOTO_MENUBAR

            if key == KEY_UP:
                self.move_up()

            elif key == KEY_DOWN:
                self.move_down()

            elif key == KEY_LEFT:
                self.move_left()

            elif key == KEY_RIGHT:
                self.move_right()

            elif (
                key == KEY_PAGEUP or key == "Ctrl-U"
            ):  # pylint: disable=consider-using-in
                self.pageup()

            elif (
                key == KEY_PAGEDOWN or key == "Ctrl-D"
            ):  # pylint: disable=consider-using-in
                self.pagedown()

            elif key == KEY_HOME:
                self.goto_top()

            elif key == KEY_END:
                self.goto_bottom()


class Widget:
    """represents a widget"""

    def __init__(self, parent, x, y, colors):
        """initialize"""

        self.parent = parent
        self.x = x
        self.y = y
        self.colors = colors
        self.has_focus = False

    def draw(self):
        """draw widget"""

        # override this method

    def gain_focus(self):
        """we get focus"""

        self.has_focus = True
        self.draw_cursor()

    def lose_focus(self):
        """we lose focus"""

        self.has_focus = False
        self.draw_cursor()

    def draw_cursor(self):
        """draw cursor"""

        # override this method


class Button(Widget):
    """represents a button"""

    def __init__(self, parent, x, y, colors, label):
        """initialize"""

        assert label is not None

        super().__init__(parent, x, y, colors)

        self.hotkey, self.hotkey_pos, self.label = label_hotkey(label)

        self.pushing = False

    def draw(self):
        """draw button"""

        self.draw_cursor()

    def draw_cursor(self):
        """draw button"""

        # the cursor _is_ the button
        # and the button is the cursor

        add = 1
        text = " " + self.label + " "
        if len(text) <= 5:
            # minimum width is 7
            text = " " + text + " "
            add += 1

        if self.has_focus:
            text = ">" + text + "<"
            color = self.colors.activebutton
            alt = True
        else:
            if not HAS_COLORS:
                text = "[" + text + "]"
            else:
                text = " " + text + " "
            color = self.colors.button
            alt = False
        add += 1

        xpos = self.x
        if self.pushing:
            # clear on left side
            self.parent.puts(xpos, self.y, " ")
            xpos += 1
        else:
            # clear on right side
            self.parent.puts(xpos + button_width(self.label), self.y, " ")

        self.parent.puts(xpos, self.y, text, color, alt)

        if self.hotkey_pos > -1:
            # draw hotkey
            if self.has_focus:
                color = self.colors.activebuttonhotkey
            else:
                color = self.colors.buttonhotkey

            self.parent.puts(
                xpos + self.hotkey_pos + add, self.y, self.hotkey, color, alt
            )

    def push(self):
        """push the button"""

        assert self.has_focus

        # animate button
        self.pushing = True
        self.draw()
        STDSCR.refresh()
        curses.doupdate()
        time.sleep(0.1)

        self.pushing = False
        self.draw()
        STDSCR.refresh()
        curses.doupdate()
        time.sleep(0.1)


class Alert(Window):
    """an alert box with buttons"""

    def __init__(
        self, colors, title, msg, buttons=None, default=0, border=True, center_text=True
    ):
        """initialize"""

        # determine width and height
        w = 0
        lines = msg.split("\n")
        for line in lines:
            if len(line) > w:
                w = len(line)
        w += 2
        if buttons is not None:
            bw = 0
            for label in buttons:
                bw += button_width(label) + 2
            bw += 2
            if bw > w:
                w = bw

        h = len(lines) + 4
        if border:
            w += 2
            h += 2

        if w > VIDEO.w:
            w = VIDEO.w

        # center the box
        x = center_x(w)
        y = center_y(h)

        super().__init__(x, y, w, h, colors, title, border)

        self.text = lines
        self.center_text = center_text

        # y position of the button bar
        y = self.bounds.h - 2
        assert y > 0

        self.hotkeys = []

        if buttons is None:
            # one OK button: center it
            label = "<O>K"
            x = center_x(button_width(label), self.bounds.w)
            self.buttons = [
                Button(self, x, y, self.colors, label),
            ]
        else:
            # make and position button widgets
            self.buttons = []

            # determine spacing
            total_len = 0
            for label in buttons:
                total_len += button_width(label)

            # spacing is a floating point number
            # but the button will have an integer position
            spacing = (self.bounds.w - total_len) / (len(buttons) + 1.0)
            if spacing < 1.0:
                spacing = 1.0

            x = spacing
            for label in buttons:
                button = Button(self, int(x), y, self.colors, label)
                self.buttons.append(button)
                x += spacing + button_width(label)

                # save hotkey
                hotkey, _, _ = label_hotkey(label)
                self.hotkeys.append(hotkey)

        assert 0 <= default < len(self.buttons)
        self.cursor = self.default = default

    def resize_event(self):
        """the terminal was resized"""

        w = self.frame.w
        h = self.frame.h
        x = center_x(w, VIDEO.w)
        y = center_y(h, VIDEO.h)

        self.frame = Rect(x, y, w, h)

        # bounds is the inner area; for view content
        if self.has_border:
            self.bounds = Rect(x + 1, y + 1, w - 2, h - 2)
        else:
            self.bounds = self.frame.copy()

        # rect is the outer area; larger because of shadow
        if self.has_shadow:
            self.rect = Rect(x, y, w + 2, h + 1)
        else:
            self.rect = self.frame.copy()

    def draw(self):
        """draw the alert box"""

        super().draw()

        # draw the text
        y = 1
        for line in self.text:
            if self.center_text:
                x = center_x(len(line), self.bounds.w)
            else:
                x = 1
            self.cputs(x, y, line)
            y += 1

        # draw buttons
        self.draw_buttons()

    def draw_buttons(self):
        """draw the buttons"""

        for button in self.buttons:
            button.draw()

    def move_right(self):
        """select button to the right"""

        if len(self.buttons) <= 1:
            return

        self.buttons[self.cursor].lose_focus()
        self.cursor += 1
        if self.cursor >= len(self.buttons):
            self.cursor = 0
        self.buttons[self.cursor].gain_focus()

    def move_left(self):
        """select button to the left"""

        if len(self.buttons) <= 1:
            return

        self.buttons[self.cursor].lose_focus()
        self.cursor -= 1
        if self.cursor < 0:
            self.cursor = len(self.buttons) - 1
        self.buttons[self.cursor].gain_focus()

    def push(self):
        """push selected button"""

        self.buttons[self.cursor].push()

    def push_hotkey(self, key):
        """push hotkey
        Returns True if key indeed pushed a button
        """

        if not self.hotkeys:
            return False

        if len(key) == 1:
            key = key.upper()

        idx = 0
        for hotkey in self.hotkeys:
            if hotkey == key:
                if self.cursor != idx:
                    self.buttons[self.cursor].lose_focus()
                    self.cursor = idx
                    self.buttons[self.cursor].gain_focus()

                self.push()
                return True

            idx += 1

        return False

    def runloop(self):
        """run the alert dialog
        Returns button choice or -1 on escape
        """

        # always open with the default button active
        self.cursor = self.default
        self.buttons[self.cursor].gain_focus()

        while True:
            key = getch()

            if key == KEY_ESC:
                self.close()
                return RETURN_TO_PREVIOUS

            if key == KEY_LEFT or key == KEY_BTAB:  # pylint: disable=consider-using-in
                self.move_left()

            elif (
                key == KEY_RIGHT or key == KEY_TAB
            ):  # pylint: disable=consider-using-in
                self.move_right()

            elif key == KEY_RETURN or key == " ":  # pylint: disable=consider-using-in
                self.push()
                self.close()
                return self.cursor

            elif self.push_hotkey(key):
                self.close()
                return self.cursor


class MenuItem:
    """a single menu item"""

    def __init__(self, label):
        """initialize"""

        self.hotkey, self.hotkey_pos, self.text = label_hotkey(label)


class Menu(Window):
    """a (dropdown) menu"""

    def __init__(self, x, y, colors, border=True, items=None, closekey=None):
        """initialize"""

        # should really have a list of items
        assert items is not None

        # determine width and height
        w = 0
        for item in items:
            l = label_length(item) + 2
            if border:
                l += 2
            if l > w:
                w = l
        h = len(items)
        if border:
            h += 2

        super().__init__(x, y, w, h, colors, None, border)

        # make list of MenuItems
        self.items = [MenuItem(item) for item in items]
        self.closekey = closekey
        self.cursor = 0

    def draw(self):
        """draw the window"""

        super().draw()
        self.draw_items()

    def draw_items(self):
        """draw the items"""

        y = 0
        for item in self.items:
            if y == self.cursor:
                # draw_cursor() will be called by Window.show()
                pass
            else:
                # normal entry
                if item.text == "--":
                    # separator line
                    VIDEO.hsplit(
                        self.frame.x,
                        self.bounds.y + y,
                        self.frame.w,
                        curses.ACS_HLINE,
                        self.colors.border,
                    )
                else:
                    self.cputs(1, y, item.text, self.colors.menu)
                    if item.hotkey is not None:
                        # draw hotkey
                        self.putch(
                            1 + item.hotkey_pos, y, item.hotkey, self.colors.menuhotkey
                        )
            y += 1

    def draw_cursor(self):
        """draw highlighted cursor line"""

        if self.flags & Window.FOCUS:
            attr = self.colors.activemenu
            attr_hotkey = self.colors.activemenuhotkey
        else:
            attr = self.colors.menu
            attr_hotkey = self.colors.menuhotkey

        item = self.items[self.cursor]
        self.cputs(0, self.cursor, " " + item.text, attr, alt=True)
        if item.hotkey is not None:
            # draw hotkey
            self.putch(
                1 + item.hotkey_pos, self.cursor, item.hotkey, attr_hotkey, alt=True
            )

    def clear_cursor(self):
        """erase the cursor"""

        item = self.items[self.cursor]
        self.cputs(0, self.cursor, " " + item.text, self.colors.menu)
        if item.hotkey is not None:
            # draw hotkey
            self.putch(
                1 + item.hotkey_pos, self.cursor, item.hotkey, self.colors.menuhotkey
            )

    def selection(self):
        """Returns plaintext of currently selected item"""

        item = self.items[self.cursor]
        return item.text

    def move_up(self):
        """move up"""

        self.clear_cursor()
        self.cursor -= 1
        if self.cursor < 0:
            self.cursor += len(self.items)

        if self.items[self.cursor].text == "--":
            # skip over separator line
            self.cursor -= 1
            assert self.cursor >= 0
            assert self.items[self.cursor].text != "--"

        self.draw_cursor()

    def move_down(self):
        """move down"""

        self.clear_cursor()
        self.cursor += 1
        if self.cursor >= len(self.items):
            self.cursor = 0

        if self.items[self.cursor].text == "--":
            # skip over separator line
            self.cursor += 1
            assert self.cursor < len(self.items)
            assert self.items[self.cursor].text != "--"

        self.draw_cursor()

    def goto_top(self):
        """go to top of menu"""

        if self.cursor == 0:
            return

        self.clear_cursor()
        self.cursor = 0
        self.draw_cursor()

    def goto_bottom(self):
        """go to bottom of menu"""

        if self.cursor >= len(self.items) - 1:
            return

        self.clear_cursor()
        self.cursor = len(self.items) - 1
        self.draw_cursor()

    def push_hotkey(self, key):
        """Returns True if the hotkey was pressed"""

        key = key.upper()
        y = 0
        for item in self.items:
            if item.hotkey == key:
                if self.cursor != y:
                    self.clear_cursor()
                    self.cursor = y
                    self.draw_cursor()
                    # give visual feedback
                    STDSCR.refresh()
                    curses.doupdate()
                    time.sleep(0.1)

                return True

            y += 1

        return False

    def runloop(self):
        """run a menu"""

        self.show()

        while True:
            key = getch()

            if key == KEY_ESC:
                self.close()
                return RETURN_TO_PREVIOUS

            if key == self.closekey or key.upper() == self.closekey:
                self.close()
                return MENU_CLOSE

            if key == KEY_LEFT or key == KEY_BTAB:  # pylint: disable=consider-using-in
                self.close()
                return MENU_LEFT

            if key == KEY_RIGHT or key == KEY_TAB:  # pylint: disable=consider-using-in
                self.close()
                return MENU_RIGHT

            if key == KEY_UP:
                self.move_up()

            elif key == KEY_DOWN:
                self.move_down()

            elif (
                key == KEY_PAGEUP or key == KEY_HOME
            ):  # pylint: disable=consider-using-in
                self.goto_top()

            elif (
                key == KEY_PAGEDOWN or key == KEY_END
            ):  # pylint: disable=consider-using-in
                self.goto_bottom()

            elif key == KEY_RETURN or key == " ":  # pylint: disable=consider-using-in
                self.close()
                return self.cursor

            elif self.push_hotkey(key):
                self.close()
                return self.cursor


class MenuBar(Window):
    """represents a menu bar"""

    def __init__(self, colors, menus, border=True):
        """initialize
        menus is a list of tuples: ('header', ['item #1', 'item #2', 'etc.'])
        """

        super().__init__(0, 0, VIDEO.w, 1, colors, border=False)

        # make list of headers and menus
        self.headers = [MenuItem(m[0]) for m in menus]

        # make list of x positions for each header
        self.pos = []
        x = 2
        for header in self.headers:
            self.pos.append(x)
            x += len(header.text) + 2

        self.cursor = 0

        # make list of menus
        self.menus = []
        x = 0
        for m in menus:
            items = m[1]
            menu = Menu(
                self.pos[x] - 1,
                self.frame.y + 1,
                colors,
                border,
                items,
                self.headers[x].hotkey,
            )
            self.menus.append(menu)
            x += 1

        # last chosen menu entry
        self.choice = -1

    def resize_event(self):
        """the terminal was resized"""

        self.frame.w = self.bounds.w = self.rect.w = VIDEO.w

    def draw(self):
        """draw menu bar"""

        VIDEO.hline(0, 0, VIDEO.w, " ", self.colors.menu)
        x = 0
        for header in self.headers:
            if x == self.cursor:
                # cursor will be drawn via Window.show()
                pass
            else:
                self.puts(self.pos[x], 0, header.text, self.colors.menu)
                if header.hotkey is not None:
                    # draw hotkey
                    self.putch(
                        self.pos[x] + header.hotkey_pos,
                        0,
                        header.hotkey,
                        self.colors.menuhotkey,
                    )
            x += 1

    def draw_cursor(self):
        """draw the cursor (highlighted when in focus)"""

        if self.flags & Window.FOCUS:
            color = self.colors.activemenu
            color_hotkey = self.colors.activemenuhotkey
            alt = True
        else:
            color = self.colors.menu
            color_hotkey = self.colors.menuhotkey
            alt = False

        header = self.headers[self.cursor]
        self.puts(self.pos[self.cursor] - 1, 0, " " + header.text + " ", color, alt)
        if header.hotkey is not None:
            # draw hotkey
            self.putch(
                self.pos[self.cursor] + header.hotkey_pos,
                0,
                header.hotkey,
                color_hotkey,
                alt,
            )

    def clear_cursor(self):
        """erase cursor"""

        color = self.colors.menu
        color_hotkey = self.colors.menuhotkey

        header = self.headers[self.cursor]
        self.puts(self.pos[self.cursor] - 1, 0, " " + header.text + " ", color)
        if header.hotkey is not None:
            # draw hotkey
            self.putch(
                self.pos[self.cursor] + header.hotkey_pos,
                0,
                header.hotkey,
                color_hotkey,
            )

    def selection(self):
        """Returns plaintext of selected item, or None if none"""

        if self.choice == -1:
            return None

        menu = self.menus[self.cursor]
        return menu.items[self.choice].text

    def position(self):
        """Returns tuple: (header index, item index)
        If item index == -1, no choice was made
        """

        return self.cursor, self.choice

    def move_left(self):
        """move left"""

        self.clear_cursor()
        self.cursor -= 1
        if self.cursor < 0:
            self.cursor += len(self.headers)
        self.draw_cursor()

    def move_right(self):
        """move right"""

        self.clear_cursor()
        self.cursor += 1
        if self.cursor >= len(self.headers):
            self.cursor = 0
        self.draw_cursor()

    def push_hotkey(self, key):
        """Returns True if the hotkey was pressed"""

        key = key.upper()
        x = 0
        for header in self.headers:
            if header.hotkey == key:
                if self.cursor != x:
                    self.clear_cursor()
                    self.cursor = x
                    self.draw_cursor()
                    # give visual feedback
                    STDSCR.refresh()
                    curses.doupdate()
                    time.sleep(0.1)

                return True

            x += 1

        return False

    def runloop(self):
        """run the menu bar"""

        while True:
            key = getch()

            if key == KEY_ESC:
                self.choice = RETURN_TO_PREVIOUS
                self.back()
                return RETURN_TO_PREVIOUS

            if key == KEY_LEFT:
                self.move_left()

            elif key == KEY_RIGHT:
                self.move_right()

            elif (
                key == KEY_RETURN
                or key == " "
                or key == KEY_DOWN
                or self.push_hotkey(key)
            ):
                # activate the menu
                while True:
                    self.menus[self.cursor].show()

                    # showing the menu makes the menubar lose focus
                    # redraw the menubar cursor however
                    # so the menubar cursor stays active
                    # while the menu is open
                    self.flags |= Window.FOCUS
                    self.draw_cursor()

                    choice = self.menus[self.cursor].runloop()
                    if choice == RETURN_TO_PREVIOUS:
                        # escape: closed menu
                        self.choice = RETURN_TO_PREVIOUS
                        self.back()
                        return RETURN_TO_PREVIOUS

                    if choice == MENU_CLOSE:
                        # close menu; return to menubar
                        break

                    if choice == MENU_LEFT:
                        # navigate left and open menu
                        self.move_left()

                    elif choice == MENU_RIGHT:
                        # navigate right and open menu
                        self.move_right()

                    else:
                        self.back()
                        self.choice = choice
                        return choice


class TextField(Widget):
    """single line of text input"""

    MAX_HISTORY = 50

    def __init__(self, parent, x, y, w, colors, history=True, inputfilter=None):
        """initialize"""

        super().__init__(parent, x, y, colors)

        self.w = w
        self.text = ""
        self.cursor = 0
        if history:
            self.history = []
            self.history_cursor = 0
        else:
            self.history = None
        self.inputfilter = inputfilter

    def draw(self):
        """draw the TextField"""

        w = len(self.text)
        VIDEO.puts(self.x, self.y, self.text, self.colors.text)
        # clear to EOL
        VIDEO.hline(self.x + w, self.y, self.w - w, " ", self.colors.text)

        self.draw_cursor()

    def draw_cursor(self):
        """draw the cursor"""

        if self.has_focus:
            # draw cursor
            if self.cursor < len(self.text):
                ch = self.text[self.cursor]
            else:
                ch = " "
            VIDEO.putch(self.x + self.cursor, self.y, ch, self.colors.cursor, alt=True)

    def clear(self):
        """clears the TextField onscreen (not the TextField content)"""

        VIDEO.hline(self.x, self.y, self.w, " ", self.colors.text)

    def add_history(self):
        """add entered text to history"""

        if self.history is None or not self.text:
            return

        try:
            idx = self.history.index(self.text)
        except ValueError:
            # not yet in history
            self.history.append(self.text)

            if len(self.history) > TextField.MAX_HISTORY:
                # discard oldest entry
                self.history.pop(0)

        else:
            # make most recent item
            self.history.pop(idx)
            self.history.append(self.text)

        self.history_cursor = 0

    def recall_up(self):
        """go back in history"""

        if self.history is None or not self.history:
            return

        self.history_cursor -= 1
        if self.history_cursor < 0:
            self.history_cursor = len(self.history) - 1

        self.text = self.history[self.history_cursor]
        self.cursor = len(self.text)

        self.draw()
        self.draw_cursor()

    def recall_down(self):
        """go forward in history"""

        if (
            self.history is None
            or self.history_cursor >= len(self.history)
            or not self.history
        ):
            return

        if self.history_cursor < len(self.history):
            self.history_cursor += 1

        if self.history_cursor < len(self.history):
            self.text = self.history[self.history_cursor]
        else:
            self.text = ""

        self.cursor = len(self.text)

        self.draw()
        self.draw_cursor()

    def runloop(self):
        """run the TextField"""

        # reset the text
        self.text = ""
        self.cursor = 0
        self.draw()

        self.gain_focus()

        while True:
            key = getch()

            if key == KEY_ESC:
                self.text = ""
                self.cursor = 0
                self.lose_focus()
                self.clear()
                return RETURN_TO_PREVIOUS

            if key == KEY_BTAB:
                self.lose_focus()
                self.clear()
                return BACK

            if key == KEY_TAB:
                self.lose_focus()
                self.clear()
                return NEXT

            if key == KEY_RETURN:
                self.add_history()
                self.lose_focus()
                self.clear()
                return ENTER

            if key == KEY_BS:
                if self.cursor > 0:
                    self.text = self.text[: self.cursor - 1] + self.text[self.cursor :]
                    self.cursor -= 1
                    self.draw()

            elif key == KEY_DEL:
                if self.cursor < len(self.text):
                    self.text = self.text[: self.cursor] + self.text[self.cursor + 1 :]
                    self.draw()

            elif key == KEY_LEFT:
                if self.cursor > 0:
                    self.cursor -= 1
                    self.draw()

            elif key == KEY_RIGHT:
                if self.cursor < len(self.text):
                    self.cursor += 1
                    self.draw()

            elif key == KEY_HOME:
                if self.cursor > 0:
                    self.cursor = 0
                    self.draw()

            elif key == KEY_END:
                if self.cursor != len(self.text):
                    self.cursor = len(self.text)
                    self.draw()

            elif key == KEY_UP:
                self.recall_up()

            elif key == KEY_DOWN:
                self.recall_down()

            elif len(key) == 1 and len(self.text) < self.w:
                if self.inputfilter is not None:
                    ch = self.inputfilter(key)
                else:
                    ch = self.default_inputfilter(key)

                if ch is not None:
                    self.text = self.text[: self.cursor] + ch + self.text[self.cursor :]
                    self.cursor += 1
                    self.draw()

    def default_inputfilter(self, key):
        """Returns key if valid input
        or None if invalid
        """

        val = ord(key)
        if ord(" ") <= val <= ord("~"):
            return key

        return None


class CmdLine(Window):
    """command line: single line with prompt"""

    def __init__(self, x, y, w, colors, prompt=None):
        """initialize"""

        super().__init__(x, y, w, 1, colors, title=None, border=False)
        x = self.bounds.x
        w = self.bounds.w
        self.prompt = prompt
        if self.prompt is not None:
            x += len(self.prompt)
            w -= len(self.prompt)
            if w < 1:
                w = 1

        self.textfield = TextField(self, x, self.bounds.y, w, colors)

    def draw(self):
        """draw the command line"""

        if self.prompt is not None:
            self.puts(0, 0, self.prompt, self.colors.prompt)

        self.textfield.draw()

    def draw_cursor(self):
        """draw the cursor"""

        self.textfield.draw_cursor()

    def runloop(self):
        """run the command line window"""

        ret = self.textfield.runloop()
        self.close()
        return ret


class WindowStack:
    """represents a stack of Windows"""

    def __init__(self):
        """initialize"""

        self.stack = []

    def remove(self, win):
        """Remove window from stack"""

        assert isinstance(win, Window)
        try:
            self.stack.remove(win)
        except ValueError:
            # win was not on stack
            pass

    def front(self, win):
        """Move window to front"""

        self.remove(win)
        self.stack.append(win)

    def back(self, win):
        """Move window back"""

        self.remove(win)
        self.stack.insert(0, win)

    def top(self):
        """Returns the top of stack"""

        if not self.stack:
            return None

        return self.stack[-1]


def video_color(fg, bg=None, bold=False):
    """Returns combined (ScreenBuf) color code"""

    if bg is None:
        # passed in only a combined color code
        return fg

    assert 0 <= fg < BOLD
    assert 0 <= bg < BOLD

    if bold:
        return (bg << 4) | BOLD | fg

    return (bg << 4) | fg


def reverse_video(color):
    """Returns reverse of combined color code"""

    bg = color >> 4
    fg = color & 7
    # in general looks nicer without bold
    #    bold = color & BOLD
    return (fg << 4) | bg


def curses_color(fg, bg=None, bold=False, alt=False):
    """Returns curses colorpair index"""

    global CURSES_COLORPAIR_IDX

    if not HAS_COLORS:
        if alt:
            return curses.A_REVERSE
        return 0

    if bg is None:
        # passed in only a combined color code
        color = fg
        fg = color & 7
        bg = color >> 4
        bold = (color & BOLD) == BOLD

    assert 0 <= fg < BOLD
    assert 0 <= bg < BOLD

    idx = "{:02x}".format((bg << 4) | fg)
    if idx not in CURSES_COLORPAIRS:
        # make new curses color pair
        assert 0 <= CURSES_COLORPAIR_IDX < curses.COLOR_PAIRS - 1
        CURSES_COLORPAIR_IDX += 1
        fg = CURSES_COLORS[fg]
        bg = CURSES_COLORS[bg]
        curses.init_pair(CURSES_COLORPAIR_IDX, fg, bg)
        CURSES_COLORPAIRS[idx] = CURSES_COLORPAIR_IDX

    color = curses.color_pair(CURSES_COLORPAIRS[idx])
    if bold:
        return color | curses.A_BOLD
    # else
    return color


def label_hotkey(label):
    """Returns triple: (hotkey, hotkey position, plaintext) of the label
    or None if there is none

    Mind that hotkeys are uppercase, or may also be "Ctrl-key"
    """

    m = REGEX_HOTKEY.match(label)
    if m is None:
        return (None, -1, label)

    hotkey = m.groups()[0]
    if len(hotkey) == 1:
        hotkey = hotkey.upper()

    hotkey_pos = label.find("<")
    if hotkey_pos > -1:
        # strip out hooks
        plaintext = label.replace("<", "").replace(">", "")
    else:
        plaintext = label

    return (hotkey, hotkey_pos, plaintext)


def label_length(label):
    """Returns visual label length"""

    m = REGEX_HOTKEY.match(label)
    if m is None:
        return len(label)
    # else
    return len(label) - 2


def button_width(label):
    """Returns visual size of a button"""

    if isinstance(label, Button):
        label = label.label

    assert isinstance(label, str)

    w = label_length(label)
    if w <= 3:
        w += 2
    return w + 4


def center_x(width, area=0):
    """Return centered x coordinate
    If area is not given, center on screen
    """

    if area == 0:
        area = VIDEO.w

    x = (area - width) * 0.5

    # round up for funny looking non-centered objects
    return int(x + 0.5)


def center_y(height, area=0):
    """Return centered y coordinate
    If area is not given, put it in top half of screen
    """

    if area == 0:
        y = (VIDEO.h - height) * 0.35
    else:
        y = (area - height) * 0.5

    return int(y + 0.5)


def linemode(mode):
    """set linemode"""

    global LINEMODE, CURSES_LINES

    if CURSES_LINES is None:
        # save original curses line characters
        CURSES_LINES = (
            curses.ACS_HLINE,
            curses.ACS_VLINE,
            curses.ACS_ULCORNER,
            curses.ACS_URCORNER,
            curses.ACS_LLCORNER,
            curses.ACS_LRCORNER,
            curses.ACS_LTEE,
            curses.ACS_RTEE,
            curses.ACS_TTEE,
            curses.ACS_BTEE,
        )
    else:
        # restore original curses line characters
        curses.ACS_HLINE = CURSES_LINES[0]
        curses.ACS_VLINE = CURSES_LINES[1]
        curses.ACS_ULCORNER = CURSES_LINES[2]
        curses.ACS_URCORNER = CURSES_LINES[3]
        curses.ACS_LLCORNER = CURSES_LINES[4]
        curses.ACS_LRCORNER = CURSES_LINES[5]
        curses.ACS_LTEE = CURSES_LINES[6]
        curses.ACS_RTEE = CURSES_LINES[7]
        curses.ACS_TTEE = CURSES_LINES[8]
        curses.ACS_BTEE = CURSES_LINES[9]

    LINEMODE = mode

    # redefine character set
    if LINEMODE & LM_ASCII:
        curses.ACS_HLINE = ord("-")
        curses.ACS_VLINE = ord("|")
        curses.ACS_ULCORNER = ord("+")
        curses.ACS_URCORNER = ord("+")
        curses.ACS_LLCORNER = ord("+")
        curses.ACS_LRCORNER = ord("+")
        curses.ACS_LTEE = ord("+")
        curses.ACS_RTEE = ord("+")
        curses.ACS_TTEE = ord("+")
        curses.ACS_BTEE = ord("+")

    if not LINEMODE & LM_VLINE:
        curses.ACS_VLINE = ord(" ")
        curses.ACS_ULCORNER = curses.ACS_HLINE
        curses.ACS_URCORNER = curses.ACS_HLINE
        curses.ACS_LLCORNER = curses.ACS_HLINE
        curses.ACS_LRCORNER = curses.ACS_HLINE
        curses.ACS_LTEE = curses.ACS_HLINE
        curses.ACS_RTEE = curses.ACS_HLINE
        curses.ACS_TTEE = curses.ACS_HLINE
        curses.ACS_BTEE = curses.ACS_HLINE

    if not LINEMODE & LM_HLINE:
        curses.ACS_HLINE = ord(" ")
        curses.ACS_ULCORNER = curses.ACS_VLINE
        curses.ACS_URCORNER = curses.ACS_VLINE
        curses.ACS_LLCORNER = curses.ACS_VLINE
        curses.ACS_LRCORNER = curses.ACS_VLINE
        curses.ACS_LTEE = curses.ACS_VLINE
        curses.ACS_RTEE = curses.ACS_VLINE
        curses.ACS_TTEE = curses.ACS_VLINE
        curses.ACS_BTEE = curses.ACS_VLINE


def init_curses():
    """initialize curses"""

    global STDSCR, CURSES_COLORS, HAS_COLORS

    os.environ["ESCDELAY"] = "25"

    STDSCR = curses.initscr()
    curses.savetty()

    if WANT_COLORS:
        HAS_COLORS = curses.has_colors()
    else:
        HAS_COLORS = False

    if HAS_COLORS:
        curses.start_color()

    curses.noecho()
    STDSCR.keypad(1)
    curses.raw()

    # disable cursor
    # may fail on some kind of terminal
    try:
        curses.curs_set(0)
    except curses.error:
        pass

    curses.nonl()
    curses.noqiflush()

    # do not scroll the screen, ever
    # even though these settings seem to have no effect (?)
    STDSCR.scrollok(False)
    STDSCR.idlok(False)
    STDSCR.idcok(False)

    # init colors in same order as the color 'enums'
    # Sadly, curses.CODES do not exist until initscr() is done
    CURSES_COLORS = (
        curses.COLOR_BLACK,
        curses.COLOR_BLUE,
        curses.COLOR_GREEN,
        curses.COLOR_CYAN,
        curses.COLOR_RED,
        curses.COLOR_MAGENTA,
        curses.COLOR_YELLOW,
        curses.COLOR_WHITE,
    )

    # odd ... screen must be refreshed at least once,
    # or things won't work as expected
    STDSCR.refresh()


def terminate():
    """end the curses window mode"""

    if STDSCR is not None:
        # enable cursor
        # may fail on some kind of terminal
        try:
            curses.curs_set(1)
        except curses.error:
            pass

        # set cursor at bottom of screen
        STDSCR.move(VIDEO.h - 1, 0)

        curses.nocbreak()
        STDSCR.keypad(0)
        curses.echo()
        curses.resetty()
        curses.endwin()

    print()
    dump_debug()

    sys.stdout.flush()
    sys.stderr.flush()


def redraw_screen():
    """redraw the entire screen"""

    VIDEO.clear_screen()

    for win in STACK.stack:
        if not win.flags & Window.SHOWN:
            continue

        win.draw()
        win.draw_cursor()

    STDSCR.refresh()
    curses.doupdate()


def resize_event():
    """the terminal was resized"""

    global VIDEO

    # start over
    VIDEO = Video()
    VIDEO.clear_screen()

    for win in STACK.stack:
        win.resize_event()
        win.save_background()

        if not win.flags & Window.SHOWN:
            continue

        win.draw()
        win.draw_cursor()

    redraw_screen()


def getch():
    """get keyboard input
    Returns key as a string value
    """

    # move cursor to bottom right corner
    STDSCR.move(VIDEO.h - 1, VIDEO.w - 1)
    #    STDSCR.leaveok(0)      # leaveok() doesn't work; broken?

    # update the screen
    curses.doupdate()

    # __MODIFY__
    STDSCR.timeout(0)
    while True:

        key = STDSCR.getch()

        ## DEBUG
        if key == 17:
            # Ctrl-Q is hardwired to bail out
            terminate()
            sys.exit(0)

        elif key == 18:
            # Ctrl-R redraws the screen
            redraw_screen()

        elif key == curses.KEY_RESIZE:
            # terminal was resized
            resize_event()

        else:
            # got a user key
            break

    if ord(" ") <= key <= ord("~"):
        # ascii keys are returned as string
        return chr(key)

    skey = "0x{:02x}".format(key)
    if skey in KEY_TABLE:
        return KEY_TABLE[skey]

    if 1 <= key <= 26:
        # Ctrl-A to Ctrl-Z
        return "Ctrl-" + chr(ord("@") + key)

    return skey


def init():
    """initialize module"""

    global VIDEO, STACK

    VIDEO = Video()
    STACK = WindowStack()


def unit_test():
    """test this module"""

    init()

    pinky = VIDEO.set_color(YELLOW, MAGENTA)
    VIDEO.set_color(YELLOW, GREEN)

    x = VIDEO.w // 2 - 1
    y = VIDEO.h // 2

    VIDEO.putch(x, y, "W")
    VIDEO.putch(x + 1, y, "J", pinky)

    menu_colors = ColorSet(BLACK, WHITE)
    menu_colors.menuhotkey = video_color(RED, WHITE)
    menu_colors.activemenu = video_color(BLACK, GREEN)
    menu_colors.activemenuhotkey = video_color(RED, GREEN)

    menubar = MenuBar(
        menu_colors,
        [
            ("<=>", ["<A>bout", "--", "<Q>uit      Ctrl-Q"]),
            (
                "<F>ile",
                [
                    "<N>ew       Ctrl-N",
                    "<L>oad      Ctrl-L",
                    "<S>ave      Ctrl-S",
                    "--",
                    "<P>rint     Ctrl-P",
                ],
            ),
            (
                "<E>dit",
                [
                    "<U>ndo      Ctrl-Z",
                    "Cut       Ctrl-X",
                    "<C>opy      Ctrl-C",
                    "<P>aste     Ctrl-V",
                    "--",
                    "<F>ind      Ctrl-F",
                    "<R>eplace   Ctrl-G",
                ],
            ),
            ("<O>ptions", ["Option <1>", "Option <2>", "Option <3>"]),
            (
                "<W>indow",
                ["<M>inimize", "<Z>oom", "<C>ycle through windows", "Bring to <F>ront"],
            ),
            ("<H>elp", ["<I>ntroduction", "<S>earch", "<O>nline help"]),
        ],
    )
    menubar.show()

    bgcolors = ColorSet(YELLOW, RED, True)
    bgwin = Window(15, 6, 50, 16, bgcolors, title="Back")
    bgwin.show()
    bgwin.puts(0, 0, "This is the back window")

    wincolors = ColorSet(WHITE, BLUE, True)
    wincolors.border = video_color(CYAN, BLUE, True)
    wincolors.title = video_color(YELLOW, BLUE, True)
    wincolors.cursor = video_color(WHITE, BLACK, True)
    wincolors.status = video_color(BLACK, WHITE, False)
    wincolors.scrollbar = wincolors.border

    win = TextWindow(0, 1, 60, 20, wincolors, title="Hello")
    win.load("textmode.py")
    win.show()

    alert_colors = ColorSet(BLACK, WHITE)
    alert_colors.title = video_color(RED, WHITE)
    alert_colors.button = video_color(WHITE, BLUE, bold=True)
    alert_colors.buttonhotkey = video_color(YELLOW, BLUE, bold=True)
    alert_colors.activebutton = video_color(WHITE, GREEN, bold=True)
    alert_colors.activebuttonhotkey = video_color(YELLOW, GREEN, bold=True)

    alert = Alert(
        alert_colors,
        title="Alert",
        msg="Failed to load file",
        buttons=["<C>ancel", "<O>K"],
        default=1,
    )
    alert.show()

    alert.runloop()

    colors = ColorSet(WHITE, BLACK)
    colors.cursor = video_color(WHITE, GREEN, bold=True)
    cmdline = CmdLine(0, VIDEO.h - 1, VIDEO.w, colors, ":")
    cmdline.show()

    # main loop
    while True:
        view = STACK.top()
        if view is None:
            break

        event = view.runloop()
        if event == RETURN_TO_PREVIOUS:
            continue

        if event == GOTO_MENUBAR:
            # activate menubar by making it front
            menubar.front()

    terminate()


if __name__ == "__main__":
    try:
        unit_test()
    except:  # pylint: disable=bare-except
        terminate()
        traceback.print_exc()
        input("hit return")


# EOB
