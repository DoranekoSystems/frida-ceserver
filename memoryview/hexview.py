#! /usr/bin/env python3
#
#   hexview.py  WJ116
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

"""hex file viewer"""

import curses
import getopt
import os
import struct
import sys

import textmode
from textmode import (  # , MAGENTA
    BLACK,
    BLUE,
    CYAN,
    GREEN,
    KEY_BS,
    KEY_BTAB,
    KEY_DEL,
    KEY_DOWN,
    KEY_END,
    KEY_ESC,
    KEY_HOME,
    KEY_LEFT,
    KEY_PAGEDOWN,
    KEY_PAGEUP,
    KEY_RETURN,
    KEY_RIGHT,
    KEY_TAB,
    KEY_UP,
    RED,
    WHITE,
    YELLOW,
    Rect,
    getch,
)

# from hexviewlib.textmode import debug

VERSION = "1.3"

OPT_LINEMODE = textmode.LM_HLINE | textmode.LM_VLINE

API = None


class MemoryFile:
    """access file data as if it is an in-memory array"""

    IOSIZE = 256 * 1024

    def __init__(self, filename=None, pagesize=25 * 16):
        """Initialise"""
        self.filename = filename
        self.filesize = 0
        self.fd = None
        self.low = self.high = 0
        self.pagesize = pagesize
        self.cachesize = self.pagesize * 3
        # round up to nearest multiple of
        if self.cachesize % MemoryFile.IOSIZE != 0:
            self.cachesize += MemoryFile.IOSIZE - (self.cachesize % MemoryFile.IOSIZE)
        self.data = None

        if filename is not None:
            self.load(filename)

    def load(self, filename):
        """Open file"""
        self.filename = filename
        self.filesize = 0x7FFFFFFFFFFF  # os.path.getsize(self.filename)
        self.fd = 0  # open(filename, 'rb')
        self.data = bytearray(
            b"\x00" * self.cachesize
        )  # bytearray(self.fd.read(self.cachesize))
        self.low = 0
        self.high = len(self.data)

    def close(self):
        """Close the file"""
        if self.fd is not None:
            self.fd.close()
            self.fd = None

        self.filename = None
        self.filesize = 0
        self.data = None

    def __len__(self):
        """Returns length"""
        return self.filesize

    def __getitem__(self, idx):
        """Return byte or range at idx"""
        if isinstance(idx, int):
            # return byte at address
            if idx < 0 or idx >= self.filesize:
                raise IndexError("MemoryFile out of bounds error")

            if idx < self.low or idx >= self.high:
                self.pagefault(idx)

            return self.data[idx - self.low]

        if isinstance(idx, slice):
            if idx.start < 0 or idx.stop > self.filesize:
                raise IndexError("MemoryFile out of bounds error")

            if idx.start < self.low or idx.stop > self.high:
                self.pagefault(self.low)

            return self.data[idx.start - self.low : idx.stop - self.low : idx.step]

        raise TypeError("invalid argument type")

    def __setitem__(self, idx, value):
        if idx < 0 or idx >= self.filesize:
            raise IndexError("MemoryFile out of bounds error")

        if idx < self.low or idx >= self.high:
            self.pagefault(idx)

        self.data[idx - self.low] = value

    def pagefault(self, addr):
        """Page in data as needed"""
        self.low = addr - self.cachesize // 2
        if self.low < 0:
            self.low = 0

        self.high = addr + self.cachesize // 2
        if self.high > self.filesize:
            self.high = self.filesize

        size = self.high - self.low
        self.high = self.low + size
        ret = API.readprocessmemory(self.low, size)
        if ret == False:
            return bytearray(b"\x00" * size)
        else:
            return bytearray(ret)

    def find(self, searchtext, pos):
        """
        find searchtext
        Returns -1 if not found
        """
        if isinstance(searchtext, str):
            searchtext = bytes(searchtext, "utf-8")

        if pos < 0 or pos >= self.filesize:
            return -1

        if pos < self.low or pos + len(searchtext) >= self.high:
            self.pagefault(self.low)

        pos -= self.low

        while True:
            idx = self.data.find(searchtext, pos)
            if idx >= 0:
                # found
                return idx + self.low

            if self.high >= self.filesize:
                # not found
                return -1

            self.low = self.high - len(searchtext)
            self.pagefault(self.low)


class HexWindow(textmode.Window):
    """hex viewer main window"""

    MODE_8BIT = 1
    MODE_16BIT = 2
    MODE_32BIT = 4
    CLEAR_VIEWMODE = 0xFFFF & ~7
    MODE_SELECT = 8
    MODE_VALUES = 0x10

    # search direction
    FORWARD = 0
    BACKWARD = 1

    def __init__(self, x, y, w, h, colors, title=None, border=True, address=0):
        """Initialize"""
        # take off height for ValueSubWindow
        h -= 6
        # turn off window shadow for HexWindow
        # because it clobbers the bottom statusbar
        super().__init__(x, y, w, h, colors, title, border, shadow=False)
        self.data = None
        self.address = address
        self.cursor_x = self.cursor_y = 0
        self.mode = HexWindow.MODE_8BIT | HexWindow.MODE_VALUES
        self.selection_start = self.selection_end = 0
        self.old_addr = self.old_x = self.old_y = 0

        colors = textmode.ColorSet(WHITE, BLACK)
        colors.cursor = textmode.video_color(WHITE, GREEN, bold=True)
        self.cmdline = CommandBar(colors, prompt=":")
        self.search = CommandBar(colors, prompt="/")
        self.searchdir = HexWindow.FORWARD
        self.hexsearch = CommandBar(colors, prompt="x/", inputfilter=hex_inputfilter)
        self.jumpaddr = CommandBar(colors, prompt="@", inputfilter=hex_inputfilter)
        self.addaddr = CommandBar(colors, prompt="@+", inputfilter=hex_inputfilter)

        # this is a hack; I always want a visible cursor
        # even though the command bar can be the front window
        # so we can ignore focus events sometimes
        self.ignore_focus = False

        colors = textmode.ColorSet(WHITE, BLACK)
        colors.border = textmode.video_color(CYAN, BLACK)
        colors.status = textmode.video_color(CYAN, BLACK)
        self.valueview = ValueSubWindow(x, y + self.frame.h - 1, w, 7, colors)

        self.address_fmt = "{:08X}  "
        self.bytes_offset = 10
        self.ascii_offset = 60

        self.edit_position = 0
        self.get_lasttime = 0

    def resize_event(self):
        """The terminal was resized"""
        # always keep same width, but height may vary
        x = self.frame.x
        y = self.frame.y
        w = self.frame.w
        if self.mode & HexWindow.MODE_VALUES:
            h = self.frame.h = textmode.VIDEO.h - 1 - (self.valueview.frame.h - 1)
        else:
            h = self.frame.h = textmode.VIDEO.h - 1

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

        if self.cursor_y >= self.bounds.h:
            self.cursor_y = self.bounds.h - 1

        # resize the command and search bars
        self.cmdline.resize_event()
        self.search.resize_event()
        self.hexsearch.resize_event()
        self.jumpaddr.resize_event()
        self.addaddr.resize_event()
        self.valueview.resize_event()

    def load(self, filename):
        """
        load file
        Raises OSError on error
        """
        self.data = MemoryFile(filename, self.bounds.h * 16)

        self.title = os.path.basename(filename)
        if len(self.title) > self.bounds.w:
            self.title = self.title[: self.bounds.w - 6] + "..."

        self.set_address_format(len(self.data))

    def set_address_format(self, top_addr):
        """Set address notation"""
        # slightly change layout so that app stays goodlooking

        if top_addr <= 0xFFFF:
            # up to 64 kiB
            self.address_fmt = "{:04X}    "
            self.bytes_offset = 8
            self.ascii_offset = 60
        elif top_addr <= 0xFFFFFFFF:
            # up to 4 GiB
            self.address_fmt = "{:08X}  "
            self.bytes_offset = 10
            self.ascii_offset = 60
        elif top_addr <= 0xFFFFFFFFFF:
            # up to 1 TiB
            self.address_fmt = "{:010X}  "
            self.bytes_offset = 12
            self.ascii_offset = 62
        else:
            # up to 256 TiB will look fine
            self.address_fmt = "{:012X} "
            self.bytes_offset = 13
            self.ascii_offset = 62

        # __MODIFY__
        self.address_fmt = "{:012X} "
        self.bytes_offset = 13
        self.ascii_offset = 62

    def show(self):
        """Open the window"""
        if self.mode & HexWindow.MODE_VALUES:
            self.valueview.show()

        super().show()

    def close(self):
        """Close window"""
        self.data.close()

        super().close()

    def lose_focus(self):
        """We lose focus"""
        if self.ignore_focus:
            # ignore only once
            self.ignore_focus = False
            return

        super().lose_focus()

    def draw(self):
        """Draw the window"""
        if not self.flags & textmode.Window.SHOWN:
            return

        super().draw()

        if self.mode & HexWindow.MODE_8BIT:
            self.draw_view_8bit()

        elif self.mode & HexWindow.MODE_16BIT:
            self.draw_view_16bit()

        elif self.mode & HexWindow.MODE_32BIT:
            self.draw_view_32bit()

        self.draw_statusbar()

    def draw_statusbar(self):
        """Draw statusbar"""
        status = None
        if self.mode & HexWindow.MODE_SELECT:
            status = "Select"

        if status is None:
            textmode.VIDEO.hline(
                self.bounds.x + self.bounds.w - 12,
                self.bounds.y + self.bounds.h,
                10,
                curses.ACS_HLINE,
                self.colors.border,
            )
        else:
            textmode.VIDEO.puts(
                self.bounds.x + self.bounds.w - 2 - len(status),
                self.bounds.y + self.bounds.h,
                status,
                self.colors.status,
            )

    def draw_view_8bit(self):
        """Draw hexview for single bytes"""
        y = 0
        while y < self.bounds.h:
            # address
            offset = self.address + y * 16
            line = self.address_fmt.format(offset)

            # bytes (left block)
            try:
                # try fast(er) implementation
                line += (
                    "{:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}  "
                    "{:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}"
                ).format(
                    self.data[offset],
                    self.data[offset + 1],
                    self.data[offset + 2],
                    self.data[offset + 3],
                    self.data[offset + 4],
                    self.data[offset + 5],
                    self.data[offset + 6],
                    self.data[offset + 7],
                    self.data[offset + 8],
                    self.data[offset + 9],
                    self.data[offset + 10],
                    self.data[offset + 11],
                    self.data[offset + 12],
                    self.data[offset + 13],
                    self.data[offset + 14],
                    self.data[offset + 15],
                )
            except IndexError:
                # do the slower version
                for i in range(0, 8):
                    try:
                        line += "{:02X} ".format(self.data[offset + i])
                    except IndexError:
                        line += "   "
                line += " "
                for i in range(8, 16):
                    try:
                        line += "{:02X} ".format(self.data[offset + i])
                    except IndexError:
                        line += "   "

            self.puts(0, y, line, self.colors.text)

            self.draw_ascii(y)
            y += 1

    def draw_view_16bit(self):
        """Draw hexview for 16 bit words"""
        y = 0
        while y < self.bounds.h:
            # address
            offset = self.address + y * 16
            line = self.address_fmt.format(offset)

            # left block
            try:
                # try fast(er) implementation
                line += (
                    "{:02X}{:02X}  {:02X}{:02X}  {:02X}{:02X}  {:02X}{:02X}   "
                    "{:02X}{:02X}  {:02X}{:02X}  {:02X}{:02X}  {:02X}{:02X}"
                ).format(
                    self.data[offset],
                    self.data[offset + 1],
                    self.data[offset + 2],
                    self.data[offset + 3],
                    self.data[offset + 4],
                    self.data[offset + 5],
                    self.data[offset + 6],
                    self.data[offset + 7],
                    self.data[offset + 8],
                    self.data[offset + 9],
                    self.data[offset + 10],
                    self.data[offset + 11],
                    self.data[offset + 12],
                    self.data[offset + 13],
                    self.data[offset + 14],
                    self.data[offset + 15],
                )
            except IndexError:
                # do the slower version
                for i in range(0, 4):
                    try:
                        line += "{:02X}".format(self.data[offset + i * 2])
                    except IndexError:
                        line += "  "
                    try:
                        line += "{:02X}".format(self.data[offset + i * 2 + 1])
                    except IndexError:
                        line += "  "
                    line += "  "

                offset += 8
                line += " "
                # right block
                for i in range(0, 4):
                    try:
                        line += "{:02X}".format(self.data[offset + i * 2])
                    except IndexError:
                        line += "  "
                    try:
                        line += "{:02X}".format(self.data[offset + i * 2 + 1])
                    except IndexError:
                        line += "  "
                    line += "  "

            self.puts(0, y, line, self.colors.text)

            self.draw_ascii(y)
            y += 1

    def draw_view_32bit(self):
        """Draw hexview for 32 bit words"""
        y = 0
        while y < self.bounds.h:
            # address
            offset = self.address + y * 16
            line = self.address_fmt.format(offset)

            # left block
            try:
                # try fast(er) implementation
                line += (
                    "{:02X}{:02X}{:02X}{:02X}    {:02X}{:02X}{:02X}{:02X}     "
                    "{:02X}{:02X}{:02X}{:02X}    {:02X}{:02X}{:02X}{:02X}"
                ).format(
                    self.data[offset],
                    self.data[offset + 1],
                    self.data[offset + 2],
                    self.data[offset + 3],
                    self.data[offset + 4],
                    self.data[offset + 5],
                    self.data[offset + 6],
                    self.data[offset + 7],
                    self.data[offset + 8],
                    self.data[offset + 9],
                    self.data[offset + 10],
                    self.data[offset + 11],
                    self.data[offset + 12],
                    self.data[offset + 13],
                    self.data[offset + 14],
                    self.data[offset + 15],
                )
            except IndexError:
                # do the slower version
                for i in range(0, 2):
                    try:
                        line += "{:02X}".format(self.data[offset + i * 4])
                    except IndexError:
                        line += "  "
                    try:
                        line += "{:02X}".format(self.data[offset + i * 4 + 1])
                    except IndexError:
                        line += "  "
                    try:
                        line += "{:02X}".format(self.data[offset + i * 4 + 2])
                    except IndexError:
                        line += "  "
                    try:
                        line += "{:02X}".format(self.data[offset + i * 4 + 3])
                    except IndexError:
                        line += "  "
                    line += "    "

                offset += 8
                line += " "
                # right block
                for i in range(0, 2):
                    try:
                        line += "{:02X}".format(self.data[offset + i * 4])
                    except IndexError:
                        line += "  "
                    try:
                        line += "{:02X}".format(self.data[offset + i * 4 + 1])
                    except IndexError:
                        line += "  "
                    try:
                        line += "{:02X}".format(self.data[offset + i * 4 + 2])
                    except IndexError:
                        line += "  "
                    try:
                        line += "{:02X}".format(self.data[offset + i * 4 + 3])
                    except IndexError:
                        line += "  "
                    line += "    "

            self.puts(0, y, line, self.colors.text)

            self.draw_ascii(y)
            y += 1

    def draw_ascii(self, y):
        """Draw ascii bytes for line y"""
        invis = []
        line = ""
        offset = self.address + y * 16
        for i in range(0, 16):
            try:
                ch = self.data[offset + i]
                if ord(" ") <= ch <= ord("~"):
                    line += chr(ch)
                else:
                    line += "."
                    invis.append(i)
            except IndexError:
                ch = " "

        # put the ASCII bytes line
        self.puts(self.ascii_offset, y, line, self.colors.text)

        # color invisibles
        for i in invis:
            self.color_putch(self.ascii_offset + i, y, self.colors.invisibles)

    def draw_cursor(self, clear=False, mark=None):  # pylint: disable=arguments-differ
        """Draw cursor"""
        if not self.flags & textmode.Window.FOCUS:
            clear = True

        if clear:
            color = self.colors.text
        else:
            color = self.colors.cursor

        if mark is not None:
            color = mark

        if self.mode & HexWindow.MODE_SELECT:
            self.draw_selection()

        offset = self.address + self.cursor_y * 16 + self.cursor_x
        x = self.hexview_position(offset)
        self.draw_cursor_at(self.bytes_offset + x, self.cursor_y, color, clear)

        y = self.cursor_y
        ch = self.data[self.address + y * 16 + self.cursor_x]
        self.draw_ascii_cursor(ch, color, clear)

        self.update_values()

    def draw_ascii_cursor(self, ch, color, clear):
        """Draw ascii cursor"""
        if clear:
            color = self.colors.text
        else:
            color = self.colors.cursor

        if ord(" ") <= ch <= ord("~"):
            ch = chr(ch)
        else:
            ch = "."
            if clear:
                color = self.colors.invisibles

        alt = not clear
        self.color_putch(self.ascii_offset + self.cursor_x, self.cursor_y, color, alt)

    def draw_cursor_at(self, x, y, color, clear):
        """Draw hex bytes cursor at x, y"""
        alt = not clear
        textmode.VIDEO.color_hline(self.bounds.x + x, self.bounds.y + y, 2, color, alt)

    def clear_cursor(self):
        """Clear the cursor"""
        self.draw_cursor(clear=True)

    def hexview_position(self, offset):
        """
        Returns x position in hex view for offset
        Returns -1 for out of bounds offset
        """
        if offset < 0:
            return -1

        pagesize = self.bounds.h * 16
        if offset > self.address + pagesize:
            return -1

        offset = (offset - self.address) % 16

        x = 0
        if self.mode & HexWindow.MODE_8BIT:
            x = offset * 3
            if offset >= 8:
                x += 1

        elif self.mode & HexWindow.MODE_16BIT:
            x = offset // 2 * 6
            if offset & 1:
                x += 2
            if offset >= 8:
                x += 1

        elif self.mode & HexWindow.MODE_32BIT:
            x = offset // 4 * 12
            mod = offset % 4
            x += mod * 2
            if offset >= 8:
                x += 1

        return x

    def draw_selection(self):
        """Draw selection"""
        start = self.selection_start
        if start < self.address:
            start = self.address
        pagesize = self.bounds.h * 16
        end = self.selection_end
        if end > self.address + pagesize:
            end = self.address + pagesize

        startx = (start - self.address) % 16
        starty = (start - self.address) // 16
        endx = (end - self.address) % 16
        endy = (end - self.address) // 16

        # ASCII view
        if starty == endy:
            textmode.VIDEO.color_hline(
                (self.bounds.x + self.ascii_offset + startx),
                self.bounds.y + starty,
                endx - startx,
                self.colors.cursor,
            )
        else:
            textmode.VIDEO.color_hline(
                (self.bounds.x + self.ascii_offset + startx),
                self.bounds.y + starty,
                16 - startx,
                self.colors.cursor,
            )
            for j in range(starty + 1, endy):
                textmode.VIDEO.color_hline(
                    (self.bounds.x + self.ascii_offset),
                    self.bounds.y + j,
                    16,
                    self.colors.cursor,
                )
            textmode.VIDEO.color_hline(
                self.bounds.x + self.ascii_offset,
                self.bounds.y + endy,
                endx,
                self.colors.cursor,
            )

        # hex view start/end position depend on viewing mode
        startx = self.hexview_position(start)
        endx = self.hexview_position(end)

        if starty == endy:
            textmode.VIDEO.color_hline(
                (self.bounds.x + self.bytes_offset + startx),
                self.bounds.y + starty,
                endx - startx,
                self.colors.cursor,
            )
        else:
            w = 16 * 3
            textmode.VIDEO.color_hline(
                (self.bounds.x + self.bytes_offset + startx),
                self.bounds.y + starty,
                w - startx,
                self.colors.cursor,
            )
            for j in range(starty + 1, endy):
                textmode.VIDEO.color_hline(
                    self.bounds.x + self.bytes_offset,
                    self.bounds.y + j,
                    w,
                    self.colors.cursor,
                )
            textmode.VIDEO.color_hline(
                self.bounds.x + self.bytes_offset,
                self.bounds.y + endy,
                endx,
                self.colors.cursor,
            )

    def update_values(self):
        """Update value view"""
        if not self.mode & HexWindow.MODE_VALUES:
            return

        # get data at cursor
        offset = self.address + self.cursor_y * 16 + self.cursor_x
        try:
            data = self.data[offset : offset + 8]
        except IndexError:
            # get data, do zero padding
            data = bytearray(8)
            for i in range(0, 8):
                try:
                    data[i] = self.data[offset + i]
                except IndexError:
                    break

        self.valueview.update(data)

    def mark_address(self, y, color=-1):
        """
        only used to draw a marked address
        Marked addresses are copied into the jumpaddr history
        """
        if color == -1:
            color = textmode.video_color(WHITE, RED, bold=True)

        textmode.VIDEO.color_hline(self.bounds.x, self.bounds.y + y, 8, color)

    def scroll_up(self, nlines=1):
        """Scroll nlines up"""
        self.address -= nlines * 16
        if self.address < 0:
            self.address = 0

        self.draw()

    def scroll_down(self, nlines=1):
        """Scroll nlines down"""
        addr = self.address + nlines * 16

        pagesize = self.bounds.h * 16
        if addr > len(self.data) - pagesize:
            addr = len(self.data) - pagesize
        if addr < 0:
            addr = 0

        if addr != self.address:
            self.address = addr
            self.draw()

    def move_up(self):
        """Move cursor up"""
        if not self.cursor_y and not self.address:
            return

        self.clear_cursor()

        if not self.cursor_y:
            self.scroll_up()
        else:
            self.cursor_y -= 1

        self.update_selection()
        self.draw_cursor()

    def move_down(self):
        """Move cursor down"""
        if self.cursor_y >= self.bounds.h - 1:
            # scroll down
            addr = self.address
            self.scroll_down()
            if self.address == addr:
                # no change (already at end)
                return
        else:
            addr = self.address + (self.cursor_y + 1) * 16 + self.cursor_x
            if addr >= len(self.data):
                # can not go beyond EOF
                return

            self.clear_cursor()
            self.cursor_y += 1

        self.update_selection()
        self.draw_cursor()

    def move_left(self):
        """Move cursor left"""
        if not self.cursor_x and not self.cursor_y:
            if not self.address:
                return

            self.scroll_up()
        else:
            self.clear_cursor()

        if not self.cursor_x:
            if self.cursor_y > 0:
                self.cursor_y -= 1
            self.cursor_x = 15
        else:
            self.cursor_x -= 1

        self.update_selection()
        self.draw_cursor()

    def move_right(self):
        """Move cursor right"""
        if self.cursor_x >= 15 and self.cursor_y >= self.bounds.h - 1:
            # scroll down
            addr = self.address
            self.scroll_down()
            if self.address == addr:
                # no change (already at end)
                return
        else:
            addr = self.address + self.cursor_y * 16 + self.cursor_x + 1
            if addr >= len(self.data):
                # can not go beyond EOF
                return

            self.clear_cursor()

        if self.cursor_x >= 15:
            self.cursor_x = 0
            if self.cursor_y < self.bounds.h - 1:
                self.cursor_y += 1
        else:
            self.cursor_x += 1

        self.update_selection()
        self.draw_cursor()

    def roll_left(self):
        """Move left by one byte"""
        if not self.address:
            return

        self.address -= 1
        self.draw()
        self.draw_cursor()

    def roll_right(self):
        """Move right by one byte"""
        top = len(self.data) - self.bounds.h * 16
        if self.address < top:
            self.address += 1
            self.draw()
            self.draw_cursor()

    def pageup(self):
        """Page up"""
        if not self.address:
            if not self.cursor_y:
                return

            self.clear_cursor()
            self.cursor_y = 0
            self.update_selection()
            self.draw_cursor()
            return

        if self.cursor_y == self.bounds.h - 1:
            self.clear_cursor()
            self.cursor_y = 0
        else:
            self.scroll_up(self.bounds.h - 1)

        self.update_selection()
        self.draw_cursor()

    def pagedown(self):
        """Page down"""
        if self.cursor_y == 0:
            self.clear_cursor()
            self.cursor_y = self.bounds.h - 1
        else:
            addr = self.address
            self.scroll_down(self.bounds.h - 1)
            if self.address == addr:
                # no change
                if self.cursor_y >= self.bounds.h - 1:
                    return

                self.clear_cursor()
                self.cursor_y = self.bounds.h - 1

        self.update_selection()
        self.draw_cursor()

    def move_home(self):
        """Go to top of document"""
        if not self.address:
            if not self.cursor_x and not self.cursor_y:
                return

            self.clear_cursor()
        else:
            self.address = 0
            self.draw()

        self.cursor_x = self.cursor_y = 0
        self.update_selection()
        self.draw_cursor()

    def move_end(self):
        """Go to last page of document"""
        pagesize = self.bounds.h * 16
        top = len(self.data) - pagesize
        if top < 0:
            top = 0

        if self.address != top:
            self.address = top
            self.draw()
        else:
            self.clear_cursor()

        if len(self.data) < pagesize:
            self.cursor_y = len(self.data) // 16
            self.cursor_x = len(self.data) % 16
        else:
            self.cursor_y = self.bounds.h - 1
            self.cursor_x = 15

        self.update_selection()
        self.draw_cursor()

    def select_view(self, key):
        """Set view option"""
        update = False
        if key == "1" and self.mode & HexWindow.MODE_8BIT != HexWindow.MODE_8BIT:
            self.mode &= HexWindow.CLEAR_VIEWMODE
            self.mode |= HexWindow.MODE_8BIT
            update = True

        elif key == "2" and self.mode & HexWindow.MODE_16BIT != HexWindow.MODE_16BIT:
            self.mode &= HexWindow.CLEAR_VIEWMODE
            self.mode |= HexWindow.MODE_16BIT
            update = True

        elif key == "4" and self.mode & HexWindow.MODE_32BIT != HexWindow.MODE_32BIT:
            self.mode &= HexWindow.CLEAR_VIEWMODE
            self.mode |= HexWindow.MODE_32BIT
            update = True

        if update:
            self.draw()
            self.draw_cursor()

    def mode_selection(self):
        """Toggle selection mode"""
        if not self.mode & HexWindow.MODE_SELECT:
            self.selection_start = self.address + self.cursor_y * 16 + self.cursor_x
            self.selection_end = self.selection_start

        self.mode ^= HexWindow.MODE_SELECT
        self.update_selection()

        if not self.mode & HexWindow.MODE_SELECT:
            # was not yet redrawn ... do it now
            self.draw()

        self.draw_cursor()

    def update_selection(self):
        """Update selection start/end"""
        if self.mode & HexWindow.MODE_SELECT:
            old_addr = self.old_addr + self.old_y * 16 + self.old_x
            addr = self.address + self.cursor_y * 16 + self.cursor_x

            if self.selection_start == self.selection_end:
                if addr < self.selection_start:
                    self.selection_start = addr
                elif addr > self.selection_end:
                    self.selection_end = addr
            else:
                if old_addr == self.selection_start:
                    self.selection_start = addr
                elif old_addr == self.selection_end:
                    self.selection_end = addr

            if self.selection_start > self.selection_end:
                # swap start, end
                # and PEP-8 looks amazingly stupid here
                (self.selection_start, self.selection_end) = (
                    self.selection_end,
                    self.selection_start,
                )

            self.draw()

    def search_error(self, msg):
        """Display error message for search functions"""
        self.ignore_focus = True
        self.search.show()
        self.search.cputs(0, 0, msg, textmode.video_color(WHITE, RED, bold=True))
        getch()
        self.search.hide()

    def find(self, again=False):
        """Text search"""
        self.searchdir = HexWindow.FORWARD
        searchtext = ""

        if not again:
            self.search.prompt = "/"
            self.ignore_focus = True
            self.search.show()
            ret = self.search.runloop()
            if ret != textmode.ENTER:
                return

            searchtext = self.search.textfield.text
            if not searchtext:
                again = True

        if again:
            try:
                searchtext = self.search.textfield.history[-1]
            except IndexError:
                return

        if not searchtext:
            return

        pos = self.address + self.cursor_y * 16 + self.cursor_x
        if again:
            pos += 1

        try:
            offset = self.data.find(searchtext, pos)
        except ValueError:
            # not found
            offset = -1

        if offset == -1:
            self.search_error("Not found")
            return

        # text was found at offset
        self.clear_cursor()
        # if on the same page, move the cursor
        pagesize = self.bounds.h * 16
        if self.address < offset + len(searchtext) < self.address + pagesize:
            pass
        else:
            # scroll the page; change base address
            self.address = offset - self.bounds.h * 8
            if self.address > len(self.data) - pagesize:
                self.address = len(self.data) - pagesize
            if self.address < 0:
                self.address = 0

            self.draw()

        # move cursor location
        diff = offset - self.address
        self.cursor_y = diff // 16
        self.cursor_x = diff % 16
        self.draw_cursor()

    def find_backwards(self, again=False):
        """Text search backwards"""
        self.searchdir = HexWindow.BACKWARD
        searchtext = ""

        if not again:
            self.search.prompt = "?"
            self.ignore_focus = True
            self.search.show()
            ret = self.search.runloop()
            if ret != textmode.ENTER:
                return

            searchtext = self.search.textfield.text
            if not searchtext:
                again = True

        if again:
            try:
                searchtext = self.search.textfield.history[-1]
            except IndexError:
                return

        if not searchtext:
            return

        pos = self.address + self.cursor_y * 16 + self.cursor_x
        try:
            offset = bytearray_find_backwards(self.data, searchtext, pos)
        except ValueError:
            # not found
            offset = -1

        if offset == -1:
            self.search_error("Not found")
            return

        # text was found at offset
        self.clear_cursor()
        # if on the same page, move the cursor
        pagesize = self.bounds.h * 16
        if self.address < offset + len(searchtext) < self.address + pagesize:
            pass
        else:
            # scroll the page; change base address
            self.address = offset - self.bounds.h * 8
            if self.address > len(self.data) - pagesize:
                self.address = len(self.data) - pagesize
            if self.address < 0:
                self.address = 0

            self.draw()

        # move cursor location
        diff = offset - self.address
        self.cursor_y = diff // 16
        self.cursor_x = diff % 16
        self.draw_cursor()

    def find_hex(self, again=False):
        """Search hex string"""
        self.searchdir = HexWindow.FORWARD
        searchtext = ""

        if not again:
            self.ignore_focus = True
            self.hexsearch.show()
            ret = self.hexsearch.runloop()
            if ret != textmode.ENTER:
                return

            searchtext = self.hexsearch.textfield.text
            if not searchtext:
                again = True

        if again:
            try:
                searchtext = self.hexsearch.textfield.history[-1]
            except IndexError:
                return

        if not searchtext:
            return

        # convert ascii searchtext to raw byte string
        searchtext = searchtext.replace(" ", "")
        if not searchtext:
            return

        if len(searchtext) & 1:
            self.search_error("Invalid byte string (uneven number of digits)")
            return

        raw = ""
        for x in range(0, len(searchtext), 2):
            hex_string = searchtext[x : x + 2]
            try:
                value = int(hex_string, 16)
            except ValueError:
                self.search_error("Invalid value in byte string")
                return

            raw += chr(value)

        pos = self.address + self.cursor_y * 16 + self.cursor_x
        if again:
            pos += 1

        try:
            offset = self.data.find(raw, pos)
        except ValueError:
            # not found
            offset = -1

        if offset == -1:
            self.search_error("Not found")
            return

        # text was found at offset
        self.clear_cursor()
        # if on the same page, move the cursor
        pagesize = self.bounds.h * 16
        if self.address < offset + len(searchtext) < self.address + pagesize:
            pass
        else:
            # scroll the page; change base address
            self.address = offset - self.bounds.h * 8
            if self.address > len(self.data) - pagesize:
                self.address = len(self.data) - pagesize
            if self.address < 0:
                self.address = 0

            self.draw()

        # move cursor location
        diff = offset - self.address
        self.cursor_y = diff // 16
        self.cursor_x = diff % 16
        self.draw_cursor()

    def jump_address(self):
        """Jump to address"""
        self.ignore_focus = True
        self.jumpaddr.show()
        ret = self.jumpaddr.runloop()
        if ret != textmode.ENTER:
            return

        text = self.jumpaddr.textfield.text
        text = text.replace(" ", "")
        if not text:
            return

        try:
            addr = int(text, 16)
        except ValueError:
            self.search_error("Invalid address")
            return

        # make addr appear at cursor_y
        addr -= self.cursor_y * 16

        pagesize = self.bounds.h * 16
        if addr > len(self.data) - pagesize:
            addr = len(self.data) - pagesize
        if addr < 0:
            addr = 0

        if addr != self.address:
            self.address = addr
            self.draw()
            self.draw_cursor()

    def plus_offset(self):
        """Add offset"""
        self.addaddr.prompt = "@+"
        self.ignore_focus = True
        self.addaddr.show()
        ret = self.addaddr.runloop()
        if ret != textmode.ENTER:
            return

        text = self.addaddr.textfield.text
        text = text.replace(" ", "")
        if not text:
            return

        try:
            if text[0] in "0ABCDEF":
                offset = int(text, 16)
            else:
                offset = int(text, 10)
        except ValueError:
            self.search_error("Invalid address")
            return

        curr_addr = self.address + self.cursor_y * 16 + self.cursor_x
        addr = curr_addr + offset
        if addr < 0:
            addr = 0

        if addr >= len(self.data):
            addr = len(self.data) - 1
        if addr < 0:
            addr = 0

        if addr == curr_addr:
            return

        pagesize = self.bounds.h * 16
        if self.address <= addr < self.address + pagesize:
            # move the cursor
            self.clear_cursor()
        else:
            # move base address
            self.address = addr
            if self.address > len(self.data) - pagesize:
                self.address = len(self.data) - pagesize
            self.draw()

        self.cursor_x = (addr - self.address) % 16
        self.cursor_y = (addr - self.address) // 16
        self.draw_cursor()

    def minus_offset(self):
        """Minus offset"""
        self.addaddr.prompt = "@-"
        self.ignore_focus = True
        self.addaddr.show()
        ret = self.addaddr.runloop()
        if ret != textmode.ENTER:
            return

        text = self.addaddr.textfield.text
        text = text.replace(" ", "")
        if not text:
            return

        try:
            if text[0] in "0ABCDEF":
                offset = int(text, 16)
            else:
                offset = int(text, 10)
        except ValueError:
            self.search_error("Invalid address")
            return

        curr_addr = self.address + self.cursor_y * 16 + self.cursor_x
        addr = curr_addr - offset
        if addr < 0:
            addr = 0

        if addr >= len(self.data):
            addr = len(self.data) - 1
        if addr < 0:
            addr = 0

        if addr == curr_addr:
            return

        pagesize = self.bounds.h * 16
        if self.address <= addr < self.address + pagesize:
            # move the cursor
            self.clear_cursor()
        else:
            # move base address
            self.address = addr
            if self.address > len(self.data) - pagesize:
                self.address = len(self.data) - pagesize
            self.draw()

        self.cursor_x = (addr - self.address) % 16
        self.cursor_y = (addr - self.address) // 16
        self.draw_cursor()

    def copy_address(self):
        """Copy current address to jump history"""
        addr = self.address + self.cursor_y * 16 + self.cursor_x
        self.jumpaddr.textfield.history.append("{:08X}".format(addr))

        # give visual feedback
        color = textmode.video_color(WHITE, RED, bold=True)
        self.mark_address(self.cursor_y, color)
        self.draw_cursor(mark=color)

    def move_begin_line(self):
        """Goto beginning of line"""
        if self.cursor_x != 0:
            self.clear_cursor()
            self.cursor_x = 0
            self.draw_cursor()

    def move_end_line(self):
        """Goto end of line"""
        if self.cursor_x != 15:
            self.clear_cursor()
            self.cursor_x = 15
            self.draw_cursor()

    def move_top(self):
        """Goto top of screen"""
        if self.cursor_y != 0:
            self.clear_cursor()
            self.cursor_y = 0
            self.draw_cursor()

    def move_middle(self):
        """Goto middle of screen"""
        y = self.bounds.h // 2
        if self.cursor_y != y:
            self.clear_cursor()
            self.cursor_y = y
            self.draw_cursor()

    def move_bottom(self):
        """Goto bottom of screen"""
        if self.cursor_y != self.bounds.h - 1:
            self.clear_cursor()
            self.cursor_y = self.bounds.h - 1
            self.draw_cursor()

    def move_word(self):
        """Move to next word"""
        end = len(self.data) - 1
        addr = self.address + self.cursor_y * 16 + self.cursor_x

        if isalphanum(self.data[addr]):
            while isalphanum(self.data[addr]) and addr < end:
                addr += 1

        while isspace(self.data[addr]) and addr < end:
            addr += 1

        if addr == self.address:
            return

        pagesize = self.bounds.h * 16
        if self.address < addr < self.address + pagesize:
            # only move cursor
            self.clear_cursor()
            diff = addr - self.address
            self.cursor_y = diff // 16
            self.cursor_x = diff % 16
        else:
            # scroll page
            # round up to nearest 16
            addr2 = addr
            mod = addr2 % 16
            if mod != 0:
                addr2 += 16 - mod
            else:
                addr2 += 16
            self.address = addr2 - pagesize
            diff = addr - self.address
            self.cursor_y = diff // 16
            self.cursor_x = diff % 16
            self.draw()

        self.draw_cursor()

    def move_word_back(self):
        """Move to previous word"""
        addr = self.address + self.cursor_y * 16 + self.cursor_x

        # skip back over any spaces
        while addr > 0 and isspace(self.data[addr - 1]):
            addr -= 1

        # move to beginning of word
        while addr > 0 and isalphanum(self.data[addr - 1]):
            addr -= 1

        pagesize = self.bounds.h * 16
        if self.address < addr < self.address + pagesize:
            # only move cursor
            self.clear_cursor()
            diff = addr - self.address
            self.cursor_y = diff // 16
            self.cursor_x = diff % 16
        else:
            # scroll page
            # round up to nearest 16
            addr2 = addr
            mod = addr2 % 16
            if mod != 0:
                addr2 += 16 - mod
            else:
                addr2 += 16
            self.address = addr2 - pagesize
            if self.address < 0:
                self.address = 0
            diff = addr - self.address
            self.cursor_y = diff // 16
            self.cursor_x = diff % 16
            self.draw()

        self.draw_cursor()

    def command(self):
        """
        command mode
        Returns 0 (do nothing) or app code
        """
        self.ignore_focus = True
        self.cmdline.show()
        ret = self.cmdline.runloop()
        if ret != textmode.ENTER:
            return 0

        cmd = self.cmdline.textfield.text
        if " " in cmd:
            cmd, arg = cmd.split(" ", 1)
        else:
            arg = None
        if not cmd:
            return 0

        if cmd == "help" or cmd == "?":  # pylint: disable=consider-using-in
            self.show_help()

        elif cmd in ("about", "version"):
            self.show_about()

        elif cmd == "license":
            self.show_license()

        elif cmd in ("q", "q!", "quit"):
            return textmode.QUIT

        elif cmd in ("wq", "wq!", "ZZ", "exit"):
            return textmode.EXIT

        elif cmd == "load":
            self.loadfile(arg)

        elif cmd in ("print", "values"):
            self.print_values()

        elif cmd == "big":
            self.set_big_endian()

        elif cmd == "little":
            self.set_little_endian()

        elif cmd == "0":
            self.move_home()

        else:
            self.ignore_focus = True
            self.cmdline.show()
            self.cmdline.cputs(
                0,
                0,
                "Unknown command '{}'".format(cmd),
                textmode.video_color(WHITE, RED, bold=True),
            )
            getch()
            self.cmdline.hide()

        return 0

    def loadfile(self, filename):
        """Load file"""
        if not filename:
            return

        if filename[0] == "~":
            filename = os.path.expanduser(filename)
        if "$" in filename:
            filename = os.path.expandvars(filename)
        try:
            self.load(filename)
        except OSError as err:
            self.ignore_focus = True
            self.cmdline.show()
            self.cmdline.cputs(
                0, 0, err.strerror, textmode.video_color(WHITE, RED, bold=True)
            )
            getch()
            self.cmdline.hide()
        else:
            self.draw()
            self.draw_cursor()

    def show_help(self):
        """Show help window"""
        win = HelpWindow(self)
        win.show()
        win.runloop()
        win.close()

    def show_about(self):
        """Show About box"""
        win = AboutBox()
        win.show()
        win.runloop()

    def show_license(self):
        """Show the software license"""
        win = LicenseBox()
        win.show()
        if win.runloop() == 0:
            # license not accepted
            textmode.terminate()
            print(
                "If you do not accept the license, you really shouldn't "
                "be using this software"
            )
            sys.exit(1)

    def print_values(self):
        """Toggle values subwindow"""
        self.mode ^= HexWindow.MODE_VALUES
        if self.mode & HexWindow.MODE_VALUES:
            self.shrink_window(self.valueview.frame.h - 1)
            self.valueview.show()
        else:
            self.valueview.hide()
            self.expand_window(self.valueview.frame.h - 1)

        self.draw()
        self.draw_cursor()
        self.update_values()

    def shrink_window(self, lines):
        """Shrink main window by n lines"""
        self.hide()
        self.frame.h -= lines
        self.bounds.h -= lines
        self.rect.h -= lines
        self.show()

        if self.cursor_y > self.bounds.h - 1:
            self.cursor_y = self.bounds.h - 1

    def expand_window(self, lines):
        """Grow main window by n lines"""
        self.hide()
        self.frame.h += lines
        self.bounds.h += lines
        self.rect.h += lines
        self.show()

    def toggle_endianness(self):
        """Toggle endianness in values subwindow"""
        if self.valueview.endian == ValueSubWindow.BIG_ENDIAN:
            self.valueview.endian = ValueSubWindow.LITTLE_ENDIAN
        else:
            self.valueview.endian = ValueSubWindow.BIG_ENDIAN

        self.update_values()
        self.valueview.update_status()

    def set_big_endian(self):
        """Set big endian mode"""
        if self.valueview.endian != ValueSubWindow.BIG_ENDIAN:
            self.valueview.endian = ValueSubWindow.BIG_ENDIAN
            self.update_values()
            self.valueview.update_status()

    def set_little_endian(self):
        """Set little endian mode"""
        if self.valueview.endian != ValueSubWindow.LITTLE_ENDIAN:
            self.valueview.endian = ValueSubWindow.LITTLE_ENDIAN
            self.update_values()
            self.valueview.update_status()

    def check_and_getdata(self):
        data = 0
        ret = API.readprocessmemory(self.address, 1024)
        if ret == False:
            data = bytearray(b"\x00" * 1024)
        else:
            data = bytearray(ret)

        for i, d in enumerate(data):
            self.data[i + self.address] = d

    def runloop(self):
        """
        run the input loop
        Returns state change code
        """
        self.gain_focus()
        while True:
            self.check_and_getdata()
            self.draw()
            self.draw_cursor()

            self.old_addr = self.address
            self.old_x = self.cursor_x
            self.old_y = self.cursor_y

            key = getch()

            # memory edit
            if key in (
                "0",
                "1",
                "2",
                "3",
                "4",
                "5",
                "6",
                "7",
                "8",
                "9",
                "a",
                "b",
                "c",
                "d",
                "e",
                "f",
            ):
                pos = self.address + self.cursor_x + self.cursor_y * 16
                orig = self.data[pos]
                if self.edit_position == 0:
                    self.data[pos] = (0x10 * int(key, 16)) | (orig & 0x0F)
                    self.edit_position = 1
                    params = {"address": pos, "buffer": [self.data[pos]]}
                    API.writeprocessmemory(pos, [self.data[pos]])
                elif self.edit_position == 1:
                    self.data[pos] = (0x01 * int(key, 16)) | (orig & 0xF0)
                    self.edit_position = 2
                    params = {"address": pos, "buffer": [self.data[pos]]}
                    API.writeprocessmemory(pos, [self.data[pos]])
                else:
                    self.edit_position = 0
                    self.move_right()
            elif key != "0x-1":
                self.edit_position = 0

            if key == KEY_ESC:
                if self.mode & HexWindow.MODE_SELECT:
                    self.mode_selection()
            elif key == KEY_UP or key == "k":  # pylint: disable=consider-using-in
                self.move_up()

            elif key == KEY_DOWN or key == "j":  # pylint: disable=consider-using-in
                self.move_down()

            elif key == KEY_LEFT or key == "h":  # pylint: disable=consider-using-in
                self.move_left()

            elif key == KEY_RIGHT or key == "l":  # pylint: disable=consider-using-in
                self.move_right()

            elif key == "<" or key == ",":  # pylint: disable=consider-using-in
                self.roll_left()

            elif key == ">" or key == ".":  # pylint: disable=consider-using-in
                self.roll_right()

            elif key == KEY_PAGEUP or key == "Ctrl-U":  # pylint: disable=consider-using-in
                self.pageup()

            elif key == KEY_PAGEDOWN or key == "Ctrl-D":  # pylint: disable=consider-using-in
                self.pagedown()

            elif key == KEY_HOME or key == "g":  # pylint: disable=consider-using-in
                self.move_home()

            elif key == KEY_END or key == "G":  # pylint: disable=consider-using-in
                self.move_end()

            elif key in ("Q", "W", "E"):
                keys = ["Q", "W", "E"]
                key = str(2 ** (keys.index(key)))
                self.select_view(key)

            elif key == "v":
                self.mode_selection()

            elif key == ":":
                # command mode
                ret = self.command()
                if ret != 0:
                    return ret

            elif key == "?":
                # find backwards
                self.find_backwards()

            elif key == "/" or key == "Ctrl-F":  # pylint: disable=consider-using-in
                self.find()

            elif key == "n" or key == "Ctrl-G":  # pylint: disable=consider-using-in
                # search again
                if self.searchdir == HexWindow.FORWARD:
                    self.find(again=True)
                elif self.searchdir == HexWindow.BACKWARD:
                    self.find_backwards(again=True)

            elif key == "x" or key == "Ctrl-X":  # pylint: disable=consider-using-in
                self.find_hex()

            elif key == "^":  # pylint: disable=consider-using-in
                self.move_begin_line()

            elif key == "$":
                self.move_end_line()

            elif key == "H":
                self.move_top()

            elif key == "M":
                self.move_middle()

            elif key == "L":
                self.move_bottom()

            elif key == "@":
                self.jump_address()

            elif key == "+":
                self.plus_offset()

            elif key == "-":
                self.minus_offset()

            elif key == "m":
                self.copy_address()

            elif key == "w":
                self.move_word()

            elif key == "B":
                self.move_word_back()

            elif key == "p":
                self.print_values()

            elif key == "P":
                self.toggle_endianness()


class ValueSubWindow(textmode.Window):
    """subwindow that shows values"""

    BIG_ENDIAN = 1
    LITTLE_ENDIAN = 2

    def __init__(self, x, y, w, h, colors):
        """Initialize"""
        super().__init__(x, y, w, h, colors, "Values", border=True, shadow=False)
        if sys.byteorder == "big":
            self.endian = ValueSubWindow.BIG_ENDIAN
        else:
            self.endian = ValueSubWindow.LITTLE_ENDIAN

    def resize_event(self):
        """The terminal was resized"""
        # use fixed width and height, but
        # the position may change; stick to bottom

        self.frame.y = textmode.VIDEO.h - self.frame.h - 1
        if self.has_border:
            self.bounds.y = self.frame.y + 1
        else:
            self.bounds.y = self.frame.y

        self.rect.y = self.frame.y

    def draw(self):
        """Draw the value subwindow"""
        super().draw()

        # draw statusline
        self.update_status()

    def update(self, data):
        """Show the values for data"""
        int8 = struct.unpack_from("@b", data)[0]
        uint8 = struct.unpack_from("@B", data)[0]

        if self.endian == ValueSubWindow.BIG_ENDIAN:
            fmt = ">"
        elif self.endian == ValueSubWindow.LITTLE_ENDIAN:
            fmt = "<"
        else:
            fmt = "="

        int16 = struct.unpack_from(fmt + "h", data)[0]
        uint16 = struct.unpack_from(fmt + "H", data)[0]
        int32 = struct.unpack_from(fmt + "i", data)[0]
        uint32 = struct.unpack_from(fmt + "I", data)[0]
        int64 = struct.unpack_from(fmt + "q", data)[0]
        uint64 = struct.unpack_from(fmt + "Q", data)[0]
        float32 = struct.unpack_from(fmt + "f", data)[0]
        float64 = struct.unpack_from(fmt + "d", data)[0]

        line = " int8 : {:<20}  uint8 : {:<20}  0x{:02x}".format(int8, uint8, uint8)  # pylint: disable=(duplicate-string-formatting-argument
        self.puts(0, 0, line, self.colors.text)

        line = " int16: {:<20}  uint16: {:<20}  0x{:04x}".format(int16, uint16, uint16)  # pylint: disable=(duplicate-string-formatting-argument
        self.puts(0, 1, line, self.colors.text)

        line = " int32: {:<20}  uint32: {:<20}  0x{:08x}".format(int32, uint32, uint32)  # pylint: disable=(duplicate-string-formatting-argument
        self.puts(0, 2, line, self.colors.text)

        line = " int64: {:<20}  uint64: {:<20}  0x{:016x}".format(int64, uint64, uint64)  # pylint: disable=(duplicate-string-formatting-argument
        self.puts(0, 3, line, self.colors.text)

        line = " float: {:<20}  double: {:<20}  0x{:016x}".format(
            float32, float64, uint64
        )  # pylint: disable=(duplicate-string-formatting-argument
        self.puts(0, 4, line, self.colors.text)

    def update_status(self):
        """Redraw statusline"""
        if self.endian == ValueSubWindow.BIG_ENDIAN:
            text = " big endian "
        else:
            text = " little endian "

        w = len(text)

        textmode.VIDEO.hline(
            self.frame.x + self.frame.w - 20,
            self.frame.y + self.frame.h - 1,
            18,
            curses.ACS_HLINE,
            self.colors.border,
        )
        textmode.VIDEO.puts(
            self.frame.x + self.frame.w - w - 1,
            self.frame.y + self.frame.h - 1,
            text,
            self.colors.status,
        )


def bytearray_find_backwards(data, search, pos=-1):
    """
    search bytearray backwards for string
    Returns index if found or -1 if not found
    May raise ValueError for invalid search
    """
    if data is None or not data:
        raise ValueError

    if search is None or not search:
        raise ValueError

    if pos == -1:
        pos = len(data)

    if pos < 0:
        return ValueError

    pos -= len(search)
    while pos >= 0:
        if data[pos : pos + len(search)] == search:
            return pos

        pos -= 1

    return -1


def hex_inputfilter(key):
    """
    hexadecimal input filter
    Returns character or None if invalid
    """
    val = ord(key)
    if (
        ord("0") <= val <= ord("9")
        or ord("a") <= val <= ord("f")
        or ord("A") <= val <= ord("F")
        or val == ord(" ")
    ):
        if ord("a") <= val <= ord("f"):
            key = key.upper()
        return key

    return None


def isalphanum(ch):
    """Returns True if character is alphanumeric"""
    return (
        ord("0") <= ch <= ord("9")
        or ord("a") <= ch <= ord("z")
        or ord("A") <= ch <= ord("Z")
        or ch == ord("_")
    )


def isspace(ch):
    """Returns True if character is treated as space"""
    return not isalphanum(ch)


class CommandBar(textmode.CmdLine):
    """
    command bar
    Same as CmdLine, but backspace can exit the command mode
    """

    def __init__(self, colors, prompt=None, inputfilter=None):
        """Initialize"""
        x = 0
        y = textmode.VIDEO.h - 1
        w = textmode.VIDEO.w
        super().__init__(x, y, w, colors, prompt)

        if self.prompt is not None:
            x += len(self.prompt)
            w -= len(self.prompt)
            if w < 1:
                w = 1

        self.textfield = CommandField(
            self, x, self.bounds.y, w, colors, True, inputfilter
        )

    def resize_event(self):
        """The terminal was resized"""
        self.frame.w = self.bounds.w = self.rect.w = textmode.VIDEO.w
        self.frame.y = self.bounds.y = self.rect.y = textmode.VIDEO.h - 1

        w = textmode.VIDEO.w
        if self.prompt is not None:
            w -= len(self.prompt)
            if w < 1:
                w = 1

        self.textfield.y = textmode.VIDEO.h - 1
        self.textfield.w = w


class CommandField(textmode.TextField):
    """
    command bar edit field
    Same as TextField, but backspace can exit the command mode
    """

    def runloop(self):
        """
        run the CommandField
        Same as TextField, but backspace can exit
        """
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
                return textmode.RETURN_TO_PREVIOUS

            if key == KEY_BTAB:
                self.lose_focus()
                self.clear()
                return textmode.BACK

            if key == KEY_TAB:
                self.lose_focus()
                self.clear()
                return textmode.NEXT

            if key == KEY_RETURN:
                self.add_history()
                self.lose_focus()
                self.clear()
                return textmode.ENTER

            if key == KEY_BS:
                if self.cursor > 0:
                    self.text = self.text[: self.cursor - 1] + self.text[self.cursor :]
                    self.cursor -= 1
                    self.draw()

                elif self.cursor == 0 and not self.text:
                    # exit
                    self.lose_focus()
                    self.clear()
                    return textmode.RETURN_TO_PREVIOUS

            elif key == KEY_DEL:
                if self.cursor < len(self.text):
                    self.text = self.text[: self.cursor] + self.text[self.cursor + 1 :]
                    self.draw()

                elif self.cursor == 0 and not self.text:
                    # exit
                    self.lose_focus()
                    self.clear()
                    return textmode.RETURN_TO_PREVIOUS

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


class HelpWindow(textmode.TextWindow):
    """displays usage information"""

    def __init__(self, parent):
        """Initialize"""
        self.parent = parent

        text = """Command keys
 :                    Enter command mode
 /        Ctrl-F      Find
 ?                    Find backwards(NotWork)
 n        Ctrl-G      Find again
 x        Ctrl-X      Find hexadecimal

 Q                    View single bytes
 W                    View 16-bit words
 E                    View 32-bit words
 p                    Toggle printed values
 P                    Toggle endianness
 <                    Roll left
 >                    Roll right
 v                    Toggle selection mode

 @                    Jump to address
 m                    Mark; copy address to
                            jump history
 +                    Add offset
 -                    Minus offset

 hjkl     arrows      Move cursor
 Ctrl-U   PageUp      Go one page up
 Ctrl-D   PageDown    Go one page down
 g        Home        Go to top
 G        End         Go to end
 ^        0           Go to start of line
 $                    Go to end of line
 H                    Go to top of screen
 M                    Go to middle of screen
 L                    Go to bottom of screen
 w                    Go to next ASCII word
 B                    Go to previous ASCII word
                     
 Ctrl-R               Redraw screen
 Ctrl-Q               Force quit
 
Commands
 :^                   Go to top
 :print   :values     Toggle printed values
 :big                 Set big endian mode
 :little              Set little endian mode
 :load FILENAME       Load alternate file
 :help    :?          Show this information
 :license             Show software license
 :about   :version    Show About box
 :q       :q!         Quit"""

        colors = textmode.ColorSet(BLACK, WHITE)
        colors.title = textmode.video_color(RED, WHITE)
        colors.cursor = textmode.video_color(BLACK, GREEN)

        w = 52
        h = textmode.VIDEO.h - 6
        if h < 4:
            h = 4
        x = textmode.center_x(w, self.parent.frame.w)
        y = textmode.center_y(h, textmode.VIDEO.h)

        super().__init__(
            x,
            y,
            w,
            h,
            colors,
            title="Help",
            border=True,
            text=text.split("\n"),
            scrollbar=False,
            status=False,
        )

    def resize_event(self):
        """The terminal was resized"""
        w = self.frame.w
        h = textmode.VIDEO.h - 6
        if h < 4:
            h = 4
        x = textmode.center_x(w, self.parent.frame.w)
        y = textmode.center_y(h, textmode.VIDEO.h)

        self.frame = Rect(x, y, w, h)

        # bounds is the inner area; for view content
        if self.has_border:
            self.bounds = Rect(x + 1, y + 1, w - 2, h - 2)
        else:
            self.bounds = self.frame

        # rect is the outer area; larger because of shadow
        if self.has_shadow:
            self.rect = Rect(x, y, w + 2, h + 1)
        else:
            self.rect = Rect(x, y, w, h)

        if self.cursor >= self.bounds.h:
            self.cursor = self.bounds.h - 1

        if self.top > len(self.text) - self.bounds.h:
            self.top = len(self.text) - self.bounds.h
            if self.top < 0:
                self.top = 0

    def runloop(self):
        """Run the Help window"""
        # this is the same as for TextWindow, but the
        # hexview app uses some more navigation keys

        while True:
            key = getch()

            if key == KEY_ESC or key == " " or key == KEY_RETURN:  # pylint: disable=consider-using-in
                self.lose_focus()
                return textmode.RETURN_TO_PREVIOUS

            if key == KEY_UP or key == "k":  # pylint: disable=consider-using-in
                self.move_up()

            elif key == KEY_DOWN or key == "j":  # pylint: disable=consider-using-in
                self.move_down()

            elif key == KEY_PAGEUP or key == "Ctrl-U":  # pylint: disable=consider-using-in
                self.pageup()

            elif key == KEY_PAGEDOWN or key == "Ctrl-D":  # pylint: disable=consider-using-in
                self.pagedown()

            elif key == KEY_HOME or key == "g":  # pylint: disable=consider-using-in
                self.goto_top()

            elif key == KEY_END or key == "G":  # pylint: disable=consider-using-in
                self.goto_bottom()


class LicenseBox(textmode.Alert):
    """shows software license"""

    def __init__(self):
        """Initialize"""
        text = """Copyright (c) 2016 Walter de Jong <walter@heiho.net>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE."""

        colors = textmode.ColorSet(BLACK, WHITE)
        colors.title = textmode.video_color(RED, WHITE)
        colors.button = textmode.video_color(WHITE, BLUE, bold=True)
        colors.buttonhotkey = textmode.video_color(YELLOW, BLUE, bold=True)
        colors.activebutton = textmode.video_color(WHITE, GREEN, bold=True)
        colors.activebuttonhotkey = textmode.video_color(YELLOW, GREEN, bold=True)
        super().__init__(
            colors,
            "License",
            text,
            ["<D>ecline", "<A>ccept"],
            default=1,
            center_text=False,
        )


class AboutBox(textmode.Alert):
    """about box"""

    def __init__(self):
        """Initialize"""
        text = """HexView
--------{}
version {}

Copyright 2016 by
Walter de Jong <walter@heiho.net>

This is free software, available
under terms of the MIT license""".format("-" * len(VERSION), VERSION)

        colors = textmode.ColorSet(BLACK, WHITE)
        colors.title = textmode.video_color(RED, WHITE)
        colors.button = textmode.video_color(WHITE, BLUE, bold=True)
        colors.buttonhotkey = textmode.video_color(YELLOW, BLUE, bold=True)
        colors.activebutton = textmode.video_color(WHITE, GREEN, bold=True)
        colors.activebuttonhotkey = textmode.video_color(YELLOW, GREEN, bold=True)
        super().__init__(colors, "About", text)

    def draw(self):
        """Draw the About box"""
        super().draw()

        # draw pretty horizontal line in text
        w = len(VERSION) + 8
        x = self.bounds.x + textmode.center_x(w, self.bounds.w)
        textmode.VIDEO.hline(x, self.frame.y + 3, w, curses.ACS_HLINE, self.colors.text)


def hexview_main(filename, address):
    """Main program"""
    colors = textmode.ColorSet(BLACK, CYAN)
    colors.cursor = textmode.video_color(WHITE, BLACK, bold=True)
    colors.status = colors.cursor
    colors.invisibles = textmode.video_color(BLUE, CYAN, bold=True)

    view = HexWindow(0, 0, 80, textmode.VIDEO.h - 1, colors, None, True, address)
    try:
        view.load(filename)
    except OSError as err:
        textmode.terminate()
        print("{}: {}".format(filename, err.strerror))
        sys.exit(-1)

    view.show()

    textmode.VIDEO.puts(
        0,
        textmode.VIDEO.h - 1,
        "Enter :help for usage information",
        textmode.video_color(WHITE, BLACK),
    )
    view.runloop()


def short_usage():
    """Print short usage information and exit"""
    print("usage: {} [options] <filename>".format(os.path.basename(sys.argv[0])))
    sys.exit(1)


def usage():
    """Print usage information and exit"""
    print("usage: {} [options] <filename>".format(os.path.basename(sys.argv[0])))
    print(
        """options:
  -h, --help           Show this information
      --no-color       Disable colors
      --ascii-lines    Use plain ASCII for line drawing
      --no-lines       Disable all line drawing
      --no-hlines      Disable horizontal lines
      --no-vlines      Disable vertical lines
  -v, --version        Display version and exit
"""
    )
    sys.exit(1)


def get_options():
    """Parse command line options"""
    global OPT_LINEMODE

    try:
        opts, args = getopt.getopt(
            sys.argv[1:],
            "hpv",
            [
                "help",
                "no-color",
                "no-lines",
                "ascii-lines",
                "no-hlines",
                "no-vlines",
                "version",
                "pid",
                "memoryview",
            ],
        )
    except getopt.GetoptError:
        short_usage()

    for opt, _ in opts:
        if opt in ("-h", "--help"):
            usage()

        elif opt == "--no-color":
            textmode.WANT_COLORS = False

        elif opt == "--no-lines":
            OPT_LINEMODE = 0

        elif opt == "--ascii-lines":
            OPT_LINEMODE |= textmode.LM_ASCII

        elif opt == "--no-hlines":
            OPT_LINEMODE &= ~textmode.LM_HLINE

        elif opt == "--no-vlines":
            OPT_LINEMODE &= ~textmode.LM_VLINE

        elif opt in ("-v", "--version"):
            print("hexview version {}".format(VERSION))
            print("Copyright 2016 by Walter de Jong <walter@heiho.net>")
            sys.exit(1)
    name = "self"
    return name


def memory_view_mode(api, address):
    global API
    API = api
    filename_ = get_options()

    textmode.init()
    textmode.linemode(OPT_LINEMODE)

    try:
        hexview_main("self", address)
    except Exception as e:
        print(e)
    finally:
        input()
        textmode.terminate()


# EOB
