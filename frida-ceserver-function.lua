openLuaServer('frida-ceserver')

local function ExecuteHexEditor()
    local address = getMemoryViewForm().HexadecimalView.SelectionStart;
    local hex = string.format("%x", address)
    local message = '{"command":"HexEditor","address":"' .. hex .. '"}'
    writeString(0xffffffffffffffff, message)
end

local function addMenuItem()
    local popupmenu = getMemoryViewForm().HexadecimalView.PopupMenu
    mi = createMenuItem(popupmenu)
    mi.Caption = '-'
    popupmenu.Items.add(mi)
    mi = createMenuItem(popupmenu)
    mi.Caption = "View in a hex editor like vim"
    mi.onClick = ExecuteHexEditor
    popupmenu.Items.add(mi)
end

function loadjs(number, code, filename)
    if filename == nil then
        filename = ""
    end
    local message = "?" .. filename
    writeString(number, code .. message)
end

function unloadjs(number)
    writeString(number, "UNLOAD")
end

addMenuItem()
