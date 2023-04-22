function loadjs(number,code,filename)
	if filename == nil then
		filename = ""
	end
	local message = "?"..filename
	writeString(number,code..message)
end

function unloadjs(number)
	writeString(number,"UNLOAD")
end