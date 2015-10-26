local utils = {}

-- Return DLL extension
function utils.dll_versioned(lib, ver)
	assert(jit)
	local fmt = {
		Windows = '%s.%s.dll',
		Linux = '%s.so.%s', BSD = '%s.so.%s', POSIX = '%s.so.%s', Other = '%s.so.%s',
		OSX = '%s.%s.dylib'
	}
	return string.format(fmt[jit.os], lib, ver)
end


-- Hexdump from http://lua-users.org/wiki/HexDump
function utils.hexdump(buf)
	for byte=1, #buf, 16 do
		local chunk = buf:sub(byte, byte+15)
		io.write(string.format('%08X  ',byte-1))
		chunk:gsub('.', function (c) io.write(string.format('%02X ',string.byte(c))) end)
		io.write(string.rep(' ',3*(16-#chunk)))
		io.write(' ',chunk:gsub('%c','.'),"\n") 
	end
end

return utils