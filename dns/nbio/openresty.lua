-- Minimal compatibility layer for OpenResty
return function (M)

function M.socket(_, proto)
	return proto == 'stream' and ngx.socket.tcp() or ngx.socket.udp()
end

M.now = ngx.now
M.go = ngx.thread.spawn

-- Coroutines interface is empty as it's implemented by OpenResty
M.step = function () error('NYI: nbio.step()') end
M.run = function () error('NYI: nbio.run()') end

-- Export
M.backend = 'openresty'

end