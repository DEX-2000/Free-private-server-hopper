local md5, hmac, base64 = {}, {}, {}

--[[ MD5 Implementation (Simplified but retained) ]]
do
	local T = {
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
	}
	local A, B, C, D = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
	local ADD, ROL = bit32.bxor, bit32.bxor -- Placeholder/shorter names for bit32 functions
	local function add(a, b) local lsw = bit32.band(a, 0xFFFF) + bit32.band(b, 0xFFFF); local msw = bit32.rshift(a, 16) + bit32.rshift(b, 16) + bit32.rshift(lsw, 16); return bit32.bor(bit32.lshift(msw, 16), bit32.band(lsw, 0xFFFF)) end
	local function rol(x, n) return bit32.bor(bit32.lshift(x, n), bit32.rshift(x, 32 - n)) end
	local F, G, H, I = function(x, y, z) return bit32.bor(bit32.band(x, y), bit32.band(bit32.bnot(x), z)) end, function(x, y, z) return bit32.bor(bit32.band(x, z), bit32.band(y, bit32.bnot(z))) end, bit32.bxor, function(x, y, z) return bit32.bxor(y, bit32.bor(x, bit32.bnot(z))) end

	function md5.sum(m)
		local a, b, c, d = A, B, C, D
		local ml = #m
		local p = m .. "\128"
		while #p % 64 ~= 56 do p = p .. "\0" end
		local len_bytes = ""
		local len_bits = ml * 8
		for i = 0, 7 do len_bytes = len_bytes .. string.char(bit32.band(bit32.rshift(len_bits, i * 8), 0xFF)) end
		p = p .. len_bytes

		for i = 1, #p, 64 do
			local chunk = p:sub(i, i + 63)
			local X = {}
			for j = 0, 15 do
				local b1, b2, b3, b4 = chunk:byte(j * 4 + 1, j * 4 + 4)
				X[j] = bit32.bor(b1, bit32.lshift(b2, 8), bit32.lshift(b3, 16), bit32.lshift(b4, 24))
			end
			local aa, bb, cc, dd = a, b, c, d
			local s = { 7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21 }
			for j = 0, 63 do
				local f, k, si
				if j < 16 then f, k, si = F(b, c, d), j, j % 4
				elseif j < 32 then f, k, si = G(b, c, d), (1 + 5 * j) % 16, 4 + (j % 4)
				elseif j < 48 then f, k, si = H(b, c, d), (5 + 3 * j) % 16, 8 + (j % 4)
				else f, k, si = I(b, c, d), (7 * j) % 16, 12 + (j % 4) end
				local temp = add(add(add(a, f), X[k]), T[j + 1])
				local new_b = add(b, rol(temp, s[si + 1]))
				a, b, c, d = d, new_b, b, c
			end
			a, b, c, d = add(a, aa), add(b, bb), add(c, cc), add(d, dd)
		end
		local function th(n)
			local s = ""
			for i = 0, 3 do s = s .. string.char(bit32.band(bit32.rshift(n, i * 8), 0xFF)) end
			return s
		end
		return th(a) .. th(b) .. th(c) .. th(d)
	end
end

--[[ HMAC Implementation ]]
do
	function hmac.new(k, m, hf)
		if #k > 64 then k = hf(k) end
		local o, i = "", ""
		for idx = 1, 64 do
			local b = (idx <= #k and string.byte(k, idx)) or 0
			o = o .. string.char(bit32.bxor(b, 0x5C))
			i = i .. string.char(bit32.bxor(b, 0x36))
		end
		return hf(o .. hf(i .. m))
	end
end

--[[ Base64 Implementation ]]
do
	local b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	function base64.encode(d)
		local t = d:gsub(".", function(x)
			local r, v = "", x:byte()
			for i = 8, 1, -1 do r = r .. (v % 2 ^ i - v % 2 ^ (i - 1) > 0 and "1" or "0") end
			return r
		end) .. "0000"
		local encoded = t:gsub("%d%d%d?%d?%d?%d?", function(x)
			if #x < 6 then return "" end
			local c = 0
			for i = 1, 6 do c = c + (x:sub(i, i) == "1" and 2 ^ (6 - i) or 0) end
			return b:sub(c + 1, c + 1)
		end)
		return encoded .. ({ "", "==", "=" })[#d % 3 + 1]
	end
end

--[[ Reserved Server Code Generation & Execution ]]
local function GRS(p)
	local u = {}
	for i = 1, 16 do u[i] = math.random(0, 255) end
	u[7] = bit32.bor(bit32.band(u[7], 0x0F), 0x40)
	u[9] = bit32.bor(bit32.band(u[9], 0x3F), 0x80)

	local fb = ""
	for i = 1, 16 do fb = fb .. string.char(u[i]) end

	local gameCode = string.format("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", table.unpack(u))

	local pb = ""
	local pR = p
	for _ = 1, 8 do
		pb = pb .. string.char(pR % 256)
		pR = math.floor(pR / 256)
	end

	local c = fb .. pb
	local key = "e4Yn8ckbCJtw2sv7qmbg"
	local s = hmac.new(key, c, md5.sum)
	local acb = s .. c
	local ac = base64.encode(acb)
	ac = ac:gsub("+", "-"):gsub("/", "_")

	local pdding = 0
	ac, _ = ac:gsub("=", function() pdding = pdding + 1 return "" end)
	ac = ac .. tostring(pdding)

	return ac, gameCode
end

local accessCode, _ = GRS(game.PlaceId)
game.RobloxReplicatedStorage.ContactListIrisInviteTeleport:FireServer(game.PlaceId, "", accessCode)
