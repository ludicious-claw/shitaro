if not LPH_OBFUSCATED then
	local a = function() end
	local g = getgenv and getgenv() or _G
	g.LPH_ATTRIBUTES = a
	g.ENCRYPT, g.VM, g.PRESET, g.OPTIMIZE, g.TRANSFORM, g.ERROR_HANDLING = a, a, a, a, a, a
	g.UNROLL, g.INLINE, g.NO_UPVALUES = a, a, a
	g.NONE, g.OPAL, g.ONYX, g.FAST, g.BALANCED, g.SECURE = a, a, a, a, a, a
	g.EXTRACT, g.CONTROL_FLOW, g.REWRITE_NAMECALLS, g.GLOBALS, g.CONSTANTS = a, a, a, a, a
end
local shhttp = rawget(getfenv(), "request")
	or (syn and syn.request)
	or (http and http.request)
	or (fluxus and fluxus.request)
	or (getgenv and getgenv().request)

if type(shhttp) ~= "function" then
	shhttp = function()
		return nil
	end
end

local shjson = game:GetService("HttpService")
local shnet = {}

--============================================================
-- KEYLESS BUILD
-- The Jnkie license gate (verifyOpen SDK + SCRIPT_KEY + the
-- 60s revalidation thread + the LocalPlayer:Kick path) is gone.
-- No network, no key, no kick. Same local API surface so the
-- rest of the script keeps working unchanged.
--============================================================
local shkey = {
	alive = true,
	reason = "KEYLESS",
	value = "FREE",
	unload = nil,
}

function shkey.bind(fn)
	if type(fn) == "function" then
		shkey.unload = fn
	end
end

function shkey.stop()
	shkey.alive = false
end

function shkey.watch()
	shkey.alive = true
end

function shkey.open()
	local genv = getgenv()
	local prev = genv.SHKEY

	if type(prev) == "table" and type(prev.stop) == "function" then
		pcall(prev.stop)
	end

	shkey.alive = true
	shkey.reason = "KEYLESS"

	genv.SCRIPT_KEY = shkey.value
	genv.SHKEY = shkey
	genv.JD_IS_PREMIUM = true
	genv.JD_REASON = "KEYLESS"

	shkey.watch()

	return true
end

if not shkey.open() then
	return
end

do
	local band, bxor, bnot = bit32.band, bit32.bxor, bit32.bnot
	local rrot, rshift = bit32.rrotate, bit32.rshift
	local schar, sbyte, srep, ssub = string.char, string.byte, string.rep, string.sub
	local tconcat = table.concat
	local floor = math.floor

	local K = {
		0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
		0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
		0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
		0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
		0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
		0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
		0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
		0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
	}

	local function sha256(msg)
		local h1,h2,h3,h4,h5,h6,h7,h8 =
			0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
			0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19

		local L = #msg
		local bitLenLo = (L * 8) % 4294967296
		local bitLenHi = floor((L * 8) / 4294967296)
		local pad = (56 - (L + 1) % 64) % 64
		msg = msg .. "\128" .. srep("\0", pad)
			.. schar(
				floor(bitLenHi / 16777216) % 256,
				floor(bitLenHi / 65536) % 256,
				floor(bitLenHi / 256) % 256,
				bitLenHi % 256,
				floor(bitLenLo / 16777216) % 256,
				floor(bitLenLo / 65536) % 256,
				floor(bitLenLo / 256) % 256,
				bitLenLo % 256
			)

		local W = table.create and table.create(64, 0) or {}
		for chunk = 1, #msg, 64 do
			for i = 0, 15 do
				local o = chunk + i * 4
				W[i+1] = sbyte(msg, o) * 16777216 + sbyte(msg, o+1) * 65536 + sbyte(msg, o+2) * 256 + sbyte(msg, o+3)
			end
			for i = 17, 64 do
				local w15 = W[i-15]
				local w2 = W[i-2]
				local s0 = bxor(rrot(w15, 7), rrot(w15, 18), rshift(w15, 3))
				local s1 = bxor(rrot(w2, 17), rrot(w2, 19), rshift(w2, 10))
				W[i] = (W[i-16] + s0 + W[i-7] + s1) % 4294967296
			end
			local a,b,c,d,e,f,g,hh = h1,h2,h3,h4,h5,h6,h7,h8
			for i = 1, 64 do
				local S1 = bxor(rrot(e, 6), rrot(e, 11), rrot(e, 25))
				local ch = bxor(band(e, f), band(bnot(e), g))
				local t1 = (hh + S1 + ch + K[i] + W[i]) % 4294967296
				local S0 = bxor(rrot(a, 2), rrot(a, 13), rrot(a, 22))
				local mj = bxor(band(a, b), band(a, c), band(b, c))
				local t2 = (S0 + mj) % 4294967296
				hh = g; g = f; f = e; e = (d + t1) % 4294967296
				d = c; c = b; b = a; a = (t1 + t2) % 4294967296
			end
			h1 = (h1 + a) % 4294967296
			h2 = (h2 + b) % 4294967296
			h3 = (h3 + c) % 4294967296
			h4 = (h4 + d) % 4294967296
			h5 = (h5 + e) % 4294967296
			h6 = (h6 + f) % 4294967296
			h7 = (h7 + g) % 4294967296
			h8 = (h8 + hh) % 4294967296
		end

		local function w4(v)
			return schar(floor(v / 16777216) % 256, floor(v / 65536) % 256, floor(v / 256) % 256, v % 256)
		end
		return w4(h1)..w4(h2)..w4(h3)..w4(h4)..w4(h5)..w4(h6)..w4(h7)..w4(h8)
	end

	local function hmac256(key, msg)
		if #key > 64 then key = sha256(key) end
		if #key < 64 then key = key .. srep("\0", 64 - #key) end
		local outer, inner = {}, {}
		for j = 1, 64 do
			local kb = sbyte(key, j)
			outer[j] = schar(bxor(kb, 0x5c))
			inner[j] = schar(bxor(kb, 0x36))
		end
		return sha256(tconcat(outer) .. sha256(tconcat(inner) .. msg))
	end

	local b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	local function b64url_enc(s)
		local out, oi = {}, 0
		local n = #s
		local i = 1
		while i <= n do
			local a = sbyte(s, i)
			local b = sbyte(s, i+1)
			local c = sbyte(s, i+2)
			local trip = a * 65536 + (b or 0) * 256 + (c or 0)
			oi = oi + 1; out[oi] = ssub(b64chars, floor(trip / 262144) + 1, floor(trip / 262144) + 1)
			oi = oi + 1; out[oi] = ssub(b64chars, floor(trip / 4096) % 64 + 1, floor(trip / 4096) % 64 + 1)
			if b then
				oi = oi + 1; out[oi] = ssub(b64chars, floor(trip / 64) % 64 + 1, floor(trip / 64) % 64 + 1)
			end
			if c then
				oi = oi + 1; out[oi] = ssub(b64chars, trip % 64 + 1, trip % 64 + 1)
			end
			i = i + 3
		end
		return tconcat(out)
	end

	local b64map = {}
	for i = 1, 64 do
		local ch = ssub("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", i, i)
		b64map[ch] = i - 1
	end
	local function b64url_dec(s)
		s = (s:gsub("-", "+"):gsub("_", "/"):gsub("[^A-Za-z0-9+/=]", ""))
		local pad = (4 - #s % 4) % 4
		s = s .. srep("=", pad)
		local out, oi = {}, 0
		for i = 1, #s, 4 do
			local a = b64map[ssub(s, i, i)] or 0
			local b = b64map[ssub(s, i+1, i+1)] or 0
			local c = b64map[ssub(s, i+2, i+2)] or 0
			local d = b64map[ssub(s, i+3, i+3)] or 0
			local n = a*262144 + b*4096 + c*64 + d
			oi = oi + 1; out[oi] = schar(floor(n / 65536) % 256)
			if ssub(s, i+2, i+2) ~= "=" then
				oi = oi + 1; out[oi] = schar(floor(n / 256) % 256)
			end
			if ssub(s, i+3, i+3) ~= "=" then
				oi = oi + 1; out[oi] = schar(n % 256)
			end
		end
		return tconcat(out)
	end

	local function hex2bin(h)
		return (h:gsub("..", function(hh) return schar(tonumber(hh, 16)) end))
	end

	local libKey = hex2bin("02d417c2bd7b033a00d3c4e9fda43fc56761f68f516cf68a68a6110f2cb99e49")
	local rng = Random.new((tick() * 1e6) % 2147483647 + os.time())

	local function randBytes(n)
		local t = {}
		for i = 1, n do t[i] = schar(rng:NextInteger(0, 255)) end
		return tconcat(t)
	end

	local function be64(v)
		local t = {}
		for i = 8, 1, -1 do t[i] = schar(v % 256); v = floor(v / 256) end
		return tconcat(t)
	end

	local function escape(s)
		return (string.gsub(s, "[^%w%-%._~/]", function(c)
			return string.format("%%%02X", string.byte(c))
		end))
	end

	local lshift, rshift32, band32 = bit32.lshift, bit32.rshift, bit32.band

	local function stream(seed)
		local function word(i)
			local a, b, c, d = sbyte(seed, i, i + 3)
			return d * 16777216 + c * 65536 + b * 256 + a
		end

		local s0, s1, s2, s3 = word(1), word(5), word(9), word(13)

		if s0 == 0 and s1 == 0 and s2 == 0 and s3 == 0 then
			s0, s1, s2, s3 = 0x9e3779b9, 0x243f6a88, 0xb7e15162, 0x85ebca6b
		end

		return function()
			local t = s0
			t = bxor(t, lshift(t, 11))
			t = bxor(t, rshift32(t, 8))
			s0, s1, s2 = s1, s2, s3
			local u = s3
			u = bxor(u, rshift32(u, 19))
			u = bxor(u, t)
			s3 = u
			return u
		end
	end

	local function unmask(body, nonce)
		local nextWord = stream(hmac256(libKey, "SHITARO-ASSET-MASK-v1\0" .. nonce))
		local n = #body

		if buffer and buffer.fromstring then
			local buf = buffer.fromstring(body)
			local i = 0

			while i + 4 <= n do
				buffer.writeu32(buf, i, bxor(buffer.readu32(buf, i), nextWord()))
				i = i + 4
			end

			if i < n then
				local k = nextWord()
				local j = 0

				while i + j < n do
					buffer.writeu8(buf, i + j, bxor(buffer.readu8(buf, i + j), band32(rshift32(k, j * 8), 255)))
					j = j + 1
				end
			end

			return buffer.tostring(buf)
		end

		local out, oi = {}, 0
		local i = 1

		while i <= n do
			local k = nextWord()

			for j = 0, 3 do
				if i + j <= n then
					oi = oi + 1
					out[oi] = schar(bxor(sbyte(body, i + j), band32(rshift32(k, j * 8), 255)))
				end
			end

			i = i + 4
		end

		return tconcat(out)
	end

	local function signed(base, kind, name)
		local nonce = randBytes(16)
		local tsb = be64(os.time())
		local tok = b64url_enc(nonce .. tsb .. hmac256(libKey, "SHITARO-" .. kind .. "-REQ-v1\0" .. name .. "\0" .. nonce .. "\0" .. tsb))

		local ok, resp = pcall(shhttp, {
			Url = base .. escape(name),
			Method = "GET",
			Headers = {
				["X-Shitaro-Token"] = tok,
				["Accept"] = "*/*",
				["Cache-Control"] = "no-cache",
			},
		})

		if not ok or type(resp) ~= "table" or resp.StatusCode ~= 200 then
			return nil
		end

		local body = resp.Body

		if type(body) ~= "string" or #body == 0 then
			return nil
		end

		local hd = resp.Headers or {}
		local sigStr = hd["X-Shitaro-Sig"] or hd["x-shitaro-sig"] or ""

		if sigStr == "" then
			return nil
		end

		if b64url_dec(sigStr) ~= hmac256(libKey, "SHITARO-" .. kind .. "-RESP-v1\0" .. name .. "\0" .. nonce .. "\0" .. be64(#body) .. body) then
			return nil
		end

		if kind == "ASSET" then
			return unmask(body, nonce)
		end

		return body
	end

	function shnet.lib(name)
		return signed("https://shitaro.lol/api/library/", "LIB", name)
	end

	function shnet.asset(name)
		return signed("https://shitaro.lol/api/assets/", "ASSET", name)
	end
end

local shblob

do
	local bxor, lrotate, lshift, rshift, band = bit32.bxor, bit32.lrotate, bit32.lshift, bit32.rshift, bit32.band
	local sbyte, schar, ssub, tconcat = string.byte, string.char, string.sub, table.concat

	local vault = {
		0x5B, 0x27, 0xE4, 0x91, 0x0C, 0xBD, 0x7A, 0x36,
		0xF1, 0x48, 0x92, 0xAE, 0x63, 0xD5, 0x1F, 0x8C,
		0x2A, 0x74, 0xB0, 0x59, 0xEE, 0x13, 0xC7, 0x6D,
		0x9F, 0x35, 0x88, 0x4C, 0xA1, 0x70, 0xDB, 0x26,
	}

	local seeds = {
		{ 0x9E3779B9, 0x85EBCA6B },
		{ 0x243F6A88, 0xC2B2AE35 },
		{ 0xB7E15162, 0x27D4EB2F },
		{ 0x85EBCA6B, 0x165667B1 },
	}

	local lut = nil

	local function alphabet()
		if lut then
			return lut
		end

		local abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
		lut = {}

		for i = 1, #abc do
			lut[sbyte(abc, i)] = i - 1
		end

		return lut
	end

	local function unb64(text)
		local tbl = alphabet()
		local out, n = {}, 0
		local acc, bits = 0, 0

		for i = 1, #text do
			local c = sbyte(text, i)
			local v = tbl[c]

			if v then
				acc = acc * 64 + v
				bits = bits + 6

				if bits >= 8 then
					bits = bits - 8
					local div = 2 ^ bits
					local byte = math.floor(acc / div)
					acc = acc - byte * div
					n = n + 1
					out[n] = schar(byte % 256)
				end
			elseif c ~= 61 and c ~= 10 and c ~= 13 and c ~= 32 and c ~= 9 then
				return nil
			end
		end

		return tconcat(out)
	end

	local function churn(feed, init, salt)
		local h = init

		for i = 1, #feed do
			h = bxor(h, feed[i])
			h = lrotate(h, 7)
			h = bxor(h, salt)
		end

		return h
	end

	local function flow(nonce)
		local feed = table.create(#vault + #nonce)

		for i = 1, #vault do
			feed[i] = vault[i]
		end

		for i = 1, #nonce do
			feed[#vault + i] = sbyte(nonce, i)
		end

		local s0 = churn(feed, seeds[1][1], seeds[1][2])
		local s1 = churn(feed, seeds[2][1], seeds[2][2])
		local s2 = churn(feed, seeds[3][1], seeds[3][2])
		local s3 = churn(feed, seeds[4][1], seeds[4][2])

		if s0 == 0 and s1 == 0 and s2 == 0 and s3 == 0 then
			s0, s1, s2, s3 = 0x9E3779B9, 0x243F6A88, 0xB7E15162, 0x85EBCA6B
		end

		return function()
			local t = s0
			t = bxor(t, lshift(t, 11))
			t = bxor(t, rshift(t, 8))
			s0, s1, s2 = s1, s2, s3
			local u = s3
			u = bxor(u, rshift(u, 19))
			u = bxor(u, t)
			s3 = u
			return u
		end
	end

	local function peel(nonce, body)
		local nextWord = flow(nonce)
		local n = #body

		if buffer and buffer.fromstring then
			local buf = buffer.fromstring(body)
			local i = 0

			while i + 4 <= n do
				buffer.writeu32(buf, i, bxor(buffer.readu32(buf, i), nextWord()))
				i = i + 4
			end

			if i < n then
				local k = nextWord()
				local j = 0

				while i + j < n do
					buffer.writeu8(buf, i + j, bxor(buffer.readu8(buf, i + j), band(rshift(k, j * 8), 255)))
					j = j + 1
				end
			end

			return buffer.tostring(buf)
		end

		local out, oi = {}, 0
		local i = 1

		while i <= n do
			local k = nextWord()

			for j = 0, 3 do
				if i + j <= n then
					oi = oi + 1
					out[oi] = schar(bxor(sbyte(body, i + j), band(rshift(k, j * 8), 255)))
				end
			end

			i = i + 4
		end

		return tconcat(out)
	end

	local function stamp(text)
		local h = 0x243F6A88
		local n = #text
		local i = 1

		while i + 7 <= n do
			local b1, b2, b3, b4, b5, b6, b7, b8 = sbyte(text, i, i + 7)
			h = bxor(lrotate(bxor(h, b1), 7), 0x9E3779B9)
			h = bxor(lrotate(bxor(h, b2), 7), 0x9E3779B9)
			h = bxor(lrotate(bxor(h, b3), 7), 0x9E3779B9)
			h = bxor(lrotate(bxor(h, b4), 7), 0x9E3779B9)
			h = bxor(lrotate(bxor(h, b5), 7), 0x9E3779B9)
			h = bxor(lrotate(bxor(h, b6), 7), 0x9E3779B9)
			h = bxor(lrotate(bxor(h, b7), 7), 0x9E3779B9)
			h = bxor(lrotate(bxor(h, b8), 7), 0x9E3779B9)
			i = i + 8
		end

		while i <= n do
			h = bxor(lrotate(bxor(h, sbyte(text, i)), 7), 0x9E3779B9)
			i = i + 1
		end

		return h
	end

	shblob = function(data)
		if type(data) ~= "string" or #data < 11 then
			return nil
		end

		local raw = data

		if sbyte(raw, 1) ~= 0x53 then
			raw = unb64(data)

			if type(raw) ~= "string" or #raw < 11 then
				return nil
			end
		end

		if sbyte(raw, 1) ~= 0x53 then
			return nil
		end

		local ver = sbyte(raw, 2)

		if ver ~= 1 and ver ~= 2 then
			return nil
		end

		local a, b, c, d = sbyte(raw, 7, 10)
		local plain = peel(ssub(raw, 3, 6), ssub(raw, 11))

		if stamp(plain) ~= d * 16777216 + c * 65536 + b * 256 + a then
			return nil
		end

		return plain
	end
end

local shcontent = game:GetService("ContentProvider")

local assetIds = {}
local assetTemps = {}
local assetIndex = nil
local assetProbed = false
local assetKeep = false
local assetBook = nil
local assetNames = nil

local function assetParse(raw)
	if type(raw) ~= "string" or #raw == 0 then
		return nil
	end

	local ok, tbl = pcall(function()
		return shjson:JSONDecode(raw)
	end)

	if ok and type(tbl) == "table" and type(tbl.f) == "table" then
		return tbl
	end

	return nil
end

local assetLedger = string.char(98, 53, 51, 50, 50, 55, 102, 48, 100, 97, 46, 112, 110, 103)

local function assetBind()
	if assetBook then
		return assetBook
	end

	local plain = shblob(shnet.asset(assetLedger))

	if type(plain) ~= "string" or #plain == 0 then
		return nil
	end

	local book, names = {}, {}

	for line in string.gmatch(plain, "([^\n]+)") do
		local logical, server, size, kind = string.match(line, "^(.-)\t(.-)\t(%d+)\t(%a+)$")
		local bytes = tonumber(size)

		if logical and logical ~= "" and server and server ~= "" and bytes and bytes > 0 then
			book[logical] = { srv = server, size = bytes, kind = kind }

			if kind ~= "data" then
				names[#names + 1] = logical
			end
		end
	end

	if not next(book) then
		return nil
	end

	table.sort(names)

	assetBook, assetNames = book, names

	return book
end

local function assetRows()
	local book = assetBind()

	if book then
		local out = {}

		for i = 1, #assetNames do
			local entry = book[assetNames[i]]
			out[i] = { n = assetNames[i], s = entry.size }
		end

		return out
	end

	if assetIndex then
		return assetIndex.f
	end

	local got = assetParse(shnet.asset("index"))

	if got then
		assetIndex = got

		return got.f
	end

	return {}
end

local function assetSize(name)
	local book = assetBind()

	if book then
		local entry = book[name]

		return entry and entry.size or nil
	end

	if not assetIndex then
		return nil
	end

	for _, e in ipairs(assetIndex.f) do
		if type(e) == "table" and e.n == name then
			return e.s
		end
	end
end

local function assetCustom()
	return getcustomasset
		or getsynasset
		or (syn and syn.get_custom_asset)
		or (fluxus and fluxus.get_custom_asset)
end

local function assetKind(name)
	if string.match(name, "%.mp3$") or string.match(name, "%.wav$") or string.match(name, "%.ogg$") then
		return "sound"
	end

	return "image"
end

local function assetReady(id, kind)
	local holder

	if kind == "sound" then
		holder = Instance.new("Sound")
		holder.SoundId = id
	else
		holder = Instance.new("ImageLabel")
		holder.Image = id
	end

	local state = nil

	pcall(function()
		shcontent:PreloadAsync({ holder }, function(_, st)
			state = st
		end)
	end)

	pcall(function()
		holder:Destroy()
	end)

	return state == Enum.AssetFetchStatus.Success
end

local function assetDrop(path)
	if type(delfile) ~= "function" then
		return false
	end

	return pcall(delfile, path) == true
end

local function assetSlot(name)
	local ext = string.match(name, "(%.%w+)$") or ""

	return string.format("shv_%08x%08x%s", math.random(0, 268435455), math.random(0, 268435455), ext)
end

local function assetMake(name, data)
	local custom = assetCustom()

	if type(custom) ~= "function" or type(writefile) ~= "function" then
		return nil
	end

	local kind = assetKind(name)
	local path = assetSlot(name)

	if not pcall(writefile, path, data) then
		return nil
	end

	local ok, id = pcall(custom, path)

	if not ok or type(id) ~= "string" or id == "" then
		assetDrop(path)
		return nil
	end

	assetReady(id, kind)

	if not assetProbed and not assetKeep then
		assetProbed = true

		if assetDrop(path) then
			if assetReady(id, kind) then
				return id
			end

			assetKeep = true

			if not pcall(writefile, path, data) then
				return nil
			end

			local again, fresh = pcall(custom, path)

			if not again or type(fresh) ~= "string" or fresh == "" then
				return nil
			end

			id = fresh
			assetReady(id, kind)
		else
			assetKeep = true
		end
	end

	if assetKeep or not assetDrop(path) then
		assetTemps[#assetTemps + 1] = path
	end

	return id
end

local function assetGet(name)
	if type(name) ~= "string" or name == "" then
		return nil
	end

	name = string.gsub(name, "\\", "/")
	name = string.gsub(name, "^%./", "")

	local hit = assetIds[name]

	if hit then
		return hit
	end

	local book = assetBind()
	local entry = book and book[name]
	local data = shnet.asset(entry and entry.srv or name)

	if type(data) ~= "string" or #data == 0 then
		return nil
	end

	if entry then
		data = shblob(data)

		if type(data) ~= "string" or #data ~= entry.size then
			return nil
		end
	else
		local size = assetSize(name)

		if type(size) == "number" and size > 0 and #data ~= size then
			return nil
		end
	end

	local id = assetMake(name, data)
	data = nil

	if id then
		assetIds[name] = id
	end

	return id
end

local function assetPurge()
	if type(delfile) ~= "function" then
		return
	end

	local stale = { "assets/shitaro_index.dat", "assets/cloud_accent.png" }

	for _, e in ipairs(assetRows()) do
		if type(e) == "table" and type(e.n) == "string" then
			stale[#stale + 1] = string.find(e.n, "/", 1, true) and e.n or ("assets/" .. e.n)
		end
	end

	for _, p in ipairs(stale) do
		if type(isfile) == "function" then
			local ok, has = pcall(isfile, p)

			if ok and has then
				pcall(delfile, p)
			end
		end
	end

	if type(listfiles) ~= "function" then
		return
	end

	local ok, entries = pcall(listfiles, "")

	if not ok or type(entries) ~= "table" then
		return
	end

	for _, f in ipairs(entries) do
		local nm = string.match(string.gsub(tostring(f), "\\", "/"), "([^/]+)$")

		if nm and (string.match(nm, "^shitaro_snd_%d+") or string.match(nm, "^shv_%x+")) then
			pcall(delfile, nm)
		end
	end
end

local function assetFlush()
	for i = #assetTemps, 1, -1 do
		assetDrop(assetTemps[i])
		assetTemps[i] = nil
	end
end

getgenv().shitaro_asset = assetGet

getgenv().shitaro_data = function(name)
	local book = assetBind()
	local entry = book and book[name]

	if not entry then
		return nil
	end

	local plain = shblob(shnet.asset(entry.srv))

	if type(plain) ~= "string" or #plain ~= entry.size then
		return nil
	end

	return plain
end

getgenv().shitaro_assetlist = function(prefix)
	local out = {}

	for _, e in ipairs(assetRows()) do
		if type(e) == "table" and type(e.n) == "string" then
			if type(prefix) ~= "string" or prefix == "" or string.sub(e.n, 1, #prefix) == prefix then
				out[#out + 1] = e.n
			end
		end
	end

	return out
end

getgenv().shitaro_volatile = function(path, id, kind)
	if type(path) ~= "string" or type(id) ~= "string" or id == "" then
		return id
	end

	kind = kind == "sound" and "sound" or "image"

	assetReady(id, kind)

	if assetKeep or not assetDrop(path) then
		assetTemps[#assetTemps + 1] = path
	end

	return id
end

getgenv().shitaro_assetflush = assetFlush

task.spawn(assetPurge)

local cloudAssetPath = "assets/cloud.png"

local cloudIconPath = "assets/cloud_accent.png"

local pngRecolorWhite

do
	local floor = math.floor
	local unpack = table.unpack or unpack

	local function slowXor(a, b)
		local r, bit = 0, 1
		while a > 0 or b > 0 do
			local ab, bb = a % 2, b % 2
			if ab ~= bb then r = r + bit end
			a = (a - ab) / 2
			b = (b - bb) / 2
			bit = bit * 2
		end
		return r
	end

	local bxor = (bit32 and bit32.bxor) or slowXor

	local crcTable

	local function crc32(s)
		if not crcTable then
			crcTable = {}
			for i = 0, 255 do
				local c = i
				for _ = 1, 8 do
					if c % 2 == 1 then
						c = bxor(floor(c / 2), 3988292384)
					else
						c = floor(c / 2)
					end
				end
				crcTable[i] = c
			end
		end

		local crc = 4294967295
		for i = 1, #s do
			crc = bxor(crcTable[bxor(crc % 256, string.byte(s, i))], floor(crc / 256))
		end
		return bxor(crc, 4294967295)
	end

	local LBASE = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258}
	local LEXT = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0}
	local DBASE = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577}
	local DEXT = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13}
	local CLORDER = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15}

	local function inflate(data, startPos)
		local pos = startPos
		local buf, cnt = 0, 0
		local out, outn = {}, 0

		local function bits(n)
			if n == 0 then return 0 end
			while cnt < n do
				buf = buf + (string.byte(data, pos) or 0) * 2 ^ cnt
				pos = pos + 1
				cnt = cnt + 8
			end
			local v = buf % 2 ^ n
			buf = (buf - v) / 2 ^ n
			cnt = cnt - n
			return v
		end

		local function build(lengths, n)
			local count, symbol = {}, {}
			for i = 0, 15 do count[i] = 0 end
			for i = 0, n - 1 do
				local l = lengths[i] or 0
				count[l] = count[l] + 1
			end
			count[0] = 0
			local offs = {}
			offs[1] = 0
			for l = 1, 15 do offs[l + 1] = offs[l] + count[l] end
			for i = 0, n - 1 do
				local l = lengths[i] or 0
				if l ~= 0 then
					symbol[offs[l]] = i
					offs[l] = offs[l] + 1
				end
			end
			return { count = count, symbol = symbol }
		end

		local function decode(h)
			local code, first, index = 0, 0, 0
			for len = 1, 15 do
				code = code + bits(1)
				local c = h.count[len]
				if code - c < first then
					return h.symbol[index + (code - first)]
				end
				index = index + c
				first = (first + c) * 2
				code = code * 2
			end
			return nil
		end

		local fixedL, fixedD

		while true do
			local last = bits(1)
			local btype = bits(2)

			if btype == 0 then
				buf, cnt = 0, 0
				local len = (string.byte(data, pos) or 0) + (string.byte(data, pos + 1) or 0) * 256
				pos = pos + 4
				for _ = 1, len do
					outn = outn + 1
					out[outn] = string.byte(data, pos) or 0
					pos = pos + 1
				end
			elseif btype == 1 or btype == 2 then
				local lcodes, dcodes

				if btype == 1 then
					if not fixedL then
						local l = {}
						for i = 0, 143 do l[i] = 8 end
						for i = 144, 255 do l[i] = 9 end
						for i = 256, 279 do l[i] = 7 end
						for i = 280, 287 do l[i] = 8 end
						fixedL = build(l, 288)
						local d = {}
						for i = 0, 29 do d[i] = 5 end
						fixedD = build(d, 30)
					end
					lcodes, dcodes = fixedL, fixedD
				else
					local hlit = bits(5) + 257
					local hdist = bits(5) + 1
					local hclen = bits(4) + 4
					local cl = {}
					for i = 0, 18 do cl[i] = 0 end
					for i = 1, hclen do cl[CLORDER[i]] = bits(3) end
					local clh = build(cl, 19)
					local lens = {}
					local i = 0
					while i < hlit + hdist do
						local sym = decode(clh)
						if sym == nil then return nil end
						if sym < 16 then
							lens[i] = sym
							i = i + 1
						elseif sym == 16 then
							local prev = lens[i - 1] or 0
							for _ = 1, 3 + bits(2) do
								lens[i] = prev
								i = i + 1
							end
						elseif sym == 17 then
							for _ = 1, 3 + bits(3) do
								lens[i] = 0
								i = i + 1
							end
						else
							for _ = 1, 11 + bits(7) do
								lens[i] = 0
								i = i + 1
							end
						end
					end
					local ll, dl = {}, {}
					for j = 0, hlit - 1 do ll[j] = lens[j] or 0 end
					for j = 0, hdist - 1 do dl[j] = lens[hlit + j] or 0 end
					lcodes = build(ll, hlit)
					dcodes = build(dl, hdist)
				end

				while true do
					local sym = decode(lcodes)
					if sym == nil then return nil end
					if sym < 256 then
						outn = outn + 1
						out[outn] = sym
					elseif sym == 256 then
						break
					else
						sym = sym - 256
						if sym > 29 then return nil end
						local length = LBASE[sym] + bits(LEXT[sym])
						local dsym = decode(dcodes)
						if dsym == nil or dsym > 29 then return nil end
						local dist = DBASE[dsym + 1] + bits(DEXT[dsym + 1])
						local from = outn - dist
						if from < 0 then return nil end
						for k = 1, length do
							outn = outn + 1
							out[outn] = out[from + k]
						end
					end
				end
			else
				return nil
			end

			if last == 1 then break end
		end

		return out, outn
	end

	local function bytesToString(t, n)
		local parts, p = {}, 0
		local i = 1
		while i <= n do
			local j = i + 2047
			if j > n then j = n end
			p = p + 1
			parts[p] = string.char(unpack(t, i, j))
			i = j + 1
		end
		return table.concat(parts)
	end

	local function u32(v)
		return string.char(floor(v / 16777216) % 256, floor(v / 65536) % 256, floor(v / 256) % 256, v % 256)
	end

	local function pngChunk(typ, data)
		return u32(#data) .. typ .. data .. u32(crc32(typ .. data))
	end

	pngRecolorWhite = function(data, maxSize)
		if type(data) ~= "string" or string.sub(data, 1, 8) ~= "\137PNG\13\10\26\10" then
			return nil
		end

		local pos = 9
		local w, h, depth, ctype, interlace
		local idat = {}

		while pos + 8 <= #data + 1 do
			local b1, b2, b3, b4 = string.byte(data, pos, pos + 3)
			local len = ((b1 * 256 + b2) * 256 + b3) * 256 + b4
			local typ = string.sub(data, pos + 4, pos + 7)
			local body = string.sub(data, pos + 8, pos + 7 + len)

			if typ == "IHDR" then
				local p = string.byte
				w = ((p(body, 1) * 256 + p(body, 2)) * 256 + p(body, 3)) * 256 + p(body, 4)
				h = ((p(body, 5) * 256 + p(body, 6)) * 256 + p(body, 7)) * 256 + p(body, 8)
				depth = p(body, 9)
				ctype = p(body, 10)
				interlace = p(body, 13)
			elseif typ == "IDAT" then
				idat[#idat + 1] = body
			elseif typ == "IEND" then
				break
			end

			pos = pos + 12 + len
		end

		if not w or depth ~= 8 or interlace ~= 0 then return nil end

		local bpp = (ctype == 6 and 4) or (ctype == 4 and 2) or nil
		if not bpp then return nil end

		local z = table.concat(idat)
		if #z < 3 then return nil end

		local px, pxn = inflate(z, 3)
		if not px then return nil end

		local stride = w * bpp
		if pxn < h * (stride + 1) then return nil end

		local rows = {}
		local src = 1
		local prev

		for y = 0, h - 1 do
			local filter = px[src]
			src = src + 1
			local row = {}
			for i = 1, stride do
				row[i] = px[src]
				src = src + 1
			end

			if filter == 1 then
				for i = bpp + 1, stride do
					row[i] = (row[i] + row[i - bpp]) % 256
				end
			elseif filter == 2 then
				if prev then
					for i = 1, stride do
						row[i] = (row[i] + prev[i]) % 256
					end
				end
			elseif filter == 3 then
				for i = 1, stride do
					local left = (i > bpp) and row[i - bpp] or 0
					local up = prev and prev[i] or 0
					row[i] = (row[i] + floor((left + up) / 2)) % 256
				end
			elseif filter == 4 then
				for i = 1, stride do
					local left = (i > bpp) and row[i - bpp] or 0
					local up = prev and prev[i] or 0
					local ul = (prev and i > bpp) and prev[i - bpp] or 0
					local pp = left + up - ul
					local pa, pb, pc = math.abs(pp - left), math.abs(pp - up), math.abs(pp - ul)
					local pr = ul
					if pa <= pb and pa <= pc then
						pr = left
					elseif pb <= pc then
						pr = up
					end
					row[i] = (row[i] + pr) % 256
				end
			elseif filter ~= 0 then
				return nil
			end

			rows[y] = row
			prev = row
		end

		local tw, th = w, h
		if maxSize and w > maxSize then
			tw = maxSize
			th = floor(h * maxSize / w + 0.5)
			if th < 1 then th = 1 end
		end

		local raw, rn = {}, 0

		for y = 0, th - 1 do
			local y0 = floor(y * h / th)
			local y1 = floor((y + 1) * h / th) - 1
			if y1 < y0 then y1 = y0 end

			rn = rn + 1
			raw[rn] = 0

			for x = 0, tw - 1 do
				local x0 = floor(x * w / tw)
				local x1 = floor((x + 1) * w / tw) - 1
				if x1 < x0 then x1 = x0 end

				local sum, count = 0, 0
				for yy = y0, y1 do
					local row = rows[yy]
					for xx = x0, x1 do
						sum = sum + row[xx * bpp + bpp]
						count = count + 1
					end
				end

				raw[rn + 1] = 255
				raw[rn + 2] = 255
				raw[rn + 3] = 255
				raw[rn + 4] = floor(sum / count + 0.5)
				rn = rn + 4
			end
		end

		local s1, s2 = 1, 0
		for i = 1, rn do
			s1 = (s1 + raw[i]) % 65521
			s2 = (s2 + s1) % 65521
		end

		local body = bytesToString(raw, rn)
		local blocks = {"\120\1"}
		local off = 1

		while off <= #body do
			local last = (off + 65535 > #body) and 1 or 0
			local part = string.sub(body, off, off + 65534)
			local len = #part
			local nlen = 65535 - len
			blocks[#blocks + 1] = string.char(last, len % 256, floor(len / 256), nlen % 256, floor(nlen / 256)) .. part
			off = off + len
		end

		blocks[#blocks + 1] = u32(s2 * 65536 + s1)

		return "\137PNG\13\10\26\10"
			.. pngChunk("IHDR", u32(tw) .. u32(th) .. string.char(8, 6, 0, 0, 0))
			.. pngChunk("IDAT", table.concat(blocks))
			.. pngChunk("IEND", "")
	end
end

local function ensureCloudIcon()
	if type(isfile) ~= "function" or type(readfile) ~= "function" or type(writefile) ~= "function" then
		return false
	end

	local existsOk, exists = pcall(isfile, cloudIconPath)
	if existsOk and exists then
		return true
	end

	local srcOk, src = pcall(isfile, cloudAssetPath)
	if not srcOk or not src then
		return false
	end

	local readOk, data = pcall(readfile, cloudAssetPath)
	if not readOk or type(data) ~= "string" then
		return false
	end

	local convOk, out = pcall(pngRecolorWhite, data, 64)
	if not convOk or type(out) ~= "string" or #out == 0 then
		return false
	end

	return pcall(writefile, cloudIconPath, out)
end

if not ensureCloudIcon() then
	cloudIconPath = cloudAssetPath
end

local esp = nil
local lib = nil
local prevLib = getgenv().shitaroebet

if prevLib then
	pcall(function()
		prevLib:unload()
	end)

	getgenv().shitaroebet = nil
end
do
	local function libsrc(name)
		local ok_is, has = pcall(isfile, name)

		if ok_is and has then
			local ok_rd, body = pcall(readfile, name)

			if ok_rd and type(body) == "string" and #body > 0 then
				return body
			end
		end

		for _ = 1, 3 do
			local body = shnet.lib(name)

			if type(body) == "string" and #body > 0 then
				return body
			end

			task.wait(0.5)
		end
	end

	local espSrc = libsrc("esp.lua")
	local uiSrc = libsrc("shitaroebet.lua")

	if espSrc and uiSrc then
		local espLoad = loadstring(espSrc, "@esp")
		local uiLoad = loadstring(uiSrc, "@shitaroebet")
		espSrc, uiSrc = nil, nil

		if espLoad and uiLoad then
			local ok1, r1 = pcall(espLoad)

			if ok1 then
				esp = r1
			end

			local ok2, r2 = pcall(uiLoad)

			if ok2 then
				lib = r2
			end
		end
	end
end

if type(lib) ~= "table" or type(lib.window) ~= "function" then
	return
end

if getgenv().shitaroebet and getgenv().shitaroebet ~= lib then
	pcall(function()
		getgenv().shitaroebet:unload()
	end)
end

prevLib = nil

getgenv().shitaroebet = lib

local ICONMAP = {
	["circle-x"] = "x",
	["circle-check"] = "shield-check",
	["clipboard"] = "file-text",
	["cube-vertexes"] = "box",
	["mouse-scrollwheel"] = "mouse-pointer",
	["person"] = "user",
	["crosshairs"] = "crosshair",
	["chart-four-vertical-bars"] = "activity",
	["memory-card"] = "database",
	["gamepad"] = "gamepad-2",
}

local function art(v, fallback)
	if type(v) == "number" then
		return v
	end

	if type(v) ~= "string" or v == "" then
		return fallback
	end

	return ICONMAP[string.lower(v)] or v
end

local function CreateIndicator()
	local ind = {}

	function ind:Set() end
	function ind:SetRender() end
	function ind:SetText() end
	function ind:Remove() end

	return ind
end

local __Notification = {
	new = function(c)
		c = c or {}
		lib:notify({
			title = c.Title or "SHITARO",
			text = c.Content or "",
			icon = art(c.Icon, "info"),
			life = c.Duration or 5,
		})
	end,
}

local __Logging = {
	new = function(ic, txt, dur, col)
		lib:notify({
			title = tostring(txt or ""),
			icon = art(ic, "file-text"),
			life = dur or 4,
			tone = (typeof(col) == "Color3") and col or nil,
		})
	end,
}

getgenv().UI_SYNC = { stamp = 0, count = 0, start = os.clock() }

local function wrapCallback(fn)
	if type(fn) ~= "function" then
		return nil
	end

	return function(...)
		local sync = getgenv().UI_SYNC
		if sync then
			local now = os.clock()
			if now - sync.stamp > 0.4 then sync.count = 0 end
			sync.stamp = now
			sync.count = sync.count + 1
		end
		return fn(...)
	end
end

local function wrapContainer(sec)
	local w = { __sec = sec }

	function w:AddToggle(cfg)
		cfg = cfg or {}

		local el = sec:toggle({
			name = cfg.Name or "toggle",
			default = cfg.Default and true or false,
			options = cfg.Option and true or false,
			flag = cfg.Flag,
			callback = wrapCallback(cfg.Callback),
		})

		local o = { __el = el }

		if cfg.Option and el.options then
			o.Option = wrapContainer(el.options)
		end

		function o:GetValue() return el:get() end
		function o:SetValue(v) el:set(v) end

		return o
	end

	function w:AddSlider(cfg)
		cfg = cfg or {}

		local dec = tonumber(cfg.Round or cfg.Rounding) or 0
		local step = (dec > 0) and (1 / (10 ^ dec)) or 1

		local el = sec:slider({
			name = cfg.Name or "slider",
			min = tonumber(cfg.Min) or 0,
			max = tonumber(cfg.Max) or 100,
			default = cfg.Default,
			step = step,
			suffix = (type(cfg.Type) == "string" and cfg.Type ~= "") and cfg.Type or "",
			flag = cfg.Flag,
			callback = wrapCallback(cfg.Callback),
		})

		local o = { __el = el }

		function o:GetValue() return el:get() end
		function o:SetValue(v) el:set(v) end

		return o
	end

	function w:AddDropdown(cfg)
		cfg = cfg or {}

		local el = sec:combo({
			name = cfg.Name or "dropdown",
			list = cfg.Values or {},
			default = cfg.Default,
			multi = cfg.Multi and true or false,
			flag = cfg.Flag,
			callback = wrapCallback(cfg.Callback),
		})

		local o = { __el = el }

		function o:GetValue() return el:get() end
		function o:SetValue(v) el:set(v) end
		function o:SetValues(v) el:setlist(v) end
		function o:Generate() end

		return o
	end

	function w:AddColorPicker(cfg)
		cfg = cfg or {}

		local hook = cfg.Callback

		local el = sec:color({
			name = cfg.Name or "color",
			default = cfg.Default,
			flag = cfg.Flag,
			callback = hook and wrapCallback(function(c)
				hook(c, cfg.Transparency)
			end) or nil,
		})

		local o = { __el = el }

		function o:GetValue() return el:get() end
		function o:SetValue(v) el:set(v) end

		return o
	end

	function w:AddKeybind(cfg)
		cfg = cfg or {}

		local el = sec:keybind({
			name = cfg.Name or "keybind",
			default = cfg.Default,
			flag = cfg.Flag,
			callback = wrapCallback(cfg.Callback),
		})

		local o = { __el = el }

		function o:GetValue() return el:get() end
		function o:SetValue(v) el:set(v) end

		return o
	end

	function w:AddButton(cfg)
		cfg = cfg or {}

		local el = sec:button({
			name = cfg.Name or "Button",
			icon = art(cfg.Icon),
			callback = cfg.Callback,
		})

		return { __el = el }
	end

	function w:AddLabel(name, wrapText)
		local el = sec:label({
			name = tostring(name or ""),
			wrap = wrapText and true or false,
		})

		local o = { __el = el }

		function o:SetValue(v) el:set(v) end
		function o:GetValue() return el:get() end

		return o
	end

	return w
end

local function side_of(pos)
	if pos == "full" or pos == 3 then
		return "full"
	end

	return (pos == "right" or pos == 2) and "right" or "left"
end

local function popmenu(cfg)
	if type(lib.popup) == "function" then
		lib:popup(cfg)
	end
end

local function askinput(cfg)
	if type(lib.ask) == "function" then
		return lib:ask(cfg)
	end
end

local function wrapPage(tab, name)
	local menu = { Name = name, __tab = tab }

	menu.Root = setmetatable({}, {
		__index = function(_, key)
			if key == "Visible" then
				local ok, v = pcall(function() return tab.page.Visible end)
				return ok and v or false
			end
		end,
	})

	function menu:AddSection(scfg)
		scfg = scfg or {}

		return wrapContainer(tab:section({
			name = scfg.Name or "SECTION",
			side = side_of(scfg.Position),
		}))
	end

	function menu:AddClone(ccfg)
		ccfg = ccfg or {}

		return tab:clone({
			name = ccfg.Name or "Character",
			side = side_of(ccfg.Position),
			height = tonumber(ccfg.Height) or 250,
			zoom = tonumber(ccfg.Zoom),
			fov = tonumber(ccfg.Fov),
			callback = ccfg.Callback,
		})
	end

	function menu:AddImageList(icfg)
		icfg = icfg or {}

		local g = tab:gallery({
			name = icfg.Name or "LIST",
			icon = art(icfg.Icon, "list"),
			side = side_of(icfg.Position),
			height = tonumber(icfg.Height) or 250,
			multi = icfg.Multi and true or false,
			thumb = icfg.Thumb or "Asset",
			cell = tonumber(icfg.Cell),
			gap = tonumber(icfg.Gap),
			search = icfg.Search ~= false,
			tools = icfg.Tools ~= false,
			reset = icfg.Reset and true or false,
			blank = icfg.Blank,
			empty = icfg.Empty,
			buttons = icfg.Buttons,
			action = icfg.Action,
			context = icfg.Context,
			list = icfg.Values or {},
			default = icfg.Default,
			flag = icfg.Flag,
			callback = wrapCallback(icfg.Callback),
		})

		local o = { __el = g }

		function o:SetData(v) g:setdata(v) end
		function o:SetValues(v) g:setdata(v) end
		function o:SetDefault(v) g:setdefault(v) end
		function o:SetValue(v) g:set(v) end
		function o:GetValue() return g:get() end
		function o:Refresh() g:refresh() end
		function o:Clear() g:clear() end
		function o:All() g:all() end
		function o:Search(q) g:search(q) end
		function o:Generate() end

		return o
	end

	if type(tab.sub) == "function" then
		function menu:AddSub(bcfg)
			bcfg = bcfg or {}

			local branch = tab:sub({
				name = bcfg.Name or "SUB",
				icon = art(bcfg.Icon, "circle-dot"),
				tip = bcfg.Tip or "",
			})

			if type(tab.setopen) == "function" then
				pcall(tab.setopen, tab, true)
			end

			return wrapPage(branch, bcfg.Name)
		end
	end

	return menu
end

local fatality = {}
fatality.Colors = { Black = Color3.fromRGB(16, 16, 16) }

function fatality:CreateNotifier()
	return {
		Notify = function(_, c)
			c = c or {}
			__Notification.new(c)
		end,
	}
end

function fatality:CreateEventNotifier()
	return {
		Notify = function(_, c)
			c = c or {}
			__Logging.new(c.Icon or "clipboard", c.Title or c.Content or "", c.Duration or 4, c.Color)
		end,
	}
end

function fatality:Loader() end
function fatality:RegisterColorElement() end
function fatality:UpdateColors() end

local root = nil

function fatality.new(cfg)
	cfg = cfg or {}

	root = lib:window({ bind = "Insert" })

	local win = {}

	win.Menus = {}
	win.ClickSoundId = ""
	win.__win = root

	function win:SetSize() end
	function win:Set3DRender() end

	function win:Toggle()
		root:toggle()
	end

	function win:AddMenu(mcfg)
		mcfg = mcfg or {}

		local tab = root:tab({
			name = mcfg.Name or "TAB",
			icon = art(mcfg.Icon, "circle-dot"),
			tip = mcfg.Tip or "",
		})

		local menu = wrapPage(tab, mcfg.Name)

		table.insert(win.Menus, menu)

		return menu
	end

	function win:AddColors()
		local ct = root:tab({ name = "colors", icon = "palette", tip = "menu colors" })

		ct:color({ name = "accent", key = "accent", side = "left" })
		ct:color({ name = "text", key = "text", side = "right" })
		ct:color({ name = "panel", key = "panel", side = "left" })
		ct:color({ name = "header", key = "head", side = "right" })
		ct:color({ name = "sidebar", key = "side", side = "left" })
		ct:color({ name = "outline", key = "line", side = "right" })
		ct:color({ name = "muted", key = "dim", side = "left" })
		ct:color({ name = "network", key = "glow", side = "right" })
		ct:color({ name = "background", key = "bg", side = "left" })

		return ct
	end

	function win:AddConfig()
		local ct = root:tab({ name = "config", icon = "save", tip = "menu settings" })

		ct:configs({ name = "Configs", side = "left" })

		return ct, ct:section({ name = "Menu", side = "right" })
	end

	function win:SetBind(v)
		root:setbind(v)
	end

	return win
end

local notification = fatality:CreateNotifier()
local event_notify = fatality:CreateEventNotifier()



task.spawn(function()
	for _, obj in ipairs(workspace:GetDescendants()) do
		if (obj:IsA("BasePart") and obj.Name == "GlowShell")
			or (obj:IsA("Model") and (obj.Name == "GlowChr" or obj.Name == "ChamsChr")) then
			pcall(function() obj:Destroy() end)
		end
	end
end)

fatality:Loader({
	Name = "SHITARO",
	Duration = 4
});

notification:Notify({
	Title = "SHITARO",
	Content = "yo, "..game.Players.LocalPlayer.DisplayName..' welcome back nigga',
	Icon = "clipboard"
})

local window = fatality.new({
	Name = "SHITARO",
	Expire = "Never",
});

local roleThreadConns = {}
local roleThread = task.spawn(function()
	local rs = game:GetService("ReplicatedStorage")
	local players = game:GetService("Players")

	local round_module = nil
	local function get_module()
		if round_module then return round_module end
		local ok, m = pcall(function()
			return require(rs:WaitForChild("Modules"):WaitForChild("CurrentRoundClient"))
		end)
		if ok and type(m) == "table" then round_module = m end
		return round_module
	end

	local map = {}
	local role_dirty = false

	local function rebuild()
		if not (esp and esp.tSet and (esp.tSet.en.flag or esp.tSet.en.chams or esp.tSet.en.matChams or esp.tSet.en.offAr)) then return end
		local m = get_module()
		local data = m and m.PlayerData
		table.clear(map)
		if type(data) == "table" then
			for name, d in pairs(data) do
				if type(d) == "table" and d.Role then
					if not ((d.Role == "Sheriff" or d.Role == "Hero") and d.Dead) then
						map[name] = (d.Role == "Hero") and "Sheriff" or d.Role
					end
				end
			end
		end
		for _, p in ipairs(players:GetPlayers()) do
			local char = p.Character
			local bp = p:FindFirstChildOfClass("Backpack")
			local hasGun = (char and char:FindFirstChild("Gun")) or (bp and bp:FindFirstChild("Gun"))
			if hasGun and map[p.Name] ~= "Murderer" then
				map[p.Name] = "Sheriff"
			end
		end
		esp.roles = map
	end

	local m = get_module()
	if m and m.PlayerDataChanged then
		pcall(function()
			roleThreadConns[#roleThreadConns + 1] = m.PlayerDataChanged.Event:Connect(function()
				role_dirty = true
			end)
		end)
	end

	local hooked_containers = setmetatable({}, { __mode = "k" })

	local function hook_gun_container(container)
		if not container or hooked_containers[container] then return end
		hooked_containers[container] = true
		roleThreadConns[#roleThreadConns + 1] = container.ChildAdded:Connect(function(c)
			if c.Name == "Gun" then role_dirty = true end
		end)
		roleThreadConns[#roleThreadConns + 1] = container.ChildRemoved:Connect(function(c)
			if c.Name == "Gun" then role_dirty = true end
		end)
	end
	local function hook_char(char)
		hook_gun_container(char)
	end
	local function hook_player(p)
		if p.Character then hook_char(p.Character) end
		roleThreadConns[#roleThreadConns + 1] = p.CharacterAdded:Connect(function(char)
			hook_char(char)
			hook_gun_container(p:FindFirstChildOfClass("Backpack"))
			role_dirty = true
		end)
		hook_gun_container(p:FindFirstChildOfClass("Backpack"))
		roleThreadConns[#roleThreadConns + 1] = p.ChildAdded:Connect(function(child)
			if child:IsA("Backpack") then
				hook_gun_container(child)
				role_dirty = true
			end
		end)
	end
	for _, p in ipairs(players:GetPlayers()) do
		pcall(hook_player, p)
	end
	roleThreadConns[#roleThreadConns + 1] = players.PlayerAdded:Connect(function(p)
		pcall(hook_player, p)
	end)

	while task.wait(0.15) do
		role_dirty = false
		rebuild()
	end
end)

local game_tab = window:AddMenu({
	Name = "game",
	Icon = "mouse-scrollwheel",
	Tip = "game func",
	AutoFill = false
})

local visuals = window:AddMenu({
	Name = "visuals",
	Tip = "players visuals",
	Icon = "eye"
})

getgenv().visualsTab = visuals

local player_tab = window:AddMenu({
	Name = "player",
	Icon = "111917761312899",
	Tip = "local penis",
	AutoFill = false
})

local anim_tab = window:AddMenu({
	Name = "animations",
	Icon = "88949301532557",
	Tip = "custom animations",
	AutoFill = false
})

local target_tab = window:AddMenu({
	Name = "target",
	Icon = "83752373575368",
	Tip = "for niggas",
	AutoFill = false
})

local misc = window:AddMenu({
	Name = "misc",
	Icon = "95127553964880",
	Tip = "idk",
	AutoFill = false
})

local skin_tab = window:AddMenu({
	Name = "skins",
	Icon = "125353572203968",
	Tip = "weapon skins",
	AutoFill = false
})

getgenv().__PLR_Q = {}

getgenv().__PLR_QUEUE = function(key, name, fn)
	local q = getgenv().__PLR_Q[key]
	if not q then
		q = {}
		getgenv().__PLR_Q[key] = q
	end
	q[#q + 1] = { name = name, fn = fn, order = #q + 1 }
end

getgenv().__PLR_FLUSH = function(key, sec)
	local q = getgenv().__PLR_Q[key]
	if not q or not sec then return end
	table.sort(q, function(a, b)
		local la, lb = #a.name, #b.name
		if la ~= lb then return la < lb end
		if a.name ~= b.name then return a.name < b.name end
		return a.order < b.order
	end)
	for _, entry in ipairs(q) do
		pcall(entry.fn, sec)
	end
	getgenv().__PLR_Q[key] = nil
end

do
	local rs = game:GetService("ReplicatedStorage")
	local players = game:GetService("Players")
	local collection = game:GetService("CollectionService")
	local run = game:GetService("RunService")
	local lp = players.LocalPlayer

	local stats = game:GetService("Stats")

	getgenv().SILENT_S = {
		enabled = false,
		predict = false,
		force = false,
		auto_on = false,
		auto_delay = 0,
		am_sheriff = false,
		fire_gap = 0,
		last_shot = 0,
		stand_off = 15,
	}
	local S = getgenv().SILENT_S

	local silent_section = game_tab:AddSection({
		Name = "sheriff",
		Position = 'left'
	})

	local MAX_RANGE = 300

	local gap_min = 0
	local gap_seen = false
	local gap_gun = nil
	local want_since = 0

	local function gap_reset()
		gap_min = 0
		gap_seen = false
		S.fire_gap = 0
	end

	local function gap_push(value)
		if value <= 0 then return end
		if not gap_seen or value < gap_min then
			gap_min = value
			gap_seen = true
			S.fire_gap = value
		end
	end

	local round_mod = nil

	local function get_round()
		if round_mod then return round_mod end
		local ok, m = pcall(function()
			return require(rs:WaitForChild("Modules"):WaitForChild("CurrentRoundClient"))
		end)
		if ok and type(m) == "table" then round_mod = m end
		return round_mod
	end

	local function holds(container, name)
		return container ~= nil and container:FindFirstChild(name) ~= nil
	end

	local function lp_has_gun()
		return holds(lp.Character, "Gun") or holds(lp:FindFirstChildOfClass("Backpack"), "Gun")
	end

	local target_player = nil
	local target_char = nil
	local target_part = nil
	local target_hum = nil

	local function refresh_target()
		local found = nil
		local m = get_round()
		local data = m and m.PlayerData or nil
		if type(data) == "table" then
			local me = data[lp.Name]
			S.am_sheriff = (me ~= nil and (me.Role == "Sheriff" or me.Role == "Hero")) or lp_has_gun()
			for name, d in pairs(data) do
				if type(d) == "table" and d.Role == "Murderer" and not d.Dead then
					found = players:FindFirstChild(name)
					break
				end
			end
		else
			S.am_sheriff = lp_has_gun()
		end
		if not found then
			for _, plr in ipairs(players:GetPlayers()) do
				if plr ~= lp and holds(plr.Character, "Knife") then
					found = plr
					break
				end
			end
		end
		if found ~= target_player then
			target_player = found
			target_char = nil
			target_part = nil
			target_hum = nil
		end
		if not found then return end
		local char = found.Character
		if char ~= target_char then
			target_char = char
			target_part = nil
			target_hum = nil
		end
		if not char then return end
		if not target_part or not target_part.Parent then
			target_part = char:FindFirstChild("HumanoidRootPart") or char:FindFirstChild("UpperTorso") or char:FindFirstChild("Torso")
		end
		if not target_hum or not target_hum.Parent then
			target_hum = char:FindFirstChildOfClass("Humanoid")
		end
	end

	local function target_alive()
		if not target_part or not target_part.Parent then return false end
		if not target_hum or not target_hum.Parent then return false end
		return target_hum.Health > 0
	end

	local ray_params = RaycastParams.new()
	ray_params.FilterType = Enum.RaycastFilterType.Exclude
	ray_params.IgnoreWater = false

	local ignore_base = {}
	local ignore_work = {}
	local ignore_time = 0

	local function refresh_ignore()
		local now = os.clock()
		if #ignore_base > 0 and now - ignore_time < 0.5 then return end
		ignore_time = now
		table.clear(ignore_base)
		local char = lp.Character
		if char then ignore_base[1] = char end
		local ok, tagged = pcall(function() return collection:GetTagged("WeaponPassthrough") end)
		if ok and type(tagged) == "table" then
			for k = 1, #tagged do
				ignore_base[#ignore_base + 1] = tagged[k]
			end
		end
	end

	local function trace(origin, direction)
		refresh_ignore()
		table.clear(ignore_work)
		for k = 1, #ignore_base do ignore_work[k] = ignore_base[k] end
		local result = nil
		for _ = 1, 6 do
			ray_params.FilterDescendantsInstances = ignore_work
			result = workspace:Raycast(origin, direction, ray_params)
			if not result then break end
			local inst = result.Instance
			if not inst then break end
			local ok, tr = pcall(function() return inst.Transparency end)
			if not ok or tr ~= 1 then break end
			ignore_work[#ignore_work + 1] = inst
		end
		return result
	end

	local function gun_attachment()
		local char = lp.Character
		local hrp = char and char:FindFirstChild("HumanoidRootPart")
		if not hrp then return nil, nil end
		return hrp:FindFirstChild("GunRaycastAttachment"), hrp
	end

	local function origin_cframe()
		local att, hrp = gun_attachment()
		if att then return att.WorldCFrame end
		if hrp then return hrp.CFrame end
		return nil
	end

	local function grav()
		local ok, g = pcall(function() return workspace.Gravity end)
		if ok and type(g) == "number" and g > 0 then return g end
		return 0
	end

	local P = {
		snap = 48,
		ring = 48,
		hit_r = 2.1,
		pad = 2.6,
		min_span = 5,
		max_span = 90,
		acc_t = 0.15,
		acc_max = 280,
		acc_min = 40,
		speed_floor = 26,
		speed_head = 1.3,
	}

	local snap_t = table.create(P.snap, 0)
	local snap_p = table.create(P.snap, Vector3.zero)
	local snap_n = 0
	local snap_i = 0

	local TR = {
		part = nil,
		pos = nil,
		time = 0,
		vel = Vector3.zero,
		gap = 0,
		ready = false,
		fresh = Vector3.zero,
		air = false,
		air_since = 0,
		jumping = false,
		jump_v = 0,
		fresh_ok = false,
		turn = 0,
		spoof = 0,
		clr = 0,
		air_edge = 0,
		jump_fresh = false,
	}

	local SK = {
		vt = table.create(P.ring, 0),
		dx = table.create(P.ring, 0),
		dz = table.create(P.ring, 0),
		vn = 0,
		vi = 0,
	}

	local EC = {
		ping = 0,
		rtt = 0,
		jitter = 0,
		seen = false,
		step = 0,
		step_seen = false,
	}

	local function step_push(dt)
		if dt <= 0 or dt > 0.5 then return end
		if EC.step_seen then
			EC.step = EC.step * 0.85 + dt * 0.15
		else
			EC.step = dt
			EC.step_seen = true
		end
	end

	local function sample_span()
		local span = math.max(EC.step, TR.gap)
		if span <= 0 then return 0 end
		return span
	end

	local HY = {
		pos = {},
		w = {},
		n = 0,
		weight = 0,
		primary = nil,
		stamp = 0,
		conf = 0,
	}

	local ground_params = RaycastParams.new()
	ground_params.FilterType = Enum.RaycastFilterType.Exclude
	ground_params.IgnoreWater = true

	local ground_filter = {}
	local axis_pool = {}

	local function ground_below(pos, reach)
		table.clear(ground_filter)
		local n = 0
		local char = target_char
		if char then
			n = n + 1
			ground_filter[n] = char
		end
		local mine = lp.Character
		if mine then
			n = n + 1
			ground_filter[n] = mine
		end
		ground_params.FilterDescendantsInstances = ground_filter
		local res = workspace:Raycast(pos, Vector3.new(0, -reach, 0), ground_params)
		if res then return res.Position.Y end
		return nil
	end

	local function snap_push(now, pos)
		snap_i = snap_i % P.snap + 1
		snap_t[snap_i] = now
		snap_p[snap_i] = pos
		if snap_n < P.snap then snap_n = snap_n + 1 end
	end

	local function snap_get(k)
		local idx = (snap_i - k - 1) % P.snap + 1
		return snap_t[idx], snap_p[idx]
	end

	local function fit_velocity()
		if snap_n < 3 then return nil end
		local newest = snap_get(0)
		local used = 0
		local sum_d = 0
		local win = sample_span() * 4
		for k = 0, snap_n - 1 do
			local t = snap_get(k)
			if newest - t > win then break end
			used = used + 1
			sum_d = sum_d + t - newest
		end
		if used < 3 then return nil end
		local mean_d = sum_d / used
		local num = Vector3.zero
		local den = 0
		for k = 0, used - 1 do
			local t, p = snap_get(k)
			local d = t - newest - mean_d
			num = num + p * d
			den = den + d * d
		end
		if den < 1e-8 then return nil end
		return num / den, -mean_d
	end

	local function recent_velocity()
		if snap_n < 2 then return nil end
		local newest, head = snap_get(0)
		local fallback, fallback_age = nil, nil
		local target_span = sample_span() * 2
		local max_span = target_span * 2
		for k = 1, snap_n - 1 do
			local t, p = snap_get(k)
			local dt = newest - t
			if dt > max_span then break end
			if dt > 0 then
				fallback = (head - p) / dt
				fallback_age = dt * 0.5
				if dt >= target_span then
					return fallback, fallback_age
				end
			end
		end
		return fallback, fallback_age
	end

	local KIN = {
		ok = false,
		ax = 0,
		az = 0,
		smax = 0,
	}

	local function kin_clear()
		KIN.ok = false
		KIN.ax = 0
		KIN.az = 0
		KIN.smax = 0
	end

	local function fit_kin()
		if snap_n < 5 then return nil end
		local t0 = snap_get(0)
		local win = math.max(sample_span() * 5, 0.12)
		local scale = win
		local n, s1, s2, s3, s4 = 0, 0, 0, 0, 0
		local bx0, bx1, bx2 = 0, 0, 0
		local bz0, bz1, bz2 = 0, 0, 0
		for k = 0, snap_n - 1 do
			local t, p = snap_get(k)
			local age = t0 - t
			if age > win then break end
			local u = -age / scale
			local u2 = u * u
			n = n + 1
			s1 = s1 + u
			s2 = s2 + u2
			s3 = s3 + u2 * u
			s4 = s4 + u2 * u2
			bx0 = bx0 + p.X
			bx1 = bx1 + p.X * u
			bx2 = bx2 + p.X * u2
			bz0 = bz0 + p.Z
			bz1 = bz1 + p.Z * u
			bz2 = bz2 + p.Z * u2
		end
		if n < 5 then return nil end
		local det = n * (s2 * s4 - s3 * s3)
			- s1 * (s1 * s4 - s3 * s2)
			+ s2 * (s1 * s3 - s2 * s2)
		if math.abs(det) < 1e-9 then return nil end
		local function solve(b0, b1, b2)
			local d1 = n * (b1 * s4 - s3 * b2)
				- b0 * (s1 * s4 - s3 * s2)
				+ s2 * (s1 * b2 - b1 * s2)
			local d2 = n * (s2 * b2 - b1 * s3)
				- s1 * (s1 * b2 - b1 * s2)
				+ b0 * (s1 * s3 - s2 * s2)
			return d1 / det, d2 / det
		end
		local cx1, cx2 = solve(bx0, bx1, bx2)
		local cz1, cz2 = solve(bz0, bz1, bz2)
		local vx, vz = cx1 / scale, cz1 / scale
		local ax, az = 2 * cx2 / (scale * scale), 2 * cz2 / (scale * scale)
		if vx ~= vx or vz ~= vz or ax ~= ax or az ~= az then return nil end
		return Vector3.new(vx, 0, vz), Vector3.new(ax, 0, az)
	end

	local function kin_update()
		local kv, ka = fit_kin()
		if not kv then
			KIN.ok = false
			KIN.ax = 0
			KIN.az = 0
			return nil
		end
		KIN.ok = true
		local sp = math.sqrt(kv.X * kv.X + kv.Z * kv.Z)
		if sp > KIN.smax then
			KIN.smax = sp
		else
			KIN.smax = KIN.smax * 0.985 + sp * 0.015
		end
		if ka and not TR.air then
			local am = math.sqrt(ka.X * ka.X + ka.Z * ka.Z)
			local ax, az = ka.X, ka.Z
			if am > P.acc_max and am > 0 then
				ax = ax * P.acc_max / am
				az = az * P.acc_max / am
			end
			KIN.ax = KIN.ax * 0.5 + ax * 0.5
			KIN.az = KIN.az * 0.5 + az * 0.5
		else
			KIN.ax = KIN.ax * 0.5
			KIN.az = KIN.az * 0.5
		end
		return kv
	end

	local function snap_vel(k)
		local t0, p0 = snap_get(k)
		local t1, p1 = snap_get(k + 1)
		local d = t0 - t1
		if d <= 0 then return nil end
		return (p0 - p1) / d, d
	end

	local function vert_accel()
		if snap_n < 3 then return nil end
		local v0, d0 = snap_vel(0)
		local v1, d1 = snap_vel(1)
		if not v0 or not v1 then return nil end
		local span = (d0 + d1) * 0.5
		if span <= 1e-4 then return nil end
		return (v0.Y - v1.Y) / span
	end

	local function air_vy()
		if snap_n < 2 then return nil end
		local edge = TR.air_edge
		if edge <= 0 then return nil end
		local g = grav()
		local newest, head = snap_get(0)
		local want = sample_span() * 2
		local best = nil
		for k = 1, snap_n - 1 do
			local t, p = snap_get(k)
			if t < edge then break end
			local dt = newest - t
			if dt > 1e-4 then
				best = (head.Y - p.Y) / dt - 0.5 * g * dt
				if dt >= want then break end
			end
		end
		return best
	end

	local function body_clearance()
		local part = target_part
		local hum = target_hum
		if not part or not hum then return 0 end
		local ok, value = pcall(function() return part.Size.Y * 0.5 + hum.HipHeight end)
		if ok and type(value) == "number" and value > 0 then return value end
		return 0
	end

	local GC = {
		base = 0,
		seen = false,
	}

	local JL = {
		v = 0,
		seen = false,
	}

	local function stand_clearance()
		if GC.seen then return GC.base end
		return body_clearance()
	end

	local function engine_vel(part)
		local ok, v = pcall(function() return part.AssemblyLinearVelocity end)
		if not ok or typeof(v) ~= "Vector3" then
			ok, v = pcall(function() return part.Velocity end)
		end
		if not ok or typeof(v) ~= "Vector3" then return nil end
		if v.Magnitude ~= v.Magnitude then return nil end
		return v
	end

	local function vel_trust(pv, ev)
		if not pv or not ev then return 0 end
		local ph = Vector3.new(pv.X, 0, pv.Z)
		local eh = Vector3.new(ev.X, 0, ev.Z)
		local pm, em = ph.Magnitude, eh.Magnitude
		if pm < 1 and em < 1 then return 1 end
		if pm < 1 or em < 1 then return 0 end
		local ratio = em / pm
		if ratio > 1.5 or ratio < 0.6 then return 0 end
		local align = ph.Unit:Dot(eh.Unit)
		if align < 0.7 then return 0 end
		local a = math.clamp((align - 0.7) / 0.25, 0, 1)
		local r = 1 - math.clamp(math.abs(ratio - 1) / 0.4, 0, 1)
		return a * r
	end

	local function phase_velocity(v, age, air)
		if not v then return nil end
		local y = 0
		if air then
			y = v.Y - grav() * math.clamp(age or 0, 0, sample_span() * 4)
		end
		return Vector3.new(v.X, y, v.Z)
	end

	local function merge_vel(fit, fit_age, fast, fast_age, engine, engine_age, air)
		local stable = phase_velocity(fit, fit_age, air)
		local instant = phase_velocity(fast, fast_age, air)
		local turn = 0
		if stable and instant then
			local sh = Vector3.new(stable.X, 0, stable.Z)
			local ih = Vector3.new(instant.X, 0, instant.Z)
			if sh.Magnitude > 1 and ih.Magnitude > 1 then
				turn = math.acos(math.clamp(sh.Unit:Dot(ih.Unit), -1, 1)) / math.pi
			end
		end
		local base = instant or stable
		if not base then return Vector3.zero, 0, nil, 0 end
		if stable and instant then
			local agility = math.clamp(turn * 2.2, 0, 1)
			base = stable:Lerp(instant, 0.4 + 0.6 * agility)
		end
		local trust = 0
		if engine then
			local live = phase_velocity(engine, engine_age, air)
			trust = vel_trust(base, live)
			if trust > 0 and air then
				base = Vector3.new(base.X, base.Y, base.Z):Lerp(Vector3.new(base.X, live.Y, base.Z), trust * 0.35)
			end
		end
		return base, turn, instant or stable, trust
	end

	local function vel_push(now, hx, hz)
		SK.vi = SK.vi % P.ring + 1
		SK.vt[SK.vi] = now
		SK.dx[SK.vi] = hx
		SK.dz[SK.vi] = hz
		if SK.vn < P.ring then SK.vn = SK.vn + 1 end
	end

	local function track_clear()
		TR.part = nil
		TR.pos = nil
		TR.vel = Vector3.zero
		TR.gap = 0
		TR.ready = false
		TR.fresh = Vector3.zero
		TR.air = false
		TR.jumping = false
		TR.jump_v = 0
		TR.fresh_ok = false
		TR.turn = 0
		TR.spoof = 0
		TR.clr = 0
		TR.air_edge = 0
		TR.jump_fresh = false
		GC.base = 0
		GC.seen = false
		JL.v = 0
		JL.seen = false
		snap_n, snap_i = 0, 0
		SK.vn, SK.vi = 0, 0
		kin_clear()
	end

	local function track_seed(part, pos, now)
		TR.part = part
		TR.pos = pos
		TR.time = now
		TR.vel = Vector3.zero
		TR.fresh = Vector3.zero
		TR.fresh_ok = false
		TR.turn = 0
		TR.jump_v = 0
		TR.gap = 0
		TR.ready = false
		TR.spoof = 0
		TR.air_edge = 0
		TR.jump_fresh = false
		GC.base = 0
		GC.seen = false
		snap_n, snap_i = 0, 0
		kin_clear()
		snap_push(now, pos)
	end

	local function track_fresh(now)
		local part = target_part
		if not part or not part.Parent then
			TR.fresh_ok = false
			return
		end
		local pos = part.Position
		local g = grav()
		local sv = snap_vel(0)
		local vy = sv and sv.Y or 0
		local accel = vert_accel()
		local falling = accel ~= nil and accel < -g * 0.5
		local guess = stand_clearance()
		local reach = guess + 6 + math.abs(vy) * sample_span() * 4
		local air
		local gy = ground_below(pos, reach)
		if gy then
			local clr = pos.Y - gy
			TR.clr = clr
			if math.abs(vy) < 1 and not falling then
				if GC.seen then
					if clr < GC.base then
						GC.base = GC.base * 0.7 + clr * 0.3
					else
						GC.base = GC.base * 0.98 + clr * 0.02
					end
				else
					GC.base = clr
					GC.seen = true
				end
			end
			local floor = GC.seen and GC.base or guess
			local tol = math.max(floor * 0.35, 1)
			air = clr > floor + tol
			if not air and falling and math.abs(vy) > 4 and clr > floor + 0.35 then
				air = true
			end
		else
			air = true
		end
		if air ~= TR.air then
			TR.air_edge = now
			if air then
				TR.air_since = now
				TR.jump_fresh = true
				TR.jump_v = JL.seen and JL.v or math.max(vy, 0)
			else
				TR.jump_fresh = false
				TR.jump_v = 0
			end
		end
		local model_vy = TR.jump_v - g * math.max(0, now - TR.air_since)
		TR.air = air
		TR.jumping = air and (vy > 1 or model_vy > 1)
	end

	local function track(now)
		local part = target_part
		if not part or not part.Parent then
			if TR.part then track_clear() end
			return
		end
		track_fresh(now)
		local pos = part.Position
		if part ~= TR.part or not TR.pos then
			track_seed(part, pos, now)
			return
		end
		local dt = now - TR.time
		if dt > 0.75 or (pos - TR.pos).Magnitude > 140 then
			track_seed(part, pos, now)
			return
		end
		if dt <= 0 then return end
		if (pos - TR.pos).Magnitude == 0 then
			if TR.gap > 0 and dt >= TR.gap then
				TR.vel = Vector3.zero
				TR.fresh = Vector3.zero
			end
			return
		end
		step_push(dt)
		TR.gap = dt
		snap_push(now, pos)
		TR.pos = pos
		TR.time = now
		local fit, fit_age = fit_velocity()
		local fast, fast_age = recent_velocity()
		local engine = engine_vel(part)
		local fresh, turn, instant, trust = merge_vel(fit, fit_age, fast, fast_age, engine, sample_span() * 0.5, TR.air)
		local kv = kin_update()
		if kv then
			fresh = Vector3.new(kv.X, fresh.Y, kv.Z)
		end
		if engine and trust <= 0 then
			if TR.spoof < 20 then TR.spoof = TR.spoof + 1 end
		elseif TR.spoof > 0 then
			TR.spoof = TR.spoof - 1
		end
		if TR.air then
			local vy = air_vy()
			if vy then
				fresh = Vector3.new(fresh.X, vy, fresh.Z)
				local since = math.max(0, now - TR.air_edge)
				if TR.jump_fresh and since <= 0.2 then
					local impulse = vy + grav() * since
					if impulse > 1 then
						if JL.seen then
							JL.v = JL.v * 0.7 + impulse * 0.3
						else
							JL.v = impulse
							JL.seen = true
						end
						if impulse > TR.jump_v then TR.jump_v = impulse end
					end
				else
					TR.jump_fresh = false
				end
			end
		end
		TR.vel = fresh
		TR.ready = fit ~= nil or fast ~= nil
		TR.fresh = TR.vel
		TR.fresh_ok = TR.ready
		TR.turn = turn
		local raw = instant or fresh
		vel_push(now, raw.X, raw.Z)
	end

	local function raw_rtt()
		local ok, ms = pcall(function()
			return stats.Network.ServerStatsItem["Data Ping"]:GetValue()
		end)
		if ok and type(ms) == "number" and ms > 0 then return ms / 1000 end
		local fine, value = pcall(function() return lp:GetNetworkPing() end)
		if fine and type(value) == "number" and value > 0 then return value * 2 end
		return nil
	end

	local function sample_ping()
		local rtt = raw_rtt()
		if not rtt or rtt ~= rtt then return end
		rtt = math.clamp(rtt, 0, 1)
		if EC.seen then
			EC.jitter = EC.jitter * 0.9 + math.abs(rtt - EC.rtt) * 0.1
			EC.rtt = EC.rtt * 0.82 + rtt * 0.18
		else
			EC.rtt = rtt
			EC.jitter = 0
			EC.seen = true
		end
		EC.ping = EC.rtt
	end

	local function lead_time()
		if not EC.seen then return 0 end
		local stale = 0
		if TR.time > 0 and EC.step_seen then
			stale = math.clamp(os.clock() - TR.time, 0, EC.step)
		end
		return math.clamp(EC.rtt + EC.jitter * 0.5 + stale, 0, 1)
	end

	local function rotate_y(v, ang)
		local c, s = math.cos(ang), math.sin(ang)
		return Vector3.new(v.X * c - v.Z * s, v.Y, v.X * s + v.Z * c)
	end

	local function dir_stats(win)
		if SK.vn < 4 then return 1, 0 end
		win = math.max(win, sample_span() * 3)
		local newest = SK.vt[SK.vi]
		local sx, sz, n = 0, 0, 0
		local prev = nil
		local turn, turn_n = 0, 0
		local oldest = newest
		for k = 0, SK.vn - 1 do
			local idx = (SK.vi - k - 1) % P.ring + 1
			local t = SK.vt[idx]
			if newest - t > win then break end
			local hx, hz = SK.dx[idx], SK.dz[idx]
			local m = math.sqrt(hx * hx + hz * hz)
			if m > 0 then
				sx = sx + hx / m
				sz = sz + hz / m
				n = n + 1
				local ang = math.atan2(hz, hx)
				if prev then
					local d = ang - prev
					while d > math.pi do d = d - 6.2831853 end
					while d < -math.pi do d = d + 6.2831853 end
					turn = turn + d
					turn_n = turn_n + 1
				end
				prev = ang
				oldest = t
			end
		end
		if n < 2 then return 1, 0 end
		local coh = math.clamp(math.sqrt(sx * sx + sz * sz) / n, 0, 1)
		local omega = 0
		local elapsed = newest - oldest
		if turn_n >= 1 and elapsed > 1e-3 then
			omega = -turn / elapsed
		end
		return coh, omega
	end

	local function predict_from(base, sa, sb, fh, now)
		local span = math.max(0, sa + sb)
		local g = grav()
		local dir = fh
		if dir.Magnitude == 0 then
			dir = Vector3.new(TR.vel.X, 0, TR.vel.Z)
		end
		local x, z
		if span > 0 and KIN.ok then
			local age = math.clamp(now - TR.time, 0, sample_span() * 2)
			local ax, az = KIN.ax, KIN.az
			if TR.air or math.sqrt(ax * ax + az * az) < P.acc_min then ax, az = 0, 0 end
			local vx = dir.X + ax * age
			local vz = dir.Z + az * age
			local ta = math.min(span, P.acc_t)
			local dx = vx * span + 0.5 * ax * ta * ta
			local dz = vz * span + 0.5 * az * ta * ta
			local reach = math.sqrt(dx * dx + dz * dz)
			local cap = math.max(KIN.smax * P.speed_head, P.speed_floor) * span
			if reach > cap and reach > 1e-6 then
				dx = dx * cap / reach
				dz = dz * cap / reach
			end
			x = base.X + dx
			z = base.Z + dz
		else
			local hspan = span
			if span > 0 and dir.Magnitude > 0 and not TR.air then
				local coh, omega = dir_stats(span)
				local conf = math.clamp(coh, 0, 1) * (1 - math.clamp(TR.turn, 0, 1) * 0.5)
				if omega ~= 0 then
					dir = rotate_y(dir, math.clamp(omega * span * 0.5 * conf, -0.6, 0.6))
				end
				hspan = span * (0.85 + 0.15 * conf)
			end
			x = base.X + dir.X * hspan
			z = base.Z + dir.Z * hspan
		end
		local y = base.Y
		if TR.air and span > 0 then
			local vy = TR.vel.Y
			local phase = math.max(0, now - TR.air_since)
			local modeled = TR.jump_v - g * phase
			if TR.jumping and TR.jump_v > 0 and g > 0 and phase <= TR.jump_v / g and modeled > vy then
				vy = modeled
			end
			y = base.Y + vy * span - 0.5 * g * span * span
			if y < base.Y then
				local clearance = stand_clearance()
				local reach = base.Y - y + clearance
				local gy = ground_below(Vector3.new(x, base.Y, z), reach)
				if gy then
					local floor = gy + clearance
					if y < floor then y = floor end
				end
			end
		end
		return Vector3.new(x, y, z)
	end

	local function build_hyps(base, now)
		table.clear(HY.pos)
		table.clear(HY.w)
		local horizon = S.predict and TR.ready and lead_time() or 0
		local fh = Vector3.new(TR.fresh.X, 0, TR.fresh.Z)
		HY.primary = predict_from(base, 0, horizon, fh, now)
		HY.n = 1
		HY.pos[1] = HY.primary
		HY.w[1] = 1
		HY.weight = 1
		HY.stamp = now
	end

	local function score_axis(anchor, axis)
		local covered = 0
		local lo, hi = 0, 0
		for k = 1, HY.n do
			local d = HY.pos[k] - anchor
			local a = d:Dot(axis)
			local perp = (d - axis * a).Magnitude
			if perp <= P.hit_r then
				covered = covered + HY.w[k]
				if a < lo then lo = a end
				if a > hi then hi = a end
			end
		end
		return covered, lo, hi
	end

	local function corridor_axes(anchor)
		table.clear(axis_pool)
		local n = 0
		local function add(v)
			if typeof(v) ~= "Vector3" or v.Magnitude < 1e-4 then return end
			local u = v.Unit
			for k = 1, n do
				if axis_pool[k]:Dot(u) > 0.985 then return end
			end
			n = n + 1
			axis_pool[n] = u
		end
		local fh = Vector3.new(TR.fresh.X, 0, TR.fresh.Z)
		if TR.air then add(TR.fresh) end
		add(fh)
		for k = 1, HY.n do
			add(HY.pos[k] - anchor)
		end
		add(TR.fresh)
		add(Vector3.new(0, 1, 0))
		return n
	end

	local function build_corridor(now)
		local part = target_part
		if not part or not part.Parent then return nil end
		local base = part.Position
		build_hyps(base, now)
		local anchor = HY.primary or base
		local count = corridor_axes(anchor)
		local best_axis, best_cov, best_lo, best_hi = nil, -1, 0, 0
		for k = 1, count do
			local axis = axis_pool[k]
			local cov, lo, hi = score_axis(anchor, axis)
			if cov > best_cov then
				best_axis, best_cov, best_lo, best_hi = axis, cov, lo, hi
			end
		end
		if not best_axis then return nil end
		HY.conf = HY.weight > 0 and best_cov / HY.weight or 0

		local pad = P.pad
		local origin = anchor + best_axis * (best_lo - pad)
		local aim = anchor + best_axis * (best_hi + pad)
		if (aim - origin).Magnitude < 4 then
			origin = anchor - best_axis * 4
			aim = anchor + best_axis * 4
		end
		return origin, aim, HY.conf, anchor
	end

	local pred_off = Vector3.zero
	local pred_stamp = 0

	local function lead_offset()
		local part = target_part
		if not part or not part.Parent then return Vector3.zero end
		if not S.predict or not TR.ready then return Vector3.zero end
		local base = part.Position
		local now = os.clock()
		local fh = Vector3.new(TR.fresh.X, 0, TR.fresh.Z)
		local point = predict_from(base, 0, lead_time(), fh, now)
		local off = point - base
		pred_stamp = now
		pred_off = off
		return pred_off
	end

	local function cloud_confidence()
		local anchor = HY.primary
		if not anchor or HY.n == 0 or HY.weight <= 0 then return 0 end
		local covered = 0
		for k = 1, HY.n do
			if (HY.pos[k] - anchor).Magnitude <= P.hit_r then
				covered = covered + HY.w[k]
			end
		end
		return covered / HY.weight
	end
	local hit_names = {
		"HumanoidRootPart", "UpperTorso", "Torso", "LowerTorso", "Head",
		"RightUpperArm", "LeftUpperArm", "Right Arm", "Left Arm",
		"RightUpperLeg", "LeftUpperLeg", "Right Leg", "Left Leg",
		"RightLowerLeg", "LeftLowerLeg",
	}

	local hit_parts = {}
	local hit_count = 0
	local hit_char = nil

	local function refresh_parts()
		local char = target_char
		if char == hit_char then return end
		table.clear(hit_parts)
		hit_count = 0
		hit_char = char
		if not char then return end
		for k = 1, #hit_names do
			local part = char:FindFirstChild(hit_names[k])
			if part and part:IsA("BasePart") then
				hit_count = hit_count + 1
				hit_parts[hit_count] = part
			end
		end
	end

	local function los_clear(origin, point)
		if not origin or not point then return false end
		local delta = point - origin
		local dist = delta.Magnitude
		if dist < 0.5 then return true end
		if dist > MAX_RANGE then return false end
		local hit = trace(origin, delta)
		if not hit then return true end
		local inst = hit.Instance
		local char = target_char
		if inst and char and (inst == char or inst:IsDescendantOf(char)) then return true end
		return (hit.Position - origin).Magnitude >= dist - 0.75
	end

	local function pick_point(origin, strict)
		refresh_parts()
		if hit_count == 0 then return nil end
		local off = lead_offset()
		local first = nil
		for k = 1, hit_count do
			local part = hit_parts[k]
			if not part.Parent then
				hit_char = nil
			else
				local point = part.Position + off
				if not origin then return point end
				if not first then first = point end
				if los_clear(origin, point) then return point end
			end
		end
		if strict then return nil end
		return first
	end

	local force_att = nil
	local force_saved = nil
	local force_stamp = 0

	local function restore_origin()
		local att = force_att
		if not att then return end
		local saved = force_saved
		force_att = nil
		force_saved = nil
		if saved then
			pcall(function()
				if att.Parent then att.CFrame = saved end
			end)
		end
	end

	local function push_origin(cf)
		local att = gun_attachment()
		if not att then return false end
		if force_att and force_att ~= att then restore_origin() end
		if not force_att then
			local ok, saved = pcall(function() return att.CFrame end)
			if not ok or typeof(saved) ~= "CFrame" then return false end
			force_att = att
			force_saved = saved
		end
		force_stamp = os.clock()
		local ok = pcall(function() att.WorldCFrame = cf end)
		if not ok then
			restore_origin()
			return false
		end
		task.defer(restore_origin)
		return true
	end

	local function is_target_hit(inst)
		local char = target_char
		if not inst or not char then return false end
		return inst == char or inst:IsDescendantOf(char)
	end

	local function force_clear(origin, aim)
		local hit = trace(origin, aim - origin)
		if not hit then return false end
		return is_target_hit(hit.Instance)
	end

	local function force_velocity()
		if TR.fresh_ok and TR.fresh.Magnitude > 0.5 then return TR.fresh end
		if TR.ready and TR.vel.Magnitude > 0.5 then return TR.vel end
		return Vector3.zero
	end

	local function resolve_force()
		local part = target_part
		if not part or not part.Parent then return nil end
		local live = part.Position
		local now = os.clock()

		local origin, aim, conf, anchor = build_corridor(now)
		if origin and aim then
			local axis = aim - origin
			local span = axis.Magnitude
			if span > 1e-3 then
				local u = axis / span
				local mark = anchor or live
				local behind = (mark - origin):Dot(u)
				if behind < P.pad then
					origin = origin - u * (P.pad - behind)
				end
				local ahead = (aim - mark):Dot(u)
				if ahead < P.min_span then
					aim = mark + u * P.min_span
				end
				local want = S.stand_off
				while want > 0 do
					local probe = origin - u * want
					if (aim - probe).Magnitude <= P.max_span
						and los_clear(probe, mark)
						and los_clear(probe, live) then
						origin = probe
						break
					end
					want = want - 3
				end
				if (aim - origin).Magnitude > P.max_span then
					origin = aim - u * P.max_span
				end
				return CFrame.new(origin, aim), CFrame.new(aim), conf or 0, mark
			end
		end

		local vel = force_velocity()
		local dir = Vector3.new(0, -1, 0)
		if vel.Magnitude > 3 then
			dir = vel.Unit
		else
			local mine = origin_cframe()
			if mine then
				local delta = live - mine.Position
				if delta.Magnitude > 2 then dir = delta.Unit end
			end
		end
		local back = live - dir * 6
		local front = live + dir * math.max(P.min_span, vel.Magnitude * lead_time() + 8)
		if not force_clear(back, front) then
			back = live - dir * 2.5
		end
		return CFrame.new(back, front), CFrame.new(front), 0, live
	end

	local function shot_shift(dt)
		if not S.predict or not TR.ready or dt <= 0 then return Vector3.zero end
		local shift = Vector3.new(TR.vel.X * dt, 0, TR.vel.Z * dt)
		if TR.air then
			local g = grav()
			local horizon = lead_time()
			local vy = TR.vel.Y
			local phase = math.max(0, os.clock() - TR.air_since)
			local modeled = TR.jump_v - g * phase
			if TR.jumping and TR.jump_v > 0 and g > 0 and phase <= TR.jump_v / g and modeled > vy then vy = modeled end
			shift = Vector3.new(shift.X, vy * dt - g * horizon * dt - 0.5 * g * dt * dt, shift.Z)
		end
		return shift
	end

	local function compensate_force(origin_cf, aim_cf, started)
		local shift = shot_shift(math.max(0, os.clock() - started))
		if shift == Vector3.zero then return origin_cf, aim_cf end
		local origin = origin_cf.Position + shift
		local aim = aim_cf.Position + shift
		return CFrame.new(origin, aim), CFrame.new(aim)
	end

	local function resolve_shot()
		if not S.enabled or not S.am_sheriff or not target_alive() then return nil end
		if S.force then
			local started = os.clock()
			local origin_cf, aim_cf = resolve_force()
			if origin_cf and aim_cf then
				origin_cf, aim_cf = compensate_force(origin_cf, aim_cf, started)
				if push_origin(origin_cf) then return aim_cf end
			end
		end
		local cf = origin_cframe()
		local aim = pick_point(cf and cf.Position or nil, false)
		if not aim then return nil end
		return CFrame.new(aim)
	end

	local function compensate_resolve(cf)
		if S.force or typeof(cf) ~= "CFrame" then return cf end
		return CFrame.new(cf.Position + shot_shift(math.max(0, os.clock() - pred_stamp)))
	end

	local weapon_service = nil
	local orig_mouse = nil
	local orig_screen = nil
	local hook_mouse = nil
	local hook_screen = nil

	local function get_weapon_service()
		if weapon_service then return weapon_service end
		local ok, m = pcall(function()
			return require(rs:WaitForChild("ClientServices"):WaitForChild("WeaponService"))
		end)
		if ok and type(m) == "table" then weapon_service = m end
		return weapon_service
	end

	local function install_hooks()
		local m = get_weapon_service()
		if not m then return end
		if not hook_mouse then
			local function knife_aim()
				local fn = getgenv().KNIFE_AIM_RESOLVE
				if type(fn) ~= "function" then return nil end
				local ok, cf = pcall(fn)
				if ok and typeof(cf) == "CFrame" then return cf end
				return nil
			end
			hook_mouse = function(self, ...)
				sample_ping()
				local ok, cf = pcall(resolve_shot)
				if ok and cf then return compensate_resolve(cf) end
				local kcf = knife_aim()
				if kcf then return kcf end
				return orig_mouse(self, ...)
			end
			hook_screen = function(self, x, y, ...)
				sample_ping()
				local ok, cf = pcall(resolve_shot)
				if ok and cf then return compensate_resolve(cf) end
				local kcf = knife_aim()
				if kcf then return kcf end
				return orig_screen(self, x, y, ...)
			end
		end
		pcall(function() setreadonly(m, false) end)
		if type(m.GetMouseTargetCFrame) == "function" and m.GetMouseTargetCFrame ~= hook_mouse then
			orig_mouse = m.GetMouseTargetCFrame
			pcall(function() m.GetMouseTargetCFrame = hook_mouse end)
		end
		if type(m.GetTargetPosition) == "function" and m.GetTargetPosition ~= hook_screen then
			orig_screen = m.GetTargetPosition
			pcall(function() m.GetTargetPosition = hook_screen end)
		end
	end

	local gun_fired_conn = nil
	local last_fire_stamp = 0

	local function on_gun_fired(tool)
		if typeof(tool) ~= "Instance" then return end
		local char = lp.Character
		if not char then return end
		local ok, mine = pcall(function() return tool:IsDescendantOf(char) end)
		if not ok or not mine then return end
		local now = os.clock()
		if last_fire_stamp > 0 and want_since > 0 and want_since <= last_fire_stamp then
			gap_push(now - last_fire_stamp)
		end
		last_fire_stamp = now
	end

	local function connect_gun_fired()
		if gun_fired_conn then return end
		local m = get_weapon_service()
		if not m then return end
		local ev = m.GunFired
		if typeof(ev) ~= "Instance" then return end
		gun_fired_conn = ev.OnClientEvent:Connect(function(tool)
			pcall(on_gun_fired, tool)
		end)
	end

	local function get_gun()
		local char = lp.Character
		if char then
			local g = char:FindFirstChild("Gun")
			if g then return g, true end
		end
		local bp = lp:FindFirstChildOfClass("Backpack")
		if bp then
			local g = bp:FindFirstChild("Gun")
			if g then return g, false end
		end
		return nil, false
	end

	local function fire_gun(gun, start_cf, aim_cf)
		if not gun or not start_cf or not aim_cf then return false end
		local remote = gun:FindFirstChild("Shoot")
		if not remote or not remote:IsA("RemoteEvent") then return false end
		return (pcall(function() remote:FireServer(start_cf, aim_cf) end))
	end

	local function auto_step(now)
		if not S.auto_on or not S.enabled or not S.am_sheriff or getgenv().AUTOFARM_HOLD or not target_alive() then
			want_since = 0
			return
		end
		local gun, equipped = get_gun()
		if not gun then
			want_since = 0
			return
		end
		if gun ~= gap_gun then
			gap_gun = gun
			gap_reset()
		end
		if not equipped then
			want_since = 0
			local hum = lp.Character and lp.Character:FindFirstChildOfClass("Humanoid")
			if hum then pcall(function() hum:EquipTool(gun) end) end
			return
		end
		if want_since == 0 then want_since = now end
		local hold = S.auto_delay
		if hold < S.fire_gap then hold = S.fire_gap end
		local since = last_fire_stamp > 0 and last_fire_stamp or S.last_shot
		if now - since < hold then return end
		if S.force then
			local started = os.clock()
			local origin_cf, aim_cf = resolve_force()
			if not origin_cf or not aim_cf then return end
			origin_cf, aim_cf = compensate_force(origin_cf, aim_cf, started)
			if fire_gun(gun, origin_cf, aim_cf) then
				S.last_shot = now
			end
			return
		end
		local cf = origin_cframe()
		if not cf then return end
		local aim = pick_point(cf.Position, true)
		if not aim then return end
		local aim_cf = compensate_resolve(CFrame.new(aim))
		if fire_gun(gun, cf, aim_cf) then
			S.last_shot = now
		end
	end

	local watch_conns = {}

	local function clear_watch()
		for k = 1, #watch_conns do
			local conn = watch_conns[k]
			pcall(function() conn:Disconnect() end)
		end
		table.clear(watch_conns)
	end

	local function setup_watch()
		clear_watch()
		local m = get_round()
		if m and m.PlayerDataChanged then
			watch_conns[#watch_conns + 1] = m.PlayerDataChanged.Event:Connect(function()
				pcall(refresh_target)
			end)
		end
		watch_conns[#watch_conns + 1] = lp.CharacterAdded:Connect(function()
			task.wait(0.3)
			pcall(refresh_target)
		end)
	end

	local next_role = 0
	local next_hook = 0

	local function tick()
		if force_att and os.clock() - force_stamp > 0.05 then restore_origin() end
		if not S.enabled then return end
		local now = os.clock()
		if now >= next_role then
			next_role = now + 0.2
			refresh_target()
		end
		sample_ping()
		track(now)
		if now >= next_hook then
			next_hook = now + 1
			install_hooks()
			connect_gun_fired()
		end
		auto_step(now)
	end

	local main_conn = run.Heartbeat:Connect(function()
		pcall(tick)
	end)

	silent_section:AddToggle({
		Name = "silent",
		Default = false,
		Flag = "silent",
		Callback = function(v)
			S.enabled = v
			getgenv().SILENT_AIM_ACTIVE = v
			if v then
				task.spawn(function()
					pcall(install_hooks)
					pcall(connect_gun_fired)
					pcall(setup_watch)
					pcall(refresh_target)
				end)
			else
				clear_watch()
				track_clear()
			end
		end
	})

	local predict_tog = silent_section:AddToggle({
		Name = "prediction",
		Default = false,
		Flag = "Silent Prediction",
		Callback = function(v)
			S.predict = v
			if not v then track_clear() end
		end
	})

	local force_tog = silent_section:AddToggle({
		Name = "force shoot",
		ToolTip = "Shoots through walls",
		Default = false,
		Flag = "Silent Force",
		Option = true,
		Callback = function(v)
			S.force = v
			if not v then restore_origin() end
		end
	})

	force_tog.Option:AddSlider({
		Name = "origin",
		Default = 15,
		Min = 0,
		Max = 40,
		Round = 0,
		Type = " studs",
		Flag = "silent_stand_off",
		Callback = function(v)
			S.stand_off = v
		end
	})

	local auto_tog = silent_section:AddToggle({
		Name = "auto shoot",
		ToolTip = "Auto shoot on murder",
		Default = false,
		Flag = "Auto Shoot",
		Option = true,
		Callback = function(v)
			S.auto_on = v
		end
	})

	auto_tog.Option:AddSlider({
		Name = "delay",
		Default = 0,
		Min = 0,
		Max = 600,
		Round = 0,
		Type = "ms",
		Flag = "silent_auto_delay",
		Callback = function(v)
			S.auto_delay = v / 1000
		end
	})

	getgenv().SILENT_INSTALL_HOOKS = function()
		pcall(install_hooks)
	end

	getgenv().SILENT_DBG = function()
		local coh, omega = dir_stats(lead_time())
		return {
			target = target_player and target_player.Name or "none",
			ping = EC.ping,
			rtt = EC.rtt,
			jitter = EC.jitter,
			step = EC.step,
			lead = lead_time(),
			coherence = coh,
			omega = omega,
			turn = TR.turn,
			spoof = TR.spoof,
			clearance = TR.clr,
			ground = GC.seen and GC.base or 0,
			jump_learned = JL.seen and JL.v or 0,
			jump_v = TR.jump_v,
			fire_gap = S.fire_gap,
			want_since = want_since,
			conf_point = cloud_confidence(),
			conf_ray = HY.conf,
			gap = TR.gap,
			airborne = TR.air,
			vel_fresh = TR.fresh,
			vel_pos = TR.vel,
		}
	end

	task.spawn(function()
		pcall(install_hooks)
		pcall(connect_gun_fired)
	end)

	getgenv().SILENT_UNLOAD = function()
		S.enabled = false
		S.predict = false
		S.force = false
		S.auto_on = false
		getgenv().SILENT_AIM_ACTIVE = false
		restore_origin()
		clear_watch()
		track_clear()
		if gun_fired_conn then
			pcall(function() gun_fired_conn:Disconnect() end)
			gun_fired_conn = nil
		end
		if main_conn then
			pcall(function() main_conn:Disconnect() end)
			main_conn = nil
		end
		local m = weapon_service
		if m then
			pcall(function() setreadonly(m, false) end)
			if orig_mouse then
				pcall(function() m.GetMouseTargetCFrame = orig_mouse end)
			end
			if orig_screen then
				pcall(function() m.GetTargetPosition = orig_screen end)
			end
		end
	end
end

local murder_section = nil

do
	local kill_section = game_tab:AddSection({
		Name = "murder",
		Position = 'center'
	})
	murder_section = kill_section

	local rs = game:GetService("ReplicatedStorage")
	local players = game:GetService("Players")
	local run = game:GetService("RunService")
	local lp = players.LocalPlayer

	local aura_on = false
	local killall_on = false
	local aura_distance = 30

	local am_murderer = false

	local aura_round_mod = nil

	local function aura_require_round()
		return require(rs:WaitForChild("Modules"):WaitForChild("CurrentRoundClient"))
	end

	local function refresh_murderer()
		local module = aura_round_mod
		if not module then
			local ok, m = pcall(aura_require_round)
			if not ok or type(m) ~= "table" then
				am_murderer = false
				return
			end
			aura_round_mod = m
			module = m
		end
		local data = module.PlayerData
		if type(data) ~= "table" then
			am_murderer = false
			return
		end
		local me = data[lp.Name]
		am_murderer = me ~= nil and me.Role == "Murderer" and not me.Dead
	end

	local function get_knife()
		local char = lp.Character
		if char then
			local equipped = char:FindFirstChild("Knife")
			if equipped then return equipped, true end
		end
		local backpack = lp:FindFirstChildOfClass("Backpack")
		if backpack then
			local stored = backpack:FindFirstChild("Knife")
			if stored then return stored, false end
		end
		return nil, false
	end

	local function ensure_knife_equipped()
		local knife, equipped = get_knife()
		if not knife then return nil end
		if not equipped then
			local hum = lp.Character and lp.Character:FindFirstChildOfClass("Humanoid")
			if hum then
				pcall(function() hum:EquipTool(knife) end)
			end
			return nil
		end
		return knife
	end

	local function knife_stab(knife)
		local events = knife:FindFirstChild("Events")
		local stabbed = events and events:FindFirstChild("KnifeStabbed")
		if stabbed then
			pcall(function() stabbed:FireServer() end)
		end
	end

	local function knife_touch(knife, part)
		local events = knife:FindFirstChild("Events")
		local touched = events and events:FindFirstChild("HandleTouched")
		if touched then
			pcall(function() touched:FireServer(part) end)
		end
	end

	local last_kill = 0
	local genv = getgenv()
	local victims = {}

	task.spawn(function()
		while task.wait(0.3) do
			if aura_on or killall_on then
				pcall(refresh_murderer)
			end
		end
	end)

	task.spawn(function()
		while task.wait() do
			if not ((aura_on or killall_on) and am_murderer) then
				continue
			end
			if genv.AUTOFARM_HOLD then
				continue
			end
			local knife = ensure_knife_equipped()
			if not knife then
				continue
			end
			if os.clock() - last_kill < 0.05 then
				continue
			end
			local char = lp.Character
			local my_part = char and char:FindFirstChild("HumanoidRootPart")
			table.clear(victims)
			local victim_count = 0
			for _, plr in ipairs(players:GetPlayers()) do
				if plr == lp then continue end
				local target_char = plr.Character
				if not target_char then continue end
				local hum = target_char:FindFirstChildOfClass("Humanoid")
				if not hum or hum.Health <= 0 then continue end
				local part = target_char:FindFirstChild("HumanoidRootPart") or target_char:FindFirstChild("Head")
				if not part then continue end
				if killall_on then
					victim_count = victim_count + 1
					victims[victim_count] = part
				elseif aura_on and my_part and (part.Position - my_part.Position).Magnitude <= aura_distance then
					victim_count = victim_count + 1
					victims[victim_count] = part
				end
			end
			if victim_count > 0 then
				knife_stab(knife)
				for i = 1, victim_count do
					knife_touch(knife, victims[i])
				end
				last_kill = os.clock()
			end
		end
	end)

	local aura = kill_section:AddToggle({
		Name = "kill aura",
		Default = false,
		Flag = "Kill Aura",
		Option = true,
		Callback = function(v)
			aura_on = v
			if v then task.spawn(refresh_murderer) end
		end
	})

	aura.Option:AddSlider({
		Name = "distance",
		Default = 30,
		Min = 5,
		Max = 60,
		Round = 1,
		Flag = "Kill Distance",
		Callback = function(v)
			aura_distance = v
		end
	})

	kill_section:AddToggle({
		Name = "kill all",
		ToolTip = "Automatically kills all players",
		Default = false,
		Flag = "Kill All",
		Callback = function(v)
			killall_on = v
			if v then task.spawn(refresh_murderer) end
		end
	})

	getgenv().KILLAURA_UNLOAD = function()
		aura_on = false
		killall_on = false
	end
end

do
	local rs = game:GetService("ReplicatedStorage")
	local players = game:GetService("Players")
	local run = game:GetService("RunService")
	local stats = game:GetService("Stats")
	local collection = game:GetService("CollectionService")
	local lp = players.LocalPlayer

	getgenv().KNIFE_S = {
		silent = false,
		predict = false,
		instance_kill = false,
		range = 400,
		lead_scale = 1,
		lead_add = 0,
		air_scale = 0.35,
		throw_speed = 96,
		impact_radius = 12,
	}
	local K = getgenv().KNIFE_S

	local GRAV = workspace.Gravity
	local MAX_HSPEED = 34
	local MAX_VSPEED = 170
	local SNAP_CAP = 20
	local FIT_WINDOW = 0.13
	local STAB_WINDOW = 0.35
	local LEAD_CAP = 1
	local OFF_CAP = 60
	local AIR_OFF_CAP = 1.8
	local AIR_VEL_CAP = 80

	local round_mod = nil
	local am_murderer = false
	local trackers = {}

	local ground_params = RaycastParams.new()
	ground_params.FilterType = Enum.RaycastFilterType.Exclude
	ground_params.IgnoreWater = true
	local ground_filter = {}

	local function ground_below(char, pos, reach)
		table.clear(ground_filter)
		local n = 0
		if char then
			n = n + 1
			ground_filter[n] = char
		end
		local mine = lp.Character
		if mine then
			n = n + 1
			ground_filter[n] = mine
		end
		ground_params.FilterDescendantsInstances = ground_filter
		local res = workspace:Raycast(pos + Vector3.new(0, 2, 0), Vector3.new(0, -(reach + 2), 0), ground_params)
		if res then return res.Position.Y end
		return nil
	end

	local function clamp_vel(v)
		local hx, hz = v.X, v.Z
		local hm = math.sqrt(hx * hx + hz * hz)
		if hm > MAX_HSPEED then
			local s = MAX_HSPEED / hm
			hx = hx * s
			hz = hz * s
		end
		return Vector3.new(hx, math.clamp(v.Y, -MAX_VSPEED, MAX_VSPEED), hz)
	end

	local function engine_vel(part)
		local ok, v = pcall(function() return part.AssemblyLinearVelocity end)
		if ok and typeof(v) == "Vector3" then return clamp_vel(v) end
		return Vector3.zero
	end

	local function merge_vel(fit, lag, eng)
		if not fit then return eng end
		fit = clamp_vel(fit)
		local fh = Vector3.new(fit.X, 0, fit.Z)
		local eh = Vector3.new(eng.X, 0, eng.Z)
		local fm = fh.Magnitude
		local em = eh.Magnitude
		local h
		if fm < 1 and em < 1 then
			h = Vector3.zero
		elseif em < 1 then
			h = fh
		elseif fm < 1 then
			h = eh
		elseif fh.Unit:Dot(eh.Unit) < 0.25 then
			h = fh
		else
			h = eh * 0.75 + fh * 0.25
		end
		local y
		if math.abs(eng.Y) > 0.5 then
			y = eng.Y
		elseif math.abs(fit.Y) > 1 then
			y = math.clamp(fit.Y - GRAV * (lag or 0), -MAX_VSPEED, MAX_VSPEED)
		else
			y = 0
		end
		return Vector3.new(h.X, y, h.Z)
	end

	local function new_tracker()
		return {
			t = table.create(SNAP_CAP, 0),
			p = table.create(SNAP_CAP, Vector3.zero),
			n = 0,
			i = 0,
			part = nil,
			pos = nil,
			time = 0,
			vel = Vector3.zero,
			gap = 0.05,
			jitter = 0,
			ready = false,
			stab = 1,
			rest_gap = 3,
			rest_ready = false,
		}
	end

	local function snap_push(tr, now, pos)
		tr.i = tr.i % SNAP_CAP + 1
		tr.t[tr.i] = now
		tr.p[tr.i] = pos
		if tr.n < SNAP_CAP then tr.n = tr.n + 1 end
	end

	local function snap_get(tr, k)
		local idx = (tr.i - k - 1) % SNAP_CAP + 1
		return tr.t[idx], tr.p[idx]
	end

	local function fit_velocity(tr)
		if tr.n < 3 then return nil end
		local newest = snap_get(tr, 0)
		local used = 0
		local sum_d = 0
		for k = 0, tr.n - 1 do
			local t = snap_get(tr, k)
			if newest - t > FIT_WINDOW then break end
			used = used + 1
			sum_d = sum_d + (t - newest)
		end
		if used < 3 then return nil end
		local mean_d = sum_d / used
		local num = Vector3.zero
		local den = 0
		for k = 0, used - 1 do
			local t, p = snap_get(tr, k)
			local d = (t - newest) - mean_d
			num = num + p * d
			den = den + d * d
		end
		if den < 1e-8 then return nil end
		return num / den, -mean_d
	end

	local function path_stability(tr)
		if tr.n < 4 then return 1 end
		local newest, head = snap_get(tr, 0)
		local path = 0
		local prev = head
		local tail = head
		local used = 0
		for k = 1, tr.n - 1 do
			local t, p = snap_get(tr, k)
			if newest - t > STAB_WINDOW then break end
			local step = prev - p
			path = path + Vector3.new(step.X, 0, step.Z).Magnitude
			prev = p
			tail = p
			used = used + 1
		end
		if used < 3 or path < 1 then return 1 end
		local net = head - tail
		return math.clamp(Vector3.new(net.X, 0, net.Z).Magnitude / path, 0, 1)
	end

	local function tracker_seed(tr, part, pos, now)
		tr.part = part
		tr.pos = pos
		tr.time = now
		tr.vel = Vector3.zero
		tr.gap = 0.05
		tr.jitter = 0
		tr.ready = false
		tr.stab = 1
		tr.n = 0
		tr.i = 0
		snap_push(tr, now, pos)
	end

	local function update_tracker(tr, char, part, now)
		local pos = part.Position
		if part ~= tr.part or not tr.pos then
			tracker_seed(tr, part, pos, now)
			return
		end
		local dt = now - tr.time
		local shift = (pos - tr.pos).Magnitude
		if dt > 0.75 or shift > 140 then
			tracker_seed(tr, part, pos, now)
			return
		end
		if shift < 0.004 or dt <= 0 then
			if tr.ready and dt > 0.12 and engine_vel(part).Magnitude < 1 then
				tr.vel = tr.vel * 0.6
			end
			return
		end
		local old_gap = tr.gap
		tr.gap = math.clamp(old_gap * 0.8 + dt * 0.2, 0.012, 0.25)
		tr.jitter = math.clamp(tr.jitter * 0.8 + math.abs(dt - old_gap) * 0.2, 0, 0.15)
		snap_push(tr, now, pos)
		tr.pos = pos
		tr.time = now
		local fit, lag = fit_velocity(tr)
		local fresh = merge_vel(fit, lag, engine_vel(part))
		if tr.ready then
			local a = 0.45
			local oh = Vector3.new(tr.vel.X, 0, tr.vel.Z)
			local nh = Vector3.new(fresh.X, 0, fresh.Z)
			if oh.Magnitude > 1 and nh.Magnitude > 1 and oh.Unit:Dot(nh.Unit) < 0.5 then
				a = 0.85
			end
			local vx = tr.vel.X + (fresh.X - tr.vel.X) * a
			local vz = tr.vel.Z + (fresh.Z - tr.vel.Z) * a
			local vy
			if math.abs(fresh.Y) > 3 then
				vy = fresh.Y
			else
				vy = tr.vel.Y + (fresh.Y - tr.vel.Y) * 0.6
			end
			tr.vel = Vector3.new(vx, vy, vz)
		else
			tr.vel = fresh
			tr.ready = true
		end
		tr.stab = path_stability(tr)
		if math.abs(fresh.Y) < 3 then
			local gy = ground_below(char, pos, 12)
			if gy then
				local gap = pos.Y - gy
				if gap > 0.5 and gap < 8 then
					if tr.rest_ready then
						tr.rest_gap = tr.rest_gap * 0.85 + gap * 0.15
					else
						tr.rest_gap = gap
						tr.rest_ready = true
					end
				end
			end
		end
	end

	local function clear_trackers()
		table.clear(trackers)
	end

	local lead_ping = 0
	local ping_seen = false

	local function sample_ping()
		local ms = 0
		local ok, v = pcall(function()
			return stats.Network.ServerStatsItem["Data Ping"]:GetValue()
		end)
		if ok and type(v) == "number" then ms = v end
		local s = math.clamp(ms / 1000, 0, 1)
		if ping_seen then
			lead_ping = lead_ping * 0.85 + s * 0.15
		else
			lead_ping = s
			ping_seen = true
		end
	end

	local function target_part_of(char)
		if not char then return nil end
		return char:FindFirstChild("HumanoidRootPart")
			or char:FindFirstChild("UpperTorso")
			or char:FindFirstChild("Torso")
			or char:FindFirstChild("Head")
	end

	local function player_alive(plr)
		local char = plr.Character
		if not char then return false end
		local hum = char:FindFirstChildOfClass("Humanoid")
		if not hum or hum.Health <= 0 then return false end
		local data = round_mod and round_mod.PlayerData
		if type(data) == "table" then
			local entry = data[plr.Name]
			if entry and entry.Dead then return false end
		end
		return true
	end

	local function update_trackers(now)
		for plr in pairs(trackers) do
			if plr.Parent ~= players then trackers[plr] = nil end
		end
		for _, plr in ipairs(players:GetPlayers()) do
			if plr == lp then continue end
			if not player_alive(plr) then
				trackers[plr] = nil
				continue
			end
			local char = plr.Character
			local part = target_part_of(char)
			if not part then
				trackers[plr] = nil
				continue
			end
			local tr = trackers[plr]
			if not tr then
				tr = new_tracker()
				trackers[plr] = tr
			end
			update_tracker(tr, char, part, now)
		end
	end

	local function pick_target()
		local my_char = lp.Character
		local root = my_char and my_char:FindFirstChild("HumanoidRootPart")
		if not root then return nil, nil, nil end
		local origin = root.Position
		local best_char, best_part, best_tr = nil, nil, nil
		local best_dist = K.range
		for _, plr in ipairs(players:GetPlayers()) do
			if plr == lp then continue end
			if not player_alive(plr) then continue end
			local char = plr.Character
			local part = target_part_of(char)
			if not part then continue end
			local dist = (part.Position - origin).Magnitude
			if dist <= best_dist then
				best_dist = dist
				best_char = char
				best_part = part
				best_tr = trackers[plr]
			end
		end
		return best_char, best_part, best_tr
	end

	local function lead_offset(tr, char, base, t)
		if not K.predict or not tr or not tr.ready then return Vector3.zero end
		if t <= 0 then return Vector3.zero end
		local vel = tr.vel
		local scale = math.clamp(tr.stab, 0.3, 1) * t
		local off_x = vel.X * scale
		local off_z = vel.Z * scale
		local vy = vel.Y
		local off_y = 0
		local reach = math.max(24, math.abs(vy) * t + tr.rest_gap + 12)
		local gy = ground_below(char, base + Vector3.new(off_x, 0, off_z), reach)
		local floor = nil
		if gy then
			local rest_y = gy + tr.rest_gap
			if rest_y <= base.Y + 0.5 then floor = rest_y end
		end
		local grounded = math.abs(vy) < 3
		if grounded and floor then
			grounded = (base.Y - floor) <= 1.5
		end
		if not grounded and math.abs(vy) < AIR_VEL_CAP then
			local tv = t * K.air_scale
			off_y = math.clamp(vy * tv - 0.5 * GRAV * tv * tv, -AIR_OFF_CAP, AIR_OFF_CAP)
		end
		local off = Vector3.new(off_x, off_y, off_z)
		if off.Magnitude > OFF_CAP then return Vector3.zero end
		if floor and base.Y + off.Y < floor then
			return Vector3.new(off.X, floor - base.Y, off.Z)
		end
		return off
	end

	local function throw_aim(tr, char, part, origin)
		local base = part.Position
		local travel = 0
		local point = base
		for _ = 1, 3 do
			local t = math.clamp(lead_ping * K.lead_scale + K.lead_add + travel, 0, LEAD_CAP)
			point = base + lead_offset(tr, char, base, t)
			if not origin or K.throw_speed <= 1 then break end
			travel = math.clamp((point - origin).Magnitude / K.throw_speed, 0, 0.7)
		end
		return point
	end

	local function get_knife()
		local char = lp.Character
		if char then
			local equipped = char:FindFirstChild("Knife")
			if equipped then return equipped, true end
		end
		local backpack = lp:FindFirstChildOfClass("Backpack")
		if backpack then
			local stored = backpack:FindFirstChild("Knife")
			if stored then return stored, false end
		end
		return nil, false
	end

	local function knife_events()
		local knife = get_knife()
		if not knife then return nil end
		return knife:FindFirstChild("Events")
	end

	local function direct_kill(part)
		if not part or not part.Parent then return false end
		local events = knife_events()
		if not events then return false end
		local stabbed = events:FindFirstChild("KnifeStabbed")
		local touched = events:FindFirstChild("HandleTouched")
		if not stabbed or not touched then return false end
		local ok = pcall(function()
			stabbed:FireServer()
			touched:FireServer(part)
		end)
		return ok
	end

	local pending = nil

	local function clear_pending()
		pending = nil
	end

	local function projectile_position(inst)
		if not inst or not inst.Parent then return nil end
		if inst:IsA("BasePart") then return inst.Position end
		local blade = inst:FindFirstChild("BladePosition")
		if blade and blade:IsA("BasePart") then return blade.Position end
		local ok, pivot = pcall(function() return inst:GetPivot() end)
		if ok and typeof(pivot) == "CFrame" then return pivot.Position end
		local first = inst:FindFirstChildWhichIsA("BasePart")
		if first then return first.Position end
		return nil
	end

	local function target_still_alive()
		if not pending then return false end
		local char = pending.char
		if not char or not char.Parent then return false end
		local hum = char:FindFirstChildOfClass("Humanoid")
		if not hum or hum.Health <= 0 then return false end
		return true
	end

	local function resolve_impact()
		if not pending then return end
		if not target_still_alive() then
			clear_pending()
			return
		end
		local part = pending.part
		if not part or not part.Parent then
			part = target_part_of(pending.char)
			pending.part = part
		end
		if not part then
			clear_pending()
			return
		end
		local land = pending.last_pos or pending.aim
		if land and (land - part.Position).Magnitude <= K.impact_radius then
			direct_kill(part)
		end
		clear_pending()
	end

	local function adopt_projectile()
		if not pending or pending.knife then return end
		local char = lp.Character
		local root = char and char:FindFirstChild("HumanoidRootPart")
		if not root then return end
		local ok, tagged = pcall(function() return collection:GetTagged("ThrowingKnife") end)
		if not ok or type(tagged) ~= "table" then return end
		local best, best_dist = nil, 24
		for k = 1, #tagged do
			local inst = tagged[k]
			if inst and inst.Parent then
				local pos = projectile_position(inst)
				if pos then
					local dist = (pos - root.Position).Magnitude
					if dist < best_dist then
						best_dist = dist
						best = inst
					end
				end
			end
		end
		if best then
			pending.knife = best
			pending.last_pos = projectile_position(best)
		end
	end

	local function segment_gap(a, b, p)
		if not a then return (b - p).Magnitude end
		local ab = b - a
		local len2 = ab:Dot(ab)
		if len2 < 1e-6 then return (b - p).Magnitude end
		local t = math.clamp((p - a):Dot(ab) / len2, 0, 1)
		return (a + ab * t - p).Magnitude
	end

	local function pending_part()
		if not pending then return nil end
		local part = pending.part
		if not part or not part.Parent then
			part = target_part_of(pending.char)
			pending.part = part
		end
		return part
	end

	local function try_flyby(pos)
		if not pending or pending.fired then return end
		local part = pending_part()
		if not part then return end
		if segment_gap(pending.last_pos, pos, part.Position) > K.impact_radius then return end
		if direct_kill(part) then pending.fired = true end
	end

	local function watch_pending(now)
		if not pending then return end
		if now - pending.time > 6 then
			clear_pending()
			return
		end
		if not target_still_alive() then
			clear_pending()
			return
		end
		adopt_projectile()
		local inst = pending.knife
		if not inst then
			if now - pending.time > 1 then clear_pending() end
			return
		end
		if inst.Parent then
			local pos = projectile_position(inst)
			if pos then
				try_flyby(pos)
				pending.last_pos = pos
			end
			pending.gone_at = nil
			return
		end
		if not pending.gone_at then
			pending.gone_at = now
			return
		end
		resolve_impact()
	end

	local function refresh_role()
		if not round_mod then
			local ok, m = pcall(function()
				return require(rs:WaitForChild("Modules"):WaitForChild("CurrentRoundClient"))
			end)
			if ok and type(m) == "table" then round_mod = m end
		end
		local data = round_mod and round_mod.PlayerData
		if type(data) == "table" then
			local me = data[lp.Name]
			if me then
				am_murderer = me.Role == "Murderer" and not me.Dead
				return
			end
		end
		am_murderer = get_knife() ~= nil
	end

	local function resolve_throw_aim()
		if not K.silent then return nil end
		local char = lp.Character
		if not char or not char:FindFirstChild("Knife") then return nil end
		local target_char, part, tr = pick_target()
		if not part then return nil end
		local root = char:FindFirstChild("HumanoidRootPart")
		local origin = root and root.Position or nil
		local point = throw_aim(tr, target_char, part, origin)
		if K.instance_kill then
			pending = {
				char = target_char,
				part = part,
				time = os.clock(),
				aim = point,
				knife = nil,
				last_pos = nil,
				gone_at = nil,
				fired = false,
			}
		else
			clear_pending()
		end
		return CFrame.new(point)
	end

	getgenv().KNIFE_AIM_RESOLVE = function()
		local ok, cf = pcall(resolve_throw_aim)
		if ok then return cf end
		return nil
	end

	local function ensure_hooks()
		local fn = getgenv().SILENT_INSTALL_HOOKS
		if type(fn) == "function" then pcall(fn) end
	end

	local next_role = 0
	local next_ping = 0
	local next_hook = 0

	local function tick()
		if not (K.silent or pending) then return end
		local now = os.clock()
		if now >= next_role then
			next_role = now + 0.25
			refresh_role()
		end
		if now >= next_ping then
			next_ping = now + 0.25
			sample_ping()
		end
		if now >= next_hook then
			next_hook = now + 1
			ensure_hooks()
		end
		update_trackers(now)
		watch_pending(now)
	end

	local main_conn = run.Heartbeat:Connect(function()
		pcall(tick)
	end)

	

	local silent_tog = murder_section:AddToggle({
		Name = "throw silent",
		ToolTip = "Redirects ur knife throw at the closest target",
		Default = false,
		Flag = "Knife Silent",
		Option = true,
		Callback = function(v)
			K.silent = v
			
			if v then
				task.spawn(function()
					ensure_hooks()
					refresh_role()
				end)
			else
				clear_trackers()
				clear_pending()
			end
		end
	})

	silent_tog.Option:AddToggle({
		Name = "insta kill",
		Default = false,
		Flag = "Knife Instance Kill",
		Callback = function(v)
			K.instance_kill = v
			if not v then clear_pending() end
		end
	})

	silent_tog.Option:AddSlider({
		Name = "radius",
		Default = 12,
		Min = 2,
		Max = 40,
		Round = 0,
		Flag = "knife_impact_radius",
		Callback = function(v)
			K.impact_radius = v
		end
	})

	local pred_tog = murder_section:AddToggle({
		Name = "prediction",
		ToolTip = "Leads the throw by ping and knife travel time",
		Default = false,
		Flag = "Knife Prediction",
		Option = true,
		Callback = function(v)
			K.predict = v
			if not v then clear_trackers() end
		end
	})

	pred_tog.Option:AddSlider({
		Name = "lead",
		Default = 100,
		Min = 0,
		Max = 320,
		Round = 0,
		Type = "%",
		Flag = "knife_lead_scale",
		Callback = function(v)
			K.lead_scale = v / 100
		end
	})

	pred_tog.Option:AddSlider({
		Name = "air",
		Default = 35,
		Min = 0,
		Max = 120,
		Round = 0,
		Type = "%",
		Flag = "knife_air_scale",
		Callback = function(v)
			K.air_scale = v / 100
		end
	})

	pred_tog.Option:AddSlider({
		Name = "offset",
		Default = 0,
		Min = -80,
		Max = 220,
		Round = 0,
		Type = "ms",
		Flag = "knife_lead_add",
		Callback = function(v)
			K.lead_add = v / 1000
		end
	})

	pred_tog.Option:AddSlider({
		Name = "speed",
		Default = 96,
		Min = 40,
		Max = 400,
		Round = 0,
		Flag = "knife_throw_speed",
		Callback = function(v)
			K.throw_speed = v
		end
	})

	getgenv().KNIFE_UNLOAD = function()
		K.silent = false
		K.predict = false
		K.instance_kill = false
		knife_ind:Set(false)
		clear_trackers()
		clear_pending()
		getgenv().KNIFE_AIM_RESOLVE = nil
		if main_conn then
			pcall(function() main_conn:Disconnect() end)
			main_conn = nil
		end
	end
end

do
	local players = game:GetService("Players")
	local lp = players.LocalPlayer

	local autograb_on = false

	local grab_rs = game:GetService("ReplicatedStorage")
	local grab_round_mod = nil
	local function grab_has_role()
		if not grab_round_mod then
			local ok, m = pcall(function()
				return require(grab_rs:WaitForChild("Modules"):WaitForChild("CurrentRoundClient"))
			end)
			if ok and type(m) == "table" then grab_round_mod = m end
		end
		local d = grab_round_mod and grab_round_mod.PlayerData
		if type(d) ~= "table" then return false end
		local me = d[lp.Name]
		return me ~= nil and me.Role ~= nil and not me.Dead
	end

	local function has_knife()
		local char = lp.Character
		if char and char:FindFirstChild("Knife") then return true end
		local backpack = lp:FindFirstChildOfClass("Backpack")
		if backpack and backpack:FindFirstChild("Knife") then return true end
		return false
	end

	local function grab_gun(obj)
		if not autograb_on or has_knife() then return end
		if not grab_has_role() then return end
		local char = lp.Character
		local root = char and char:FindFirstChild("HumanoidRootPart")
		if not root then return end
		pcall(function() obj.CFrame = root.CFrame end)
		local prompt = obj:FindFirstChildOfClass("ProximityPrompt")
		if prompt then
			pcall(function() fireproximityprompt(prompt) end)
		end
	end

	local function scan_guns()
		for _, obj in pairs(workspace:GetDescendants()) do
			if obj.Name == "GunDrop" and obj:IsA("BasePart") then
				grab_gun(obj)
			end
		end
	end

	local grab_desc_conn = nil

	local function grab_desc_added(obj)
		if obj.Name == "GunDrop" and obj:IsA("BasePart") then
			task.wait(0.1)
			grab_gun(obj)
		end
	end

	local function grab_desc_stop()
		if grab_desc_conn then
			pcall(function() grab_desc_conn:Disconnect() end)
			grab_desc_conn = nil
		end
	end

	local run = game:GetService("RunService")
	local cs = game:GetService("CollectionService")
	local rs = game:GetService("ReplicatedStorage")

	local autofarm_on = false
	local autoreset_on = false
	local autokill_on = false
	local coins_done = false
	local saw_coins = false
	local farm_target = nil
	local nc_cache = {}
	local FARM_SPEED = 23
	local round_mod = nil
	local collected_ids = {}
	local collected_count = 0

	local farm_mode = "Basic"
	local avoid_murder = false
	local was_down = false
	local down_ref_y = nil
	local last_touch = 0
	local DOWN_DEPTH = 14
	local DOWN_RISE_XZ = 4
	local AVOID_DIST = 40
	local RISE_SAFE_DIST = 20

	getgenv().AUTOFARM_HOLD = false

	local function farm_hrp()
		local c = lp.Character
		return c and c:FindFirstChild("HumanoidRootPart")
	end

	local function get_round_data()
		if not round_mod then
			local ok, m = pcall(function()
				return require(rs:WaitForChild("Modules"):WaitForChild("CurrentRoundClient"))
			end)
			if ok and type(m) == "table" then round_mod = m end
		end
		return round_mod and round_mod.PlayerData
	end

	local function can_farm()
		local char = lp.Character
		local hum = char and char:FindFirstChildOfClass("Humanoid")
		if not hum or hum.Health <= 0 then return false end
		local d = get_round_data()
		if type(d) == "table" then
			local me = d[lp.Name]
			if not me or not me.Role or me.Dead then return false end
		end
		return true
	end

	local function coin_bags_full()
		local pg = lp:FindFirstChild("PlayerGui")
		local main = pg and pg:FindFirstChild("MainGUI")
		local gg = main and main:FindFirstChild("Game")
		local bags = gg and gg:FindFirstChild("CoinBags")
		local container = bags and bags:FindFirstChild("Container")
		if not container then return false end
		local any = false
		for _, v in ipairs(container:GetChildren()) do
			if v:IsA("Frame") and v.Visible then
				any = true
				local full = v:FindFirstChild("Full")
				if not (full and full.Visible) then
					return false
				end
			end
		end
		return any
	end

	local function update_hold()
		getgenv().AUTOFARM_HOLD = autofarm_on and autokill_on and not coins_done
	end

	local function reset_farm_progress()
		collected_ids = {}
		collected_count = 0
		coins_done = false
		saw_coins = false
		farm_target = nil
		update_hold()
	end

	task.spawn(function()
		local ok, remote = pcall(function()
			return rs:WaitForChild("Remotes"):WaitForChild("Gameplay"):WaitForChild("CoinsStarted", 15)
		end)
		if ok and remote then
			remote.OnClientEvent:Connect(reset_farm_progress)
		end
	end)

	lp.CharacterAdded:Connect(function()
		reset_farm_progress()
	end)

	local function coin_available(v)
		return v and v.Parent and v:IsA("BasePart") and not v:GetAttribute("Collected") and not v:GetAttribute("Delete")
	end

	local function available_coins()
		local list = {}
		for _, v in ipairs(cs:GetTagged("CoinVisual")) do
			if coin_available(v) then
				list[#list + 1] = v
			end
		end
		return list
	end

	local function nearest_coin(pos, list)
		local best, bd = nil, math.huge
		for _, v in ipairs(list) do
			local d = (v.Position - pos).Magnitude
			if d < bd then bd = d best = v end
		end
		return best
	end

	local function set_farm_noclip(on)
		local char = lp.Character
		local hum = char and char:FindFirstChildOfClass("Humanoid")
		if on then
			if not char then return end
			if hum then pcall(function() hum.PlatformStand = true end) end
			for _, p in ipairs(char:GetDescendants()) do
				if p:IsA("BasePart") and p.CanCollide then
					if nc_cache[p] == nil then nc_cache[p] = p.CanCollide end
					p.CanCollide = false
				end
			end
		else
			if hum then pcall(function() hum.PlatformStand = false end) end
			for p, v in pairs(nc_cache) do
				if p and p.Parent then pcall(function() p.CanCollide = v end) end
			end
			nc_cache = {}
		end
	end

	local up_params = RaycastParams.new()
	up_params.FilterType = Enum.RaycastFilterType.Exclude
	up_params.IgnoreWater = true

	local function return_to_surface()
		local hrp = farm_hrp()
		if not hrp then return end
		local origin = hrp.Position
		up_params.FilterDescendantsInstances = { lp.Character }
		local res = workspace:Raycast(origin, Vector3.new(0, 400, 0), up_params)
		local y = res and (res.Position.Y + 5) or (down_ref_y and down_ref_y + 5 or nil)
		if not y then return end
		pcall(function()
			hrp.CFrame = CFrame.new(origin.X, y, origin.Z)
			hrp.AssemblyLinearVelocity = Vector3.zero
			hrp.AssemblyAngularVelocity = Vector3.zero
		end)
	end

	local function farm_release()
		if was_down then
			was_down = false
			return_to_surface()
		end
		set_farm_noclip(false)
	end

	local murder_hrp_cache, murder_hrp_t = nil, 0
	local function murderer_hrp()
		local now = os.clock()
		if now - murder_hrp_t < 0.25 then return murder_hrp_cache end
		murder_hrp_t = now
		murder_hrp_cache = nil
		local d = get_round_data()
		if type(d) == "table" then
			local me = d[lp.Name]
			if me and me.Role == "Murderer" then return nil end
			for name, info in pairs(d) do
				if type(info) == "table" and info.Role == "Murderer" and not info.Dead and name ~= lp.Name then
					local pl = players:FindFirstChild(name)
					local char = pl and pl.Character
					local h = char and char:FindFirstChild("HumanoidRootPart")
					local hum = char and char:FindFirstChildOfClass("Humanoid")
					if h and (not hum or hum.Health > 0) then murder_hrp_cache = h end
					break
				end
			end
		end
		return murder_hrp_cache
	end

	local function flat_dist(a, b)
		return Vector3.new(a.X - b.X, 0, a.Z - b.Z).Magnitude
	end

	local function pick_coin(pos, list, mpos)
		if not (avoid_murder and mpos) then
			return nearest_coin(pos, list)
		end
		local safe, sd = nil, math.huge
		local far, fd = nil, -1
		for _, v in ipairs(list) do
			local md = flat_dist(v.Position, mpos)
			if md > fd then fd = md far = v end
			if md >= AVOID_DIST then
				local d = (v.Position - pos).Magnitude
				if d < sd then sd = d safe = v end
			end
		end
		if safe then return safe end
		if far and fd >= AVOID_DIST * 0.6 then return far end
		return nil
	end

	local function coin_ok_now(v, mpos)
		if not coin_available(v) then return false end
		if avoid_murder and mpos and flat_dist(v.Position, mpos) < AVOID_DIST * 0.6 then return false end
		return true
	end

	local function avoid_steer(cur, dest, mpos)
		if not (avoid_murder and mpos) then return dest end
		local dm = flat_dist(cur, mpos)
		if dm >= AVOID_DIST then return dest end
		local away = Vector3.new(cur.X - mpos.X, 0, cur.Z - mpos.Z)
		if away.Magnitude < 0.1 then away = Vector3.new(1, 0, 0) end
		away = away.Unit
		local want = Vector3.new(dest.X - cur.X, 0, dest.Z - cur.Z)
		local mag = want.Magnitude
		if mag < 0.1 then return dest end
		local weight = 1 + (1 - dm / AVOID_DIST) * 2
		local blend = (want.Unit + away * weight)
		if blend.Magnitude < 0.1 then blend = away else blend = blend.Unit end
		local np = cur + blend * mag
		return Vector3.new(np.X, dest.Y, np.Z)
	end

	local function touch_targets(coin)
		local list = {}
		local seen = {}
		local function add(p)
			if p and not seen[p] and p:IsA("BasePart") and p:FindFirstChildOfClass("TouchTransmitter") then
				seen[p] = true
				list[#list + 1] = p
			end
		end
		add(coin)
		for _, v in ipairs(coin:GetChildren()) do add(v) end
		local par = coin.Parent
		if par then
			if par:IsA("BasePart") then add(par) end
			for _, v in ipairs(par:GetChildren()) do add(v) end
		end
		if #list == 0 then list[1] = coin end
		return list
	end

	local function fire_touch(coin)
		if type(firetouchinterest) ~= "function" then return end
		if not coin or not coin.Parent then return end
		local now = os.clock()
		if now - last_touch < 0.05 then return end
		last_touch = now
		local hrp = farm_hrp()
		if not hrp then return end
		for _, p in ipairs(touch_targets(coin)) do
			pcall(firetouchinterest, hrp, p, 0)
			pcall(firetouchinterest, hrp, p, 1)
		end
	end

	local function farm_move(hrp, dest, dt)
		local dir = dest - hrp.Position
		local dist = dir.Magnitude
		local np = dest
		if dist > 0.1 then
			np = hrp.Position + dir.Unit * math.min(FARM_SPEED * dt, dist)
		end
		local cf = CFrame.new(np)
		if farm_mode == "Down" then
			cf = cf * CFrame.Angles(-math.pi * 0.5, 0, 0)
			was_down = true
		end
		pcall(function()
			hrp.CFrame = cf
			hrp.AssemblyLinearVelocity = Vector3.zero
			hrp.AssemblyAngularVelocity = Vector3.zero
		end)
	end

	local farm_conn = run.Stepped:Connect(function(_, dt)
		if not autofarm_on then return end
		if not can_farm() then
			farm_target = nil
			was_down = false
			set_farm_noclip(false)
			return
		end
		local hrp = farm_hrp()
		if not hrp then return end

		local list = {}
		for _, v in ipairs(cs:GetTagged("CoinVisual")) do
			if v and v.Parent and v:IsA("BasePart") then
				if v:GetAttribute("Collected") then
					local id = v:GetAttribute("CoinID")
					if id and not collected_ids[id] then
						collected_ids[id] = true
						collected_count = collected_count + 1
					end
				elseif not v:GetAttribute("Delete") then
					list[#list + 1] = v
				end
			end
		end

		local function finish()
			farm_target = nil
			farm_release()
			if not coins_done then
				coins_done = true
				update_hold()
				if autoreset_on then
					local hum = lp.Character and lp.Character:FindFirstChildOfClass("Humanoid")
					if hum then pcall(function() hum.Health = 0 end) end
				end
			end
		end

		if saw_coins and coin_bags_full() then
			finish()
			return
		end

		if #list > 0 then
			saw_coins = true
			if coins_done then coins_done = false update_hold() end

			local mhrp = avoid_murder and murderer_hrp() or nil
			local mpos = mhrp and mhrp.Position or nil

			if not coin_ok_now(farm_target, mpos) then
				farm_target = pick_coin(hrp.Position, list, mpos)
			end

			if farm_target then
				set_farm_noclip(true)
				local cpos = farm_target.Position
				down_ref_y = cpos.Y
				local dest = cpos

				if farm_mode == "Down" then
					local xz = flat_dist(hrp.Position, cpos)
					local safe_to_rise = (not mpos) or flat_dist(hrp.Position, mpos) > RISE_SAFE_DIST
					if xz <= DOWN_RISE_XZ and safe_to_rise then
						dest = cpos
						fire_touch(farm_target)
					else
						dest = Vector3.new(cpos.X, cpos.Y - DOWN_DEPTH, cpos.Z)
					end
				elseif (cpos - hrp.Position).Magnitude <= 6 then
					fire_touch(farm_target)
				end

				dest = avoid_steer(hrp.Position, dest, mpos)
				farm_move(hrp, dest, dt)
			elseif mpos then
				set_farm_noclip(true)
				local away = Vector3.new(hrp.Position.X - mpos.X, 0, hrp.Position.Z - mpos.Z)
				if away.Magnitude < 0.1 then away = Vector3.new(1, 0, 0) end
				away = away.Unit
				local y = hrp.Position.Y
				if farm_mode == "Down" and down_ref_y then y = down_ref_y - DOWN_DEPTH end
				farm_move(hrp, hrp.Position + away * 40 + Vector3.new(0, y - hrp.Position.Y, 0), dt)
			end
		else
			farm_target = nil
			farm_release()
			if saw_coins and not coins_done and collected_count > 0 then
				finish()
			end
		end
	end)

	local misc_section = game_tab:AddSection({
		Name = "autos",
		Position = 'right'
	})

	misc_section:AddToggle({
		Name = "grab gun",
		ToolTip = "Automatically grabs the gun when it drops",
		Default = false,
		Flag = "Auto Gun",
		Callback = function(v)
			autograb_on = v
			if v then
				if not grab_desc_conn then
					grab_desc_conn = workspace.DescendantAdded:Connect(grab_desc_added)
				end
				task.spawn(scan_guns)
			else
				grab_desc_stop()
			end
		end
	})

	local farm_tgl = misc_section:AddToggle({
		Name = "farm",
		ToolTip = "Automatically farms coins",
		Default = false,
		Flag = "Auto Farm",
		Option = true,
		Callback = function(v)
			autofarm_on = v
			reset_farm_progress()
			if not v then
				farm_release()
			end
		end
	})

	farm_tgl.Option:AddDropdown({
		Name = "type",
		Default = "Basic",
		Values = { "Basic", "Down" },
		Flag = "farm type detka",
		Callback = function(v)
			local nv = type(v) == "table" and v[1] or v
			if nv ~= "Basic" and nv ~= "Down" then nv = "Basic" end
			if nv == farm_mode then return end
			farm_mode = nv
			farm_target = nil
			if farm_mode == "Basic" and was_down then
				was_down = false
				return_to_surface()
			end
		end
	})

	farm_tgl.Option:AddToggle({
		Name = "murder check",
		Default = false,
		Flag = "bypass by shitaro ezez",
		Callback = function(v)
			avoid_murder = v
			farm_target = nil
		end
	})

	farm_tgl.Option:AddToggle({
		Name = "auto reset",
		ToolTip = "Automatically resets if the coin bags are full",
		Default = false,
		Flag = "Auto Reset",
		Callback = function(v)
			autoreset_on = v
		end
	})

	farm_tgl.Option:AddToggle({
		Name = "auto kill",
		ToolTip = "Automatically kill murder or all players if the\ncoin bags are full",
		Default = false,
		Flag = "Auto FarmK",
		Callback = function(v)
			autokill_on = v
			update_hold()
		end
	})

	getgenv().AUTOFARM_UNLOAD = function()
		autofarm_on = false
		autoreset_on = false
		autokill_on = false
		coins_done = false
		saw_coins = false
		farm_target = nil
		getgenv().AUTOFARM_HOLD = false
		avoid_murder = false
		farm_mode = "Basic"
		if farm_conn then pcall(function() farm_conn:Disconnect() end) farm_conn = nil end
		farm_release()
	end

	getgenv().AUTOGRAB_UNLOAD = function()
		autograb_on = false
		grab_desc_stop()
	end
end

do
	local esp_preview = visuals:AddClone({
		Name = "preview",
		Position = "left",
		Height = 232,
		Callback = function(model, item)
			local plr = game:GetService("Players").LocalPlayer

			_G.VIEWPORT_PLAYER = plr
			_G.VIEWPORT_CLONE = model
			_G.VIEWPORT_FRAME = item.viewport

			if getgenv().SELF_CHAMS_FIXCLONE then
				pcall(getgenv().SELF_CHAMS_FIXCLONE, item.parts)
			end

			if esp and esp._loaded then
				if _G.FAKE_PLAYER then
					pcall(esp.UpdateClone, _G.FAKE_PLAYER, model)
				else
					local ok, fake = pcall(esp.AddClone, model, plr, item.viewport)

					if ok then
						_G.FAKE_PLAYER = fake
					end
				end
			end
		end
	})

	local preview_scroll = nil

	do
		local node = esp_preview.viewport and esp_preview.viewport.Parent

		while node do
			if node:IsA("ScrollingFrame") then
				preview_scroll = node

				break
			end

			node = node.Parent
		end
	end

	esp_preview:onrender(function(item)
		local live = item.active and true or false

		if live then
			local vp = item.viewport
			local vs = vp.AbsoluteSize

			if vs.X < 8 or vs.Y < 8 then
				live = false
			elseif preview_scroll then
				local vpos = vp.AbsolutePosition
				local spos = preview_scroll.AbsolutePosition
				local ssize = preview_scroll.AbsoluteSize

				live = vpos.X >= spos.X - 1
					and vpos.Y >= spos.Y - 1
					and vpos.X + vs.X <= spos.X + ssize.X + 1
					and vpos.Y + vs.Y <= spos.Y + ssize.Y + 1
			end
		end

		getgenv().VISUALS_TAB_OPEN = live
	end)

	getgenv().ESP_PREVIEW_UNLOAD = function()
		getgenv().VISUALS_TAB_OPEN = false

		if _G.FAKE_PLAYER then
			if esp and esp.RemoveClone then
				pcall(esp.RemoveClone, _G.FAKE_PLAYER)
			end

			_G.FAKE_PLAYER = nil
		end

		_G.VIEWPORT_CLONE = nil
		_G.VIEWPORT_FRAME = nil
		_G.VIEWPORT_PLAYER = nil
	end

	local visuals_left = visuals:AddSection({
		Name = "esp",
		Position = 'right'
	})
	
	local world_page = (type(visuals.AddSub) == "function") and visuals:AddSub({
		Name = "world",
		Icon = "globe",
		Tip = "world visuals"
	}) or visuals

	getgenv().worldTab = world_page

	local visuals_right = world_page:AddSection({
		Name = "world",
		Position = 'left'
	})
	
	getgenv().WORLD_FOG_ENABLED = false
	getgenv().WORLD_FOG_COLOR = Color3.fromRGB(192, 192, 192)
	getgenv().WORLD_FOG_START = 0
	getgenv().WORLD_FOG_END = 1000
	getgenv().WORLD_FULLBRIGHT_ENABLED = false
	getgenv().WORLD_AMBIENT_ENABLED = false
	getgenv().WORLD_AMBIENT_COLOR = Color3.fromRGB(128, 128, 128)
	
	local lighting = game:GetService("Lighting")
	local originalFogColor = lighting.FogColor
	local originalFogStart = lighting.FogStart
	local originalFogEnd = lighting.FogEnd
	local originalBrightness = lighting.Brightness
	local originalAmbient = lighting.Ambient
	local originalOutdoorAmbient = lighting.OutdoorAmbient
	local originalGlobalShadows = lighting.GlobalShadows
	local originalClockTime = lighting.ClockTime
	local originalColorShift_Bottom = lighting.ColorShift_Bottom
	local originalColorShift_Top = lighting.ColorShift_Top
	local originalEnvironmentDiffuseScale = lighting.EnvironmentDiffuseScale
	local originalEnvironmentSpecularScale = lighting.EnvironmentSpecularScale
	local originalGeographicLatitude = lighting.GeographicLatitude
	local originalExposureCompensation = lighting.ExposureCompensation
	
	local shader_enabled = false
	local shader_type = "morning"
	local shader_connection = nil
	local original_effects = {}
	local created_effects = {}
	
	local bloom_effect = nil
	local blur_effect = nil
	local colorcor_effect = nil
	local depth_effect = nil
	local atmosphere_effect = nil
	local cloud_effect = nil
	
	local shaders = {
		morning = {
			yfbghj = Color3.fromRGB(10, 10, 10),
			khnbfth = 1.5,
			tgvbyd = 7.5,
			hgyghkg = Color3.fromRGB(0, 0, 0),
			yfbhjku = Color3.fromRGB(200, 200, 200),
			ygyyfgvhbjytrt = 0.1,
			sdfcddc = 0.1,
			hyhnngtf = Color3.fromRGB(10, 10, 10),
			ghuybhuyhj = 44,
			hdfr7thgr = 0.3,
			hgnujuu7thgr = true,
			fhnchvhfjsd = -0.02,
			ugtbbjhygt = 0.8,
			tfbghuugbnjhg = -0.5,
			fvrtccvghghj = Color3.fromRGB(100, 150, 200),
			jnfdhbnfcvh = 0.2,
			fvtyghj = 5,
			ygbhnj = 0.8,
			njnfg = 2,
			jdfkd = 0.5,
			fvgsdfg = 15,
			sdkvkflv = 5,
			hbjhd = 0.5,
			shdbsnjfc = 0.2,
			skdjfkdm = 0.5,
			sjdjncdjf = Color3.fromRGB(70, 120, 170),
			efjdjfk = Color3.fromRGB(10, 50, 100),
			sejfd = 0.3,
			jddfjsd = 1,
			gyhgtg = 0.6,
			ygbhggv = 0.36,
			jghbjhgyfd = Color3.fromRGB(255, 255, 255)
		},
		midday = {
			yfbghj = Color3.fromRGB(2, 2, 2),
			khnbfth = 3.25,
			tgvbyd = 8,
			hgyghkg = Color3.fromRGB(0, 0, 0),
			yfbhjku = Color3.fromRGB(255, 247, 237),
			ygyyfgvhbjytrt = 0.203,
			sdfcddc = 0.255,
			hyhnngtf = Color3.fromRGB(51, 54, 67),
			ghuybhuyhj = -15.12,
			hdfr7thgr = 0.85,
			hgnujuu7thgr = true,
			fhnchvhfjsd = 0.1,
			ugtbbjhygt = 0.5,
			tfbghuugbnjhg = -0.3,
			fvrtccvghghj = Color3.fromRGB(242, 243, 243),
			jnfdhbnfcvh = 0.3,
			fvtyghj = 10,
			ygbhnj = 0.8,
			njnfg = 5,
			jdfkd = 0.277,
			fvgsdfg = 21.54,
			sdkvkflv = 16.77,
			hbjhd = 0.277,
			shdbsnjfc = 0.364,
			skdjfkdm = 0.556,
			sjdjncdjf = Color3.fromRGB(175, 221, 255),
			efjdjfk = Color3.fromRGB(13, 105, 172),
			sejfd = 0.36,
			jddfjsd = 0.72,
			gyhgtg = 0.75,
			ygbhggv = 0.26,
			jghbjhgyfd = Color3.fromRGB(255, 255, 255)
		},
		evening = {
			yfbghj = Color3.fromRGB(2, 2, 2),
			khnbfth = 2.25,
			tgvbyd = 16,
			hgyghkg = Color3.fromRGB(0, 0, 0),
			yfbhjku = Color3.fromRGB(255, 247, 237),
			ygyyfgvhbjytrt = 0.203,
			sdfcddc = 0.215,
			hyhnngtf = Color3.fromRGB(0, 0, 0),
			ghuybhuyhj = 45,
			hdfr7thgr = 0.65,
			hgnujuu7thgr = true,
			fhnchvhfjsd = 0.1,
			ugtbbjhygt = 0.5,
			tfbghuugbnjhg = -0.3,
			fvrtccvghghj = Color3.fromRGB(255, 205, 185),
			jnfdhbnfcvh = 0.3234,
			fvtyghj = 10,
			ygbhnj = 0.813,
			njnfg = 5,
			jdfkd = 0.217,
			fvgsdfg = 21.54,
			sdkvkflv = 16.77,
			hbjhd = 0.277,
			shdbsnjfc = 0.364,
			skdjfkdm = 5.556,
			sjdjncdjf = Color3.fromRGB(199, 175, 166),
			efjdjfk = Color3.fromRGB(44, 39, 33),
			sejfd = 0.36,
			jddfjsd = 1.72,
			gyhgtg = 0.55,
			ygbhggv = 0.43,
			jghbjhgyfd = Color3.fromRGB(199, 175, 166)
		},
		night = {
			yfbghj = Color3.fromRGB(33, 33, 33),
			khnbfth = 3.25,
			tgvbyd = 20,
			hgyghkg = Color3.fromRGB(0, 0, 0),
			yfbhjku = Color3.fromRGB(255, 247, 237),
			ygyyfgvhbjytrt = 0.203,
			sdfcddc = 0.255,
			hyhnngtf = Color3.fromRGB(51, 54, 67),
			ghuybhuyhj = -15,
			hdfr7thgr = 0.85,
			hgnujuu7thgr = true,
			fhnchvhfjsd = -0.06,
			ugtbbjhygt = -0.02,
			tfbghuugbnjhg = -0.2,
			fvrtccvghghj = Color3.fromRGB(242, 243, 243),
			jnfdhbnfcvh = 0.34,
			fvtyghj = 10,
			ygbhnj = 0.813,
			njnfg = 5,
			jdfkd = 0.217,
			fvgsdfg = 11.54,
			sdkvkflv = 16.77,
			hbjhd = 0.277,
			shdbsnjfc = 0.264,
			skdjfkdm = 0.156,
			sjdjncdjf = Color3.fromRGB(175, 221, 255),
			efjdjfk = Color3.fromRGB(13, 105, 172),
			sejfd = 0.36,
			jddfjsd = 1.72,
			gyhgtg = 0.65,
			ygbhggv = 0.33,
			jghbjhgyfd = Color3.fromRGB(255, 255, 255)
		}
	}
	
	local function ensure_effects()
		if not bloom_effect or not bloom_effect.Parent then
			bloom_effect = lighting:FindFirstChildOfClass("BloomEffect")
			if not bloom_effect then
				bloom_effect = Instance.new("BloomEffect")
				bloom_effect.Enabled = false
				bloom_effect.Parent = lighting
				created_effects.bloom = true
			end
		end
		if not blur_effect or not blur_effect.Parent then
			blur_effect = lighting:FindFirstChildOfClass("BlurEffect")
			if not blur_effect then
				blur_effect = Instance.new("BlurEffect")
				blur_effect.Enabled = false
				blur_effect.Size = 0
				blur_effect.Parent = lighting
				created_effects.blur = true
			end
		end
		if not colorcor_effect or not colorcor_effect.Parent then
			colorcor_effect = lighting:FindFirstChildOfClass("ColorCorrectionEffect")
			if not colorcor_effect then
				colorcor_effect = Instance.new("ColorCorrectionEffect")
				colorcor_effect.Enabled = false
				colorcor_effect.Parent = lighting
				created_effects.colorcor = true
			end
		end
		if not depth_effect or not depth_effect.Parent then
			depth_effect = lighting:FindFirstChildOfClass("DepthOfFieldEffect")
			if not depth_effect then
				depth_effect = Instance.new("DepthOfFieldEffect")
				depth_effect.Enabled = false
				depth_effect.Parent = lighting
				created_effects.depth = true
			end
		end
		if not atmosphere_effect or not atmosphere_effect.Parent then
			atmosphere_effect = lighting:FindFirstChildOfClass("Atmosphere")
			if not atmosphere_effect then
				atmosphere_effect = Instance.new("Atmosphere")
				atmosphere_effect.Parent = lighting
				created_effects.atmosphere = true
			end
		end
		if workspace.Terrain and (not cloud_effect or not cloud_effect.Parent) then
			cloud_effect = workspace.Terrain:FindFirstChildOfClass("Clouds")
			if not cloud_effect then
				cloud_effect = Instance.new("Clouds")
				cloud_effect.Cover = 0
				cloud_effect.Density = 0
				cloud_effect.Parent = workspace.Terrain
				created_effects.cloud = true
			end
		end
	end
	
	local function save_original_effects()
		bloom_effect = lighting:FindFirstChildOfClass("BloomEffect")
		blur_effect = lighting:FindFirstChildOfClass("BlurEffect")
		colorcor_effect = lighting:FindFirstChildOfClass("ColorCorrectionEffect")
		depth_effect = lighting:FindFirstChildOfClass("DepthOfFieldEffect")
		atmosphere_effect = lighting:FindFirstChildOfClass("Atmosphere")
		if workspace.Terrain then
			cloud_effect = workspace.Terrain:FindFirstChildOfClass("Clouds")
		end
		
		if colorcor_effect then
			original_effects.colorcor = {
				Brightness = colorcor_effect.Brightness,
				Contrast = colorcor_effect.Contrast,
				Saturation = colorcor_effect.Saturation,
				TintColor = colorcor_effect.TintColor,
				Enabled = colorcor_effect.Enabled
			}
		end
		if bloom_effect then
			original_effects.bloom = {
				Intensity = bloom_effect.Intensity,
				Size = bloom_effect.Size,
				Threshold = bloom_effect.Threshold,
				Enabled = bloom_effect.Enabled
			}
		end
		if blur_effect then
			original_effects.blur = {
				Size = blur_effect.Size,
				Enabled = blur_effect.Enabled
			}
		end
		if depth_effect then
			original_effects.depth = {
				FarIntensity = depth_effect.FarIntensity,
				FocusDistance = depth_effect.FocusDistance,
				InFocusRadius = depth_effect.InFocusRadius,
				NearIntensity = depth_effect.NearIntensity,
				Enabled = depth_effect.Enabled
			}
		end
		if atmosphere_effect then
			original_effects.atmosphere = {
				Density = atmosphere_effect.Density,
				Offset = atmosphere_effect.Offset,
				Color = atmosphere_effect.Color,
				Decay = atmosphere_effect.Decay,
				Glare = atmosphere_effect.Glare,
				Haze = atmosphere_effect.Haze
			}
		end
		if cloud_effect then
			original_effects.cloud = {
				Cover = cloud_effect.Cover,
				Density = cloud_effect.Density,
				Color = cloud_effect.Color
			}
		end
	end
	
	local shader_fog_inf = math.huge
	local shader_fog_color = Color3.fromRGB(255, 255, 255)

	local function apply_shader(shader_data)
		ensure_effects()
		local v = shader_data.yfbghj
		if lighting.Ambient ~= v then lighting.Ambient = v end
		v = shader_data.khnbfth
		if lighting.Brightness ~= v then lighting.Brightness = v end
		v = shader_data.tgvbyd
		if lighting.ClockTime ~= v then lighting.ClockTime = v end
		v = shader_data.hgyghkg
		if lighting.ColorShift_Bottom ~= v then lighting.ColorShift_Bottom = v end
		v = shader_data.yfbhjku
		if lighting.ColorShift_Top ~= v then lighting.ColorShift_Top = v end
		v = shader_data.ygyyfgvhbjytrt
		if lighting.EnvironmentDiffuseScale ~= v then lighting.EnvironmentDiffuseScale = v end
		v = shader_data.sdfcddc
		if lighting.EnvironmentSpecularScale ~= v then lighting.EnvironmentSpecularScale = v end
		v = shader_data.hyhnngtf
		if lighting.OutdoorAmbient ~= v then lighting.OutdoorAmbient = v end
		v = shader_data.ghuybhuyhj
		if lighting.GeographicLatitude ~= v then lighting.GeographicLatitude = v end
		v = shader_data.hdfr7thgr
		if lighting.ExposureCompensation ~= v then lighting.ExposureCompensation = v end
		v = shader_data.hgnujuu7thgr
		if lighting.GlobalShadows ~= v then lighting.GlobalShadows = v end
		if lighting.FogEnd ~= shader_fog_inf then lighting.FogEnd = shader_fog_inf end
		if lighting.FogColor ~= shader_fog_color then lighting.FogColor = shader_fog_color end
		if lighting.FogStart ~= shader_fog_inf then lighting.FogStart = shader_fog_inf end
		
		if colorcor_effect then
			v = shader_data.fhnchvhfjsd
			if colorcor_effect.Brightness ~= v then colorcor_effect.Brightness = v end
			v = shader_data.ugtbbjhygt
			if colorcor_effect.Contrast ~= v then colorcor_effect.Contrast = v end
			v = shader_data.tfbghuugbnjhg
			if colorcor_effect.Saturation ~= v then colorcor_effect.Saturation = v end
			v = shader_data.fvrtccvghghj
			if colorcor_effect.TintColor ~= v then colorcor_effect.TintColor = v end
			if colorcor_effect.Enabled ~= true then colorcor_effect.Enabled = true end
		end
		if bloom_effect then
			v = shader_data.jnfdhbnfcvh
			if bloom_effect.Intensity ~= v then bloom_effect.Intensity = v end
			v = shader_data.fvtyghj
			if bloom_effect.Size ~= v then bloom_effect.Size = v end
			v = shader_data.ygbhnj
			if bloom_effect.Threshold ~= v then bloom_effect.Threshold = v end
			if bloom_effect.Enabled ~= true then bloom_effect.Enabled = true end
		end
		if blur_effect then
			v = shader_data.njnfg
			if blur_effect.Size ~= v then blur_effect.Size = v end
			if blur_effect.Enabled ~= false then blur_effect.Enabled = false end
		end
		if depth_effect then
			v = shader_data.jdfkd
			if depth_effect.FarIntensity ~= v then depth_effect.FarIntensity = v end
			v = shader_data.fvgsdfg
			if depth_effect.FocusDistance ~= v then depth_effect.FocusDistance = v end
			v = shader_data.sdkvkflv
			if depth_effect.InFocusRadius ~= v then depth_effect.InFocusRadius = v end
			v = shader_data.hbjhd
			if depth_effect.NearIntensity ~= v then depth_effect.NearIntensity = v end
			if depth_effect.Enabled ~= true then depth_effect.Enabled = true end
		end
		if atmosphere_effect then
			v = shader_data.shdbsnjfc
			if atmosphere_effect.Density ~= v then atmosphere_effect.Density = v end
			v = shader_data.skdjfkdm
			if atmosphere_effect.Offset ~= v then atmosphere_effect.Offset = v end
			v = shader_data.sjdjncdjf
			if atmosphere_effect.Color ~= v then atmosphere_effect.Color = v end
			v = shader_data.efjdjfk
			if atmosphere_effect.Decay ~= v then atmosphere_effect.Decay = v end
			v = shader_data.sejfd
			if atmosphere_effect.Glare ~= v then atmosphere_effect.Glare = v end
			v = shader_data.jddfjsd
			if atmosphere_effect.Haze ~= v then atmosphere_effect.Haze = v end
		end
		if cloud_effect then
			v = shader_data.gyhgtg
			if cloud_effect.Cover ~= v then cloud_effect.Cover = v end
			v = shader_data.ygbhggv
			if cloud_effect.Density ~= v then cloud_effect.Density = v end
			v = shader_data.jghbjhgyfd
			if cloud_effect.Color ~= v then cloud_effect.Color = v end
		end
	end
	
	local function restore_original()
		if original_effects.colorcor and colorcor_effect then
			for prop, value in pairs(original_effects.colorcor) do
				colorcor_effect[prop] = value
			end
		elseif created_effects.colorcor and colorcor_effect then
			colorcor_effect:Destroy()
			colorcor_effect = nil
			created_effects.colorcor = nil
		end
		if original_effects.bloom and bloom_effect then
			for prop, value in pairs(original_effects.bloom) do
				bloom_effect[prop] = value
			end
		elseif created_effects.bloom and bloom_effect then
			bloom_effect:Destroy()
			bloom_effect = nil
			created_effects.bloom = nil
		end
		if original_effects.blur and blur_effect then
			for prop, value in pairs(original_effects.blur) do
				blur_effect[prop] = value
			end
		elseif created_effects.blur and blur_effect then
			blur_effect:Destroy()
			blur_effect = nil
			created_effects.blur = nil
		end
		if original_effects.depth and depth_effect then
			for prop, value in pairs(original_effects.depth) do
				depth_effect[prop] = value
			end
		elseif created_effects.depth and depth_effect then
			depth_effect:Destroy()
			depth_effect = nil
			created_effects.depth = nil
		end
		if original_effects.atmosphere and atmosphere_effect then
			for prop, value in pairs(original_effects.atmosphere) do
				atmosphere_effect[prop] = value
			end
		elseif created_effects.atmosphere and atmosphere_effect then
			atmosphere_effect:Destroy()
			atmosphere_effect = nil
			created_effects.atmosphere = nil
		end
		if original_effects.cloud and cloud_effect then
			for prop, value in pairs(original_effects.cloud) do
				cloud_effect[prop] = value
			end
		elseif created_effects.cloud and cloud_effect then
			cloud_effect:Destroy()
			cloud_effect = nil
			created_effects.cloud = nil
		end
	end
	
	save_original_effects()
	local time_on, exposure_on, skybox_on = false, false, false
		local time_value, exposure_value = 12, 0
		local skybox_name = "Jungle"

		getgenv().WORLD_TIME_ENABLED = false
		getgenv().WORLD_EXPOSURE_ENABLED = false
		getgenv().WORLD_SKYBOX_ENABLED = false

		local skyboxes = {
			["Jungle"] = {
				SkyboxBk = "http://www.roblox.com/asset/?id=214399891",
				SkyboxDn = "http://www.roblox.com/asset/?id=214399887",
				SkyboxFt = "http://www.roblox.com/asset/?id=214399894",
				SkyboxLf = "http://www.roblox.com/asset/?id=214405668",
				SkyboxRt = "http://www.roblox.com/asset/?id=214399899",
				SkyboxUp = "http://www.roblox.com/asset/?id=214399889"
			},
			["Blossom"] = {
				SkyboxBk = "http://www.roblox.com/asset/?id=271042516",
				SkyboxDn = "http://www.roblox.com/asset/?id=271077243",
				SkyboxFt = "http://www.roblox.com/asset/?id=271042556",
				SkyboxLf = "http://www.roblox.com/asset/?id=271042310",
				SkyboxRt = "http://www.roblox.com/asset/?id=271042467",
				SkyboxUp = "http://www.roblox.com/asset/?id=271077958"
			},
			["Red night"] = {
				SkyboxBk = "http://www.roblox.com/Asset/?ID=401664839",
				SkyboxDn = "http://www.roblox.com/Asset/?ID=401664862",
				SkyboxFt = "http://www.roblox.com/Asset/?ID=401664960",
				SkyboxLf = "http://www.roblox.com/Asset/?ID=401664881",
				SkyboxRt = "http://www.roblox.com/Asset/?ID=401664901",
				SkyboxUp = "http://www.roblox.com/Asset/?ID=401664936"
			},
			["Purple default"] = {
				SkyboxBk = "http://www.roblox.com/asset/?id=13694952867",
				SkyboxDn = "http://www.roblox.com/asset/?id=13694968325",
				SkyboxFt = "http://www.roblox.com/asset/?id=13694980654",
				SkyboxLf = "http://www.roblox.com/asset/?id=13694998113",
				SkyboxRt = "http://www.roblox.com/asset/?id=13695002700",
				SkyboxUp = "http://www.roblox.com/asset/?id=13695007103"
			},
			["Foggy"] = {
				SkyboxBk = "rbxassetid://1370717244",
				SkyboxDn = "rbxassetid://1370717336",
				SkyboxFt = "rbxassetid://1370717438",
				SkyboxLf = "rbxassetid://1370717567",
				SkyboxRt = "rbxassetid://1370717698",
				SkyboxUp = "rbxassetid://1370717782"
			}
		}

		local sky_assets = {
			["Galaxy"] = 15983996673,
			["Anime"] = 13107361022,
			["Minecraft"] = 2758029221
		}

		local created_sky, original_sky, original_sky_parent = nil, nil, nil

		local function detach_original() 
			if original_sky then return end
			local existing = lighting:FindFirstChildOfClass("Sky")
			if existing and existing ~= created_sky then
				original_sky = existing
				original_sky_parent = existing.Parent
				pcall(function() existing.Parent = nil end)
			end
		end

		local function clear_created()
			if created_sky then
				pcall(function() created_sky:Destroy() end)
				created_sky = nil
			end
		end

		local function apply_textures(data)
			detach_original()
			clear_created()
			local sky = Instance.new("Sky")
			sky.Name = "ShitaroSky"
			for k, v in pairs(data) do
				pcall(function() sky[k] = v end)
			end
			sky.Parent = lighting
			created_sky = sky
		end

		local function apply_asset(id)
			task.spawn(function()
				local ok, objs = pcall(function() return game:GetObjects("rbxassetid://" .. id) end)
				if not ok or type(objs) ~= "table" then return end
				local found = nil
				for _, o in ipairs(objs) do
					if o:IsA("Sky") then
						found = o
						break
					end
					local s = o:FindFirstChildWhichIsA("Sky", true)
					if s then
						found = s
						break
					end
				end
				if not found or not skybox_on then return end
				detach_original()
				clear_created()
				found.Name = "ShitaroSky"
				found.Parent = lighting
				created_sky = found
			end)
		end

		local function apply_skybox(name)
			if skyboxes[name] then
				apply_textures(skyboxes[name])
			elseif sky_assets[name] then
				apply_asset(sky_assets[name])
			end
		end

		local function restore_skybox()
			clear_created()
			if original_sky then
				pcall(function() original_sky.Parent = original_sky_parent or lighting end)
				original_sky = nil
				original_sky_parent = nil
			end
		end
	do
		local aura_lp = game:GetService("Players").LocalPlayer
		local aura_ids = {
			angel = "97658130917593",
			starlight = "134645216613107",
			heavenly = "139300897520961",
			ribbon = "132069507632161",
			sakura = "81755778619404",
			wind = "80694081850877",
			flow = "119913533725648",
			star = "73754563740680"
		}
		local aura_order = {"angel", "starlight", "heavenly", "ribbon", "sakura", "wind", "flow", "star"}
		local aura_cache, aura_particles = {}, {}
		local aura_on, aura_type, aura_col, aura_conn = false, "angel", Color3.fromRGB(133, 220, 255), nil
		local aura_bt_conn = nil

		local aura_bt_accum = 0
		local aura_bt_stripped = setmetatable({}, {__mode = "k"})
		local aura_host = nil

		local AURA_GROUPS = {
			head = { "Head" },
			torso = { "Torso", "UpperTorso", "LowerTorso", "HumanoidRootPart", "Root" },
			larm = { "Left Arm", "LeftUpperArm", "LeftLowerArm", "LeftHand" },
			rarm = { "Right Arm", "RightUpperArm", "RightLowerArm", "RightHand" },
			lleg = { "Left Leg", "LeftUpperLeg", "LeftLowerLeg", "LeftFoot" },
			rleg = { "Right Leg", "RightUpperLeg", "RightLowerLeg", "RightFoot" },
		}

		local aura_group_of = {}
		for group, names in pairs(AURA_GROUPS) do
			for i = 1, #names do aura_group_of[names[i]] = group end
		end

		local function aura_fake_model()
			local rig = _G.FAKE_MODEL_RIG
			if typeof(rig) ~= "Instance" then return nil end
			if not rig:IsA("Model") or not rig.Parent then return nil end
			return rig
		end

		local function aura_center(host)
			local primary = host.PrimaryPart
			if primary and primary:IsA("BasePart") then return primary end
			local pick, best = nil, -1
			for _, d in ipairs(host:GetDescendants()) do
				if d:IsA("BasePart") then
					local size = d.Size
					local vol = size.X * size.Y * size.Z
					if vol > best then pick, best = d, vol end
				end
			end
			return pick
		end

		local function aura_slot(host, name, center)
			local direct = host:FindFirstChild(name, true)
			if direct and direct:IsA("BasePart") then return direct end
			local group = aura_group_of[name]
			if group then
				local names = AURA_GROUPS[group]
				for i = 1, #names do
					local part = host:FindFirstChild(names[i], true)
					if part and part:IsA("BasePart") then return part end
				end
			end
			return center
		end

		local function strip_backtrack_auras()
			local clones = _G.BACKTRACK_CLONES
			if not clones then return end
			for model in pairs(clones) do
				if typeof(model) == "Instance" and model.Parent then
					local desc = model:GetDescendants()
					local n = #desc
					if aura_bt_stripped[model] ~= n then
						for i = 1, n do
							local child = desc[i]
							if child:IsA("ParticleEmitter") or child:IsA("Beam") or child:IsA("Trail")
								or child:IsA("PointLight") or child:IsA("SpotLight") or child:IsA("SurfaceLight") then
								pcall(function() child:Destroy() end)
							end
						end
						aura_bt_stripped[model] = #model:GetDescendants()
					end
				end
			end
		end

		local function load_aura(name)
			if aura_cache[name] then return aura_cache[name] end
			local id = aura_ids[name]
			if not id then return nil end
			local ok, objs = pcall(game.GetObjects, game, "rbxassetid://"..id)
			if ok and objs and objs[1] then
				aura_cache[name] = objs[1]
				return objs[1]
			end
			return nil
		end

		local function color_aura(model, color)
			local seq = ColorSequence.new(color)
			for _, d in ipairs(model:GetDescendants()) do
				if d:IsA("PointLight") then
					d.Color = color
				elseif d:IsA("ParticleEmitter") or d:IsA("Beam") or d:IsA("Trail") then
					d.Color = seq
				end
			end
		end

		local function clear_aura()
			for i = #aura_particles, 1, -1 do
				pcall(function() aura_particles[i]:Destroy() end)
				aura_particles[i] = nil
			end
			
			local function clean_model(model)
				if not model then return end
				if _G.BACKTRACK_CLONES and _G.BACKTRACK_CLONES[model] then return end
				if _G.VIEWPORT_CLONE and model == _G.VIEWPORT_CLONE then return end
				
				for _, part in ipairs(model:GetChildren()) do
					if part:IsA("BasePart") then
						for _, child in ipairs(part:GetChildren()) do
							if child:IsA("ParticleEmitter") or child:IsA("Beam") or child:IsA("Trail") or child:IsA("PointLight") then
								local is_aura = false
								for aura_name, _ in pairs(aura_ids) do
									if child.Name:lower():find(aura_name) or child.Name:find("Aura") or child.Name:find("Effect") then
										is_aura = true
										break
									end
								end
								if is_aura then
									pcall(function() child:Destroy() end)
								end
							end
						end
					end
				end
			end
			
			local char = aura_lp.Character
			if char then
				clean_model(char)
			end
			
			for _, obj in ipairs(workspace:GetChildren()) do
				if obj:IsA("Model") and obj.Name == aura_lp.Name then
					clean_model(obj)
				end
			end
			
			local players_folder = workspace:FindFirstChild("Players")
			if players_folder then
				for _, obj in ipairs(players_folder:GetChildren()) do
					if obj:IsA("Model") and obj.Name == aura_lp.Name then
						clean_model(obj)
					end
				end
			end
		end

		local function aura_real_char()
			local char = aura_lp.Character
			if not char then return nil end
			if _G.BACKTRACK_CLONES and _G.BACKTRACK_CLONES[char] then return nil end
			if _G.VIEWPORT_CLONE and char == _G.VIEWPORT_CLONE then return nil end
			if char:GetAttribute("1") then return nil end
			if char.Parent == workspace then return char end
			for _, obj in ipairs(workspace:GetChildren()) do
				if obj:IsA("Model") and obj.Name == aura_lp.Name then
					if not (_G.BACKTRACK_CLONES and _G.BACKTRACK_CLONES[obj]) and obj ~= _G.VIEWPORT_CLONE and not obj:GetAttribute("1") then
						local hrp = obj:FindFirstChild("HumanoidRootPart")
						if hrp and hrp:IsA("BasePart") then return obj end
					end
				end
			end
			return nil
		end

		local function aura_resolve_host()
			local fake = aura_fake_model()
			if fake then return fake, true end
			return aura_real_char(), false
		end

		local function apply_aura()
			clear_aura()
			aura_host = nil

			local host, is_fake = aura_resolve_host()
			if not host then return end

			local src = load_aura(aura_type)
			if not src then return end
			color_aura(src, aura_col)
			local center = is_fake and aura_center(host) or nil
			local cloned = src:Clone()
			for _, part in ipairs(cloned:GetChildren()) do
				local target
				if is_fake then
					target = aura_slot(host, part.Name, center)
				else
					target = host:FindFirstChild(part.Name)
				end
				if target and target:IsA("BasePart") then
					for _, child in ipairs(part:GetChildren()) do
						child.Parent = target
						aura_particles[#aura_particles+1] = child
					end
				end
			end
			cloned:Destroy()
			aura_host = host
		end

		local function aura_sync()
			if not aura_on then return end
			local host = aura_resolve_host()
			if host ~= aura_host then
				apply_aura()
				return
			end
			if not host then return end
			local first = aura_particles[1]
			if first and not first.Parent then apply_aura() end
		end

		local aura_tgl = visuals_right:AddToggle({
			Name = "aura",
			Default = false,
			Flag = "world_aura",
			Option = true,
			Callback = function(v)
				aura_on = v
				clear_aura()
				aura_host = nil
				if aura_conn then pcall(function() aura_conn:Disconnect() end) aura_conn = nil end
				if aura_bt_conn then pcall(function() aura_bt_conn:Disconnect() end) aura_bt_conn = nil end
				if v then
					task.spawn(apply_aura)
					aura_conn = aura_lp.CharacterAdded:Connect(function()
						task.wait(0.5)
						if aura_on then apply_aura() end
					end)
					aura_bt_accum = 0
					table.clear(aura_bt_stripped)
					aura_bt_conn = game:GetService("RunService").Heartbeat:Connect(function(dt)
						aura_bt_accum = aura_bt_accum + dt
						if aura_bt_accum < 0.2 then return end
						aura_bt_accum = 0
						strip_backtrack_auras()
						aura_sync()
					end)
				end
			end
		})

		aura_tgl.Option:AddDropdown({
			Name = "type",
			Default = "angel",
			Values = aura_order,
			Flag = "world_aura_type",
			Callback = function(v)
				aura_type = type(v) == "table" and v[1] or v
				if aura_on then task.spawn(apply_aura) end
			end
		})

		aura_tgl.Option:AddColorPicker({
			Name = "color",
			Default = aura_col,
			Flag = "world_aura_col",
			Callback = function(c)
				aura_col = c
				for _, m in pairs(aura_cache) do color_aura(m, c) end
				if aura_on then task.spawn(apply_aura) end
			end
		})

		getgenv().AURA_UNLOAD = function()
			aura_on = false
			if aura_conn then pcall(function() aura_conn:Disconnect() end) aura_conn = nil end
			if aura_bt_conn then pcall(function() aura_bt_conn:Disconnect() end) aura_bt_conn = nil end
			table.clear(aura_bt_stripped)
			clear_aura()
			aura_host = nil
		end
	end
	local function disable_shader()
		shader_enabled = false
		if shader_connection then
			shader_connection:Disconnect()
			shader_connection = nil
		end
		restore_original()
		lighting.Ambient = getgenv().WORLD_AMBIENT_ENABLED and getgenv().WORLD_AMBIENT_COLOR or originalAmbient
		lighting.OutdoorAmbient = getgenv().WORLD_AMBIENT_ENABLED and getgenv().WORLD_AMBIENT_COLOR or originalOutdoorAmbient
		lighting.Brightness = getgenv().WORLD_FULLBRIGHT_ENABLED and 2 or originalBrightness
		lighting.FogColor = getgenv().WORLD_FOG_ENABLED and getgenv().WORLD_FOG_COLOR or originalFogColor
		lighting.FogStart = getgenv().WORLD_FOG_ENABLED and getgenv().WORLD_FOG_START or originalFogStart
		lighting.FogEnd = getgenv().WORLD_FOG_ENABLED and getgenv().WORLD_FOG_END or (getgenv().WORLD_FULLBRIGHT_ENABLED and 100000 or originalFogEnd)
		lighting.GlobalShadows = getgenv().WORLD_FULLBRIGHT_ENABLED and false or originalGlobalShadows
		lighting.ClockTime = getgenv().WORLD_FULLBRIGHT_ENABLED and 14 or originalClockTime
		lighting.ColorShift_Bottom = originalColorShift_Bottom
		lighting.ColorShift_Top = originalColorShift_Top
		lighting.EnvironmentDiffuseScale = originalEnvironmentDiffuseScale
		lighting.EnvironmentSpecularScale = originalEnvironmentSpecularScale
		lighting.GeographicLatitude = originalGeographicLatitude
		lighting.ExposureCompensation = originalExposureCompensation
	end

	getgenv().SHADER_UNLOAD = disable_shader
	local skybox_tgl = visuals_right:AddToggle({
			Name = "skybox",
			Default = false,
			Flag = "world_skybox",
			Option = true,
			Callback = function(v)
				skybox_on = v
				getgenv().WORLD_SKYBOX_ENABLED = v
				if v then apply_skybox(skybox_name) else restore_skybox() end
			end
		})

		skybox_tgl.Option:AddDropdown({
			Name = "preset",
			Default = "Jungle",
			Values = {"Purple", "Red night", "Blossom", "Jungle", "Foggy", "Galaxy", "Anime", "Minecraft"},
			Flag = "world_skybox_preset",
			Callback = function(v)
				skybox_name = type(v) == "table" and v[1] or v
				if skybox_on then apply_skybox(skybox_name) end
			end
		})
	local shaderToggle = visuals_right:AddToggle({
		Name = "shaders",
		Default = false,
		Flag = "world_shader_enabled",
		Option = true,
		Callback = function(v)
			shader_enabled = v
			if v then
				apply_shader(shaders[shader_type])
				if not shader_connection then
					local shader_accum = 0
					shader_connection = game:GetService("RunService").Heartbeat:Connect(function(dt)
						if not shader_enabled then return end
						local d = shaders[shader_type]
						shader_accum = shader_accum + dt
						if shader_accum >= 1 then
							shader_accum = 0
							apply_shader(d)
							return
						end
						if lighting.Ambient ~= d.yfbghj
							or lighting.Brightness ~= d.khnbfth
							or lighting.ClockTime ~= d.tgvbyd
							or lighting.OutdoorAmbient ~= d.hyhnngtf
							or lighting.ExposureCompensation ~= d.hdfr7thgr
							or lighting.GlobalShadows ~= d.hgnujuu7thgr
							or lighting.ColorShift_Top ~= d.yfbhjku
							or lighting.FogEnd ~= math.huge then
							apply_shader(d)
						end
					end)
				end
			else
				disable_shader()
			end
		end
	})
	
	shaderToggle.Option:AddDropdown({
		Name = "preset",
		Default = "morning",
		Values = {"morning", "midday", "evening", "night"},
		Flag = "world_shader_type",
		Callback = function(selected)
			shader_type = selected
			if shader_enabled then
				apply_shader(shaders[shader_type])
			end
		end
	})


		
	do
		local UserInputService = game:GetService("UserInputService")
		local RunService = game:GetService("RunService")
		local Players = game:GetService("Players")
		local LP = Players.LocalPlayer
		local Camera = workspace.CurrentCamera
		
		local crosshair_lines = {}
		local crosshair_enabled = false
		local crosshair_hidden_game_cursor = false
		local original_cursor_icon = nil
		local gun_equipped = false
		local game_crosshair_gui = nil
		local game_crosshair_hook_conn = nil
		local mouse_icon_hook = nil
		local mouse_icon_hook_active = false
		
		local gap_size = 4
		local line_length = 8
		local line_thickness = 2
		local line_color = Color3.fromRGB(255, 255, 255)
		local outline_color = Color3.fromRGB(0, 0, 0)
		local rotation_speed = 0
		
		local current_rotation = 0
		local crosshair_connection = nil
		local gun_watch_connections = {}
		local crosshair_angles = { 0, 0, 0, 0 }
		
		local function has_gun_equipped()
			local char = LP.Character
			if char and char:FindFirstChild("Gun") then
				return true
			end
			return false
		end
		
		local function create_crosshair_lines()
			for i = 1, 8 do
				local line = Drawing.new("Line")
				line.Visible = false
				line.Color = (i % 2 == 0) and outline_color or line_color
				line.Thickness = (i % 2 == 0) and line_thickness + 2 or line_thickness
				line.Transparency = 1
				line.ZIndex = (i % 2 == 0) and 999 or 1000
				crosshair_lines[i] = line
			end
		end
		
		local function destroy_crosshair_lines()
			for i = 1, #crosshair_lines do
				if crosshair_lines[i] then
					pcall(function() crosshair_lines[i]:Remove() end)
					crosshair_lines[i] = nil
				end
			end
		end
		
		local function update_crosshair_visibility(show, equipped)
			if equipped == nil then
				equipped = has_gun_equipped()
			end
			gun_equipped = equipped
			local should_show = show and crosshair_enabled and gun_equipped
			
			for i = 1, #crosshair_lines do
				if crosshair_lines[i] then
					crosshair_lines[i].Visible = should_show
				end
			end
		end
		
		local function hide_game_crosshair_gui()
			local pg = LP:FindFirstChild("PlayerGui")
			if not pg then return end
			local topbar = pg:FindFirstChild("GameTopbar")
			if not topbar then return end
			local crosshair = topbar:FindFirstChild("Crosshair")
			if crosshair and crosshair:IsA("GuiObject") then
				game_crosshair_gui = crosshair
				crosshair.Visible = false
			end
		end
		
		local function show_game_crosshair_gui()
			if game_crosshair_gui and game_crosshair_gui.Parent then
				pcall(function()
					if game_crosshair_gui:IsA("GuiObject") then
						game_crosshair_gui.Visible = true
					end
				end)
			end
		end
		
		local function setup_mouse_icon_hook()
			mouse_icon_hook_active = true
			if mouse_icon_hook then return end
			
			mouse_icon_hook = hookmetamethod(game, "__newindex", function(self, property, value)
				if property == "Icon" and mouse_icon_hook_active and crosshair_hidden_game_cursor
					and checkcaller() == false and self:IsA("Mouse") then
					if value == "rbxassetid://79658449" or value == "" then
						return
					end
				end
				return mouse_icon_hook(self, property, value)
			end)
		end
		
		local function remove_mouse_icon_hook()
			mouse_icon_hook_active = false
		end
		
		local function hide_game_cursor(hide)
			if hide and crosshair_hidden_game_cursor then
				setup_mouse_icon_hook()
				local mouse = LP:GetMouse()
				if mouse then
					mouse.Icon = ""
				end
				hide_game_crosshair_gui()
			else
				remove_mouse_icon_hook()
				local mouse = LP:GetMouse()
				if mouse then
					mouse.Icon = ""
				end
				if not crosshair_enabled then
					show_game_crosshair_gui()
				end
			end
		end
		
		local function update_crosshair(dt)
			if not crosshair_enabled or #crosshair_lines == 0 then return end
			
			local equipped = has_gun_equipped()
			gun_equipped = equipped
			if not equipped then
				update_crosshair_visibility(false, equipped)
				return
			end
			
			local mouse_pos = UserInputService:GetMouseLocation()
			local center_x = mouse_pos.X
			local center_y = mouse_pos.Y
			
			if rotation_speed > 0 then
				current_rotation = (current_rotation + dt * rotation_speed * 100) % 360
			else
				current_rotation = 0
			end
			
			local rad = math.rad(current_rotation)
			local cos = math.cos
			local sin = math.sin
			local pi = math.pi
			
			crosshair_angles[1] = rad
			crosshair_angles[2] = pi/2 + rad
			crosshair_angles[3] = pi + rad
			crosshair_angles[4] = 3*pi/2 + rad
			
			for i = 1, 4 do
				local angle = crosshair_angles[i]
				local line_idx = (i - 1) * 2 + 1
				local outline_idx = line_idx + 1
				
				local start_x = center_x + gap_size * cos(angle)
				local start_y = center_y + gap_size * sin(angle)
				local end_x = center_x + (gap_size + line_length) * cos(angle)
				local end_y = center_y + (gap_size + line_length) * sin(angle)
				
				local outline_start_x = center_x + (gap_size - 1) * cos(angle)
				local outline_start_y = center_y + (gap_size - 1) * sin(angle)
				local outline_end_x = center_x + (gap_size + line_length + 1) * cos(angle)
				local outline_end_y = center_y + (gap_size + line_length + 1) * sin(angle)
				
				if crosshair_lines[line_idx] then
					crosshair_lines[line_idx].From = Vector2.new(start_x, start_y)
					crosshair_lines[line_idx].To = Vector2.new(end_x, end_y)
				end
				
				if crosshair_lines[outline_idx] then
					crosshair_lines[outline_idx].From = Vector2.new(outline_start_x, outline_start_y)
					crosshair_lines[outline_idx].To = Vector2.new(outline_end_x, outline_end_y)
				end
			end
			
			update_crosshair_visibility(true, equipped)
		end
		
		local function start_crosshair()
			if crosshair_connection then return end
			
			if #crosshair_lines == 0 then
				create_crosshair_lines()
			end
			
			crosshair_connection = RunService.RenderStepped:Connect(update_crosshair)
			
			local function watch_gun(container)
				if not container then return end
				local conn1 = container.ChildAdded:Connect(function(child)
					if child.Name == "Gun" then
						hide_game_crosshair_gui()
						update_crosshair_visibility(true)
						hide_game_cursor(true)
					end
				end)
				local conn2 = container.ChildRemoved:Connect(function(child)
					if child.Name == "Gun" then
						update_crosshair_visibility(false)
						hide_game_cursor(false)
					end
				end)
				table.insert(gun_watch_connections, conn1)
				table.insert(gun_watch_connections, conn2)
			end
			
			if not game_crosshair_hook_conn then
				local pg = LP:FindFirstChild("PlayerGui")
				if pg then
					game_crosshair_hook_conn = pg.DescendantAdded:Connect(function(descendant)
						if descendant.Name == "Crosshair" and descendant.Parent and descendant.Parent.Name == "GameTopbar" then
							if crosshair_hidden_game_cursor and descendant:IsA("GuiObject") then
								descendant.Visible = false
								game_crosshair_gui = descendant
							end
						end
					end)
				end
			end
			
			local char = LP.Character
			if char then
				watch_gun(char)
			end
			
			local backpack = LP:FindFirstChildOfClass("Backpack")
			if backpack then
				watch_gun(backpack)
			end
			
			local char_conn = LP.CharacterAdded:Connect(function(new_char)
				task.wait(0.3)
				watch_gun(new_char)
				watch_gun(LP:FindFirstChildOfClass("Backpack"))
				gun_equipped = has_gun_equipped()
				update_crosshair_visibility(true, gun_equipped)
				hide_game_cursor(gun_equipped and crosshair_hidden_game_cursor)
			end)
			table.insert(gun_watch_connections, char_conn)
			
			gun_equipped = has_gun_equipped()
			update_crosshair_visibility(true, gun_equipped)
			hide_game_cursor(gun_equipped and crosshair_hidden_game_cursor)
		end
		
		local function stop_crosshair()
			if crosshair_connection then
				pcall(function() crosshair_connection:Disconnect() end)
				crosshair_connection = nil
			end
			
			if game_crosshair_hook_conn then
				pcall(function() game_crosshair_hook_conn:Disconnect() end)
				game_crosshair_hook_conn = nil
			end
			
			for _, conn in ipairs(gun_watch_connections) do
				pcall(function() conn:Disconnect() end)
			end
			gun_watch_connections = {}
			
			update_crosshair_visibility(false)
			hide_game_cursor(false)
			show_game_crosshair_gui()
			destroy_crosshair_lines()
		end
		
		local crosshair_toggle = visuals_right:AddToggle({
			Name = "crosshair",
			Default = false,
			Flag = "sheriffcros",
			Option = true,
			Callback = function(v)
				crosshair_enabled = v
				if v then
					start_crosshair()
				else
					stop_crosshair()
				end
			end
		})
		
		crosshair_toggle.Option:AddToggle({
			Name = "hide original",
			Default = false,
			Flag = "hidegame",
			Callback = function(v)
				crosshair_hidden_game_cursor = v
				if gun_equipped and crosshair_enabled then
					hide_game_cursor(v)
				end
			end
		})
		
		crosshair_toggle.Option:AddSlider({
			Name = "gap",
			Default = 4,
			Min = 0,
			Max = 20,
			Round = 1,
			Flag = "gap",
			Callback = function(v)
				gap_size = v
			end
		})
		
		crosshair_toggle.Option:AddSlider({
			Name = "line",
			Default = 8,
			Min = 2,
			Max = 30,
			Round = 1,
			Flag = "length",
			Callback = function(v)
				line_length = v
			end
		})
		
		crosshair_toggle.Option:AddSlider({
			Name = "thickness",
			Default = 2,
			Min = 1,
			Max = 5,
			Round = 1,
			Flag = "thickness",
			Callback = function(v)
				line_thickness = v
				for i = 1, #crosshair_lines do
					if crosshair_lines[i] then
						crosshair_lines[i].Thickness = (i % 2 == 0) and v + 2 or v
					end
				end
			end
		})
		
		crosshair_toggle.Option:AddSlider({
			Name = "rotation",
			Default = 0,
			Min = 0,
			Max = 10,
			Round = 1,
			Flag = "rotation",
			Callback = function(v)
				rotation_speed = v
			end
		})
		
		crosshair_toggle.Option:AddColorPicker({
			Name = "line",
			Default = Color3.fromRGB(255, 255, 255),
			Flag = "croslinec",
			Callback = function(c)
				line_color = c
				for i = 1, #crosshair_lines do
					if crosshair_lines[i] and i % 2 == 1 then
						crosshair_lines[i].Color = c
					end
				end
			end
		})
		
		crosshair_toggle.Option:AddColorPicker({
			Name = "outline",
			Default = Color3.fromRGB(0, 0, 0),
			Flag = "crosoutlinec",
			Callback = function(c)
				outline_color = c
				for i = 1, #crosshair_lines do
					if crosshair_lines[i] and i % 2 == 0 then
						crosshair_lines[i].Color = c
					end
				end
			end
		})
		
		getgenv().CROSSHAIR_UNLOAD = function()
			crosshair_enabled = false
			stop_crosshair()
		end
	end
	local fullbright = visuals_right:AddToggle({
		Name = "fullbright",
		Default = false,
		Flag = "world_fullbright",
		Callback = function(v)
			getgenv().WORLD_FULLBRIGHT_ENABLED = v
			if v then
				lighting.Brightness = 2
				lighting.ClockTime = 14
				lighting.GlobalShadows = false
				lighting.OutdoorAmbient = Color3.fromRGB(128, 128, 128)
				if not getgenv().WORLD_FOG_ENABLED then
					lighting.FogEnd = 100000
				end
			else
				lighting.Brightness = originalBrightness
				lighting.GlobalShadows = originalGlobalShadows
				lighting.OutdoorAmbient = getgenv().WORLD_AMBIENT_ENABLED and getgenv().WORLD_AMBIENT_COLOR or originalOutdoorAmbient
				if getgenv().WORLD_FOG_ENABLED then
					lighting.FogEnd = getgenv().WORLD_FOG_END
				else
					lighting.FogEnd = originalFogEnd
				end
			end
		end
	})
	local customFog = visuals_right:AddToggle({
		Name = "custom fog",
		Default = false,
		Flag = "world_custom_fog",
		Option = true,
		Callback = function(v)
			getgenv().WORLD_FOG_ENABLED = v
			if v then
				lighting.FogColor = getgenv().WORLD_FOG_COLOR
				lighting.FogStart = getgenv().WORLD_FOG_START
				lighting.FogEnd = getgenv().WORLD_FOG_END
			else
				lighting.FogColor = originalFogColor
				lighting.FogStart = originalFogStart
				lighting.FogEnd = originalFogEnd
			end
		end
	})
	
	customFog.Option:AddColorPicker({
		Name = "color",
		Default = Color3.fromRGB(192, 192, 192),
		Flag = "world_fog_color",
		Callback = function(c)
			getgenv().WORLD_FOG_COLOR = c
			if getgenv().WORLD_FOG_ENABLED then
				lighting.FogColor = c
			end
		end
	})
	
	customFog.Option:AddSlider({
		Name = "start",
		Default = 0,
		Min = 0,
		Max = 1000,
		Round = 1,
		Flag = "world_fog_start",
		Callback = function(v)
			getgenv().WORLD_FOG_START = v
			if getgenv().WORLD_FOG_ENABLED then
				lighting.FogStart = v
			end
		end
	})
	
	customFog.Option:AddSlider({
		Name = "end",
		Default = 1000,
		Min = 0,
		Max = 1000,
		Round = 1,
		Flag = "world_fog_end",
		Callback = function(v)
			getgenv().WORLD_FOG_END = v
			if getgenv().WORLD_FOG_ENABLED then
				lighting.FogEnd = v
			end
		end
	})
	
		local time_tgl = visuals_right:AddToggle({
			Name = "time changer",
			Default = false,
			Flag = "world_time",
			Option = true,
			Callback = function(v)
				time_on = v
				getgenv().WORLD_TIME_ENABLED = v
				lighting.ClockTime = v and time_value or originalClockTime
			end
		})

		time_tgl.Option:AddSlider({
			Name = "time",
			Default = 12,
			Min = 0,
			Max = 24,
			Round = 1,
			Flag = "world_time_value",
			Callback = function(v)
				time_value = v
				if time_on then lighting.ClockTime = v end
			end
		})
do
		local RunService = game:GetService("RunService")
		local SOFT = "rbxasset://textures/particles/smoke_main.dds"

		local fx_on, fx_type, fx_color, fx_rate = false, "Snow", Color3.fromRGB(150, 200, 255), 250
		local fx_part, fx_emitter, fx_conn, fx_pos, fx_look = nil, nil, nil, nil, nil
		local FX_SPAN, FX_TALL = 260, 140

		local function style_emitter(t)
			local e = fx_emitter
			if not e then return end
			e.Texture = SOFT
			e.LightInfluence = 0
			e.LightEmission = 0.4
			e.ZOffset = 0
			e.Drag = 0
			e.EmissionDirection = Enum.NormalId.Bottom
			e.Rate = fx_rate
			e.Color = ColorSequence.new(fx_color)
			if t == "Snow" then
				e.Lifetime = NumberRange.new(4, 6)
				e.Speed = NumberRange.new(6, 12)
				e.Acceleration = Vector3.new(2, -6, 1)
				e.SpreadAngle = Vector2.new(35, 35)
				e.Rotation = NumberRange.new(0, 360)
				e.RotSpeed = NumberRange.new(-40, 40)
				e.Squash = NumberSequence.new(0)
				e.Size = NumberSequence.new(0.55)
				e.Transparency = NumberSequence.new({
					NumberSequenceKeypoint.new(0, 0.2),
					NumberSequenceKeypoint.new(0.8, 0.3),
					NumberSequenceKeypoint.new(1, 1)
				})
			else
				e.Lifetime = NumberRange.new(5, 7)
				e.Speed = NumberRange.new(5, 10)
				e.Acceleration = Vector3.new(4, -5, 2)
				e.SpreadAngle = Vector2.new(40, 40)
				e.Rotation = NumberRange.new(0, 360)
				e.RotSpeed = NumberRange.new(-80, 80)
				e.Squash = NumberSequence.new(1.4)
				e.Size = NumberSequence.new(0.5)
				e.Transparency = NumberSequence.new({
					NumberSequenceKeypoint.new(0, 0.15),
					NumberSequenceKeypoint.new(0.85, 0.25),
					NumberSequenceKeypoint.new(1, 1)
				})
			end
		end

		local function stop_fx()
			if fx_conn then pcall(function() fx_conn:Disconnect() end) fx_conn = nil end
			if fx_part then pcall(function() fx_part:Destroy() end) fx_part = nil end
			fx_emitter = nil
			fx_pos = nil
			fx_look = nil
		end

		local function ensure_part()
			if fx_part and fx_part.Parent then return end
			fx_part = Instance.new("Part")
			fx_part.Name = "SHITARO_WORLD_FX"
			fx_part.Anchored = true
			fx_part.CanCollide = false
			fx_part.CanQuery = false
			fx_part.CanTouch = false
			fx_part.Transparency = 1
			fx_part.Size = Vector3.new(FX_SPAN, FX_TALL, FX_SPAN)
			fx_part.Parent = workspace
			fx_emitter = Instance.new("ParticleEmitter")
			pcall(function()
				fx_emitter.Shape = Enum.ParticleEmitterShape.Box
				fx_emitter.ShapeStyle = Enum.ParticleEmitterShapeStyle.Volume
			end)
			fx_emitter.Parent = fx_part
			style_emitter(fx_type)
		end

		local function burst_fx()
			if not fx_emitter then return end
			fx_emitter:Emit(math.clamp(math.floor(fx_rate*0.16), 30, 140))
		end

		local function start_fx()
			ensure_part()
			if fx_conn then return end
			fx_pos = nil
			fx_look = nil
			fx_conn = RunService.RenderStepped:Connect(function()
				if not (fx_part and fx_part.Parent) then return end
				local cam = workspace.CurrentCamera
				if not cam then return end
				local cf = cam.CFrame
				local p = cf.Position
				local d = cf.LookVector
				local flat = Vector3.new(d.X, 0, d.Z)
				if flat.Magnitude < 0.05 then
					flat = Vector3.new(0, 0, -1)
				else
					flat = flat.Unit
				end
				if fx_pos and fx_look and (p - fx_pos).Magnitude < 10 and flat:Dot(fx_look) > 0.95 then return end
				fx_pos = p
				fx_look = flat
				fx_part.CFrame = CFrame.new(p + flat * (FX_SPAN * 0.22) + Vector3.new(0, FX_TALL * 0.5 - 26, 0))
			end)
			burst_fx()
		end

		local fx_tgl = visuals_right:AddToggle({
			Name = "world effects",
			Default = false,
			Flag = "world_effects",
			Option = true,
			Callback = function(v)
				fx_on = v
				if v then start_fx() else stop_fx() end
			end
		})

		fx_tgl.Option:AddDropdown({
			Name = "preset",
			Default = "Snow",
			Values = {"Snow", "Sakura"},
			Flag = "world_effects_type",
			Callback = function(v)
				fx_type = type(v) == "table" and v[1] or v
				if fx_on then
					style_emitter(fx_type)
					burst_fx()
				end
			end
		})

		fx_tgl.Option:AddColorPicker({
			Name = "color",
			Default = fx_color,
			Flag = "world_effects_color",
			Callback = function(c)
				fx_color = c
				if fx_emitter then fx_emitter.Color = ColorSequence.new(c) end
			end
		})

		fx_tgl.Option:AddSlider({
			Name = "range",
			Default = 250,
			Min = 20,
			Max = 900,
			Round = 1,
			Flag = "world_effects_rate",
			Callback = function(v)
				fx_rate = v
				if fx_emitter then
					style_emitter(fx_type)
					burst_fx()
				end
			end
		})

		getgenv().WORLD_FX_UNLOAD = function()
			fx_on = false
			stop_fx()
		end
	end
	local ambient = visuals_right:AddToggle({
		Name = "ambient",
		Default = false,
		Flag = "world_custom_ambient",
		Option = true,
		Callback = function(v)
			getgenv().WORLD_AMBIENT_ENABLED = v
			if v then
				lighting.Ambient = getgenv().WORLD_AMBIENT_COLOR
				lighting.OutdoorAmbient = getgenv().WORLD_AMBIENT_COLOR
			else
				lighting.Ambient = originalAmbient
				lighting.OutdoorAmbient = originalOutdoorAmbient
			end
		end
	})
	
	ambient.Option:AddColorPicker({
		Name = "color",
		Default = Color3.fromRGB(128, 128, 128),
		Flag = "world_ambient_color",
		Callback = function(c)
			getgenv().WORLD_AMBIENT_COLOR = c
			if getgenv().WORLD_AMBIENT_ENABLED then
				lighting.Ambient = c
				lighting.OutdoorAmbient = c
			end
		end
	})
		local exposure_tgl = visuals_right:AddToggle({
			Name = "exposure",
			Default = false,
			Flag = "world_exposure",
			Option = true,
			Callback = function(v)
				exposure_on = v
				getgenv().WORLD_EXPOSURE_ENABLED = v
				lighting.ExposureCompensation = v and exposure_value or originalExposureCompensation
			end
		})

		exposure_tgl.Option:AddSlider({
			Name = "range",
			Default = 0,
			Min = -5,
			Max = 5,
			Round = 2,
			Flag = "world_exposure_value",
			Callback = function(v)
				exposure_value = v
				if exposure_on then lighting.ExposureCompensation = v end
			end
		})

		local exposure_watch = true

		local function enforce_exposure()
			if not exposure_on then return end
			if lighting.ExposureCompensation ~= exposure_value then
				lighting.ExposureCompensation = exposure_value
			end
		end

		pcall(function()
			lighting:GetPropertyChangedSignal("ExposureCompensation"):Connect(function()
				if exposure_watch then
					enforce_exposure()
				end
			end)
		end)

		task.spawn(function()
			while exposure_watch do
				task.wait(0.25)
				pcall(enforce_exposure)
			end
		end)

		

		getgenv().WORLD_EXTRA_UNLOAD = function()
			exposure_watch = false
			time_on, exposure_on, skybox_on = false, false, false
			getgenv().WORLD_TIME_ENABLED = false
			getgenv().WORLD_EXPOSURE_ENABLED = false
			getgenv().WORLD_SKYBOX_ENABLED = false
			pcall(function() lighting.ClockTime = originalClockTime end)
			pcall(function() lighting.ExposureCompensation = originalExposureCompensation end)
			restore_skybox()
		end

	
	
	
	
	
	
	

	

	

	local enable = visuals_left:AddToggle({
		Name = "global",
		Default = false,
		Flag = "esp_enable",
		Callback = function(v)
			esp.tSet.en.en = v
			if v and not esp._loaded then
				esp.Load()
				if _G.VIEWPORT_CLONE and _G.VIEWPORT_PLAYER and _G.VIEWPORT_FRAME then
					_G.FAKE_PLAYER = esp.AddClone(_G.VIEWPORT_CLONE, _G.VIEWPORT_PLAYER, _G.VIEWPORT_FRAME)
				end
			elseif not v and esp._loaded then
				if _G.FAKE_PLAYER then
					esp.RemoveClone(_G.FAKE_PLAYER)
					_G.FAKE_PLAYER = nil
				end
				esp.Unload()
			end
		end
	})

	local box = visuals_left:AddToggle({
		Name = "box",
		Default = false,
		Flag = "esp_box",
		Option = true,
		Callback = function(v)
			esp.tSet.en.box = v
		end
	})
	
	box.Option:AddColorPicker({
		Name = "color",
		Default = Color3.new(1,0,0),
		Transparency = 1,
		Flag = "esp_box_col",
		Callback = function(c, t)
			esp.tSet.en.boxCol = {c, t or 1}
		end
	})
	
	box.Option:AddDropdown({
		Name = "preset",
		Default = "Static",
		Values = {"Static", "Corners"},
		Flag = "esp_box_type",
		Callback = function(v)
			esp.tSet.en.boxType = v
		end
	})
	
	box.Option:AddToggle({
		Name = "gradient",
		Default = false,
		Flag = "esp_box_grd",
		Callback = function(v)
			esp.tSet.en.boxGrd = v
		end
	})
	
	box.Option:AddColorPicker({
		Name = "gradient 1",
		Default = Color3.new(1,0,0),
		Flag = "esp_box_grd1",
		Callback = function(c)
			esp.tSet.en.boxGrdCol[1] = c
		end
	})
	
	box.Option:AddColorPicker({
		Name = "gradient 2",
		Default = Color3.new(0,0,1),
		Flag = "esp_box_grd2",
		Callback = function(c)
			esp.tSet.en.boxGrdCol[2] = c
		end
	})
	
	box.Option:AddToggle({
		Name = "fill",
		Default = false,
		Flag = "esp_box_fill",
		Callback = function(v)
			esp.tSet.en.boxF = v
		end
	})
	
	box.Option:AddColorPicker({
		Name = "fill",
		Default = Color3.new(1,0,0),
		Transparency = 0.5,
		Flag = "esp_box_fill_col",
		Callback = function(c, t)
			esp.tSet.en.boxFCol = {c, t or 0.5}
		end
	})
	
	box.Option:AddToggle({
		Name = "fill gradient",
		Default = false,
		Flag = "esp_box_fill_grd",
		Callback = function(v)
			esp.tSet.en.boxFGrd = v
		end
	})
	
	box.Option:AddColorPicker({
		Name = "fill gradient 1",
		Default = Color3.new(1,0,0),
		Flag = "esp_box_fill_grd1",
		Callback = function(c)
			esp.tSet.en.boxFGrdCol[1] = c
		end
	})
	
	box.Option:AddColorPicker({
		Name = "fill gradient 2",
		Default = Color3.new(0,0,1),
		Flag = "esp_box_fill_grd2",
		Callback = function(c)
			esp.tSet.en.boxFGrdCol[2] = c
		end
	})
	local name = visuals_left:AddToggle({
		Name = "name",
		Default = false,
		Flag = "esp_name",
		Option = true,
		Callback = function(v)
			esp.tSet.en.name = v
		end
	})
	
	name.Option:AddColorPicker({
		Name = "color",
		Default = Color3.new(1,1,1),
		Transparency = 1,
		Flag = "esp_name_col",
		Callback = function(c, t)
			esp.tSet.en.nCol = {c, t or 1}
		end
	})
	
	name.Option:AddToggle({
		Name = "gradient",
		Default = false,
		Flag = "esp_name_grd",
		Callback = function(v)
			esp.tSet.en.nGrd = v
		end
	})
	
	name.Option:AddColorPicker({
		Name = "gradient 1",
		Default = Color3.new(1,1,1),
		Flag = "esp_name_grd1",
		Callback = function(c)
			esp.tSet.en.nGrdCol[1] = c
		end
	})
	
	name.Option:AddColorPicker({
		Name = "gradient 2",
		Default = Color3.new(1,0,0),
		Flag = "esp_name_grd2",
		Callback = function(c)
			esp.tSet.en.nGrdCol[2] = c
		end
	})
	
	local avatar = visuals_left:AddToggle({
		Name = "avatar",
		Default = false,
		Flag = "esp_avatar",
		Callback = function(v)
			esp.tSet.en.av = v
		end
	})
	esp.tSet.en.offArSz = 42
	esp.tSet.en.offArDis = 260
	local ar = visuals_left:AddToggle({
		Name = "arrows",
		Default = false,
		Flag = "esp_arrows",
		Option = true,
		Callback = function(v)
			esp.tSet.en.offAr = v
		end
	})

	ar.Option:AddColorPicker({
		Name = "murder",
		Default = Color3.fromRGB(255, 60, 60),
		Flag = "esp_arrow_mur",
		Callback = function(c)
			esp.tSet.en.offArColMur = {c, 1}
		end
	})

	ar.Option:AddColorPicker({
		Name = "innocent",
		Default = Color3.fromRGB(255, 255, 255),
		Flag = "esp_arrow_inno",
		Callback = function(c)
			esp.tSet.en.offArColInno = {c, 1}
		end
	})

	ar.Option:AddColorPicker({
		Name = "sheriff",
		Default = Color3.fromRGB(0, 153, 255),
		Flag = "esp_arrow_shf",
		Callback = function(c)
			esp.tSet.en.offArColShf = {c, 1}
		end
	})

	ar.Option:AddSlider({
		Name = "size",
		Min = 16,
		Max = 96,
		Default = 42,
		Flag = "esp_arrow_size",
		Callback = function(v)
			esp.tSet.en.offArSz = v
		end
	})

	ar.Option:AddSlider({
		Name = "distance",
		Min = 40,
		Max = 520,
		Default = 260,
		Flag = "esp_arrow_distance",
		Callback = function(v)
			esp.tSet.en.offArDis = v
		end
	})


	
	
	
	
	local dist = visuals_left:AddToggle({
		Name = "distance",
		Default = false,
		Flag = "esp_dist",
		Option = true,
		Callback = function(v)
			esp.tSet.en.dis = v
		end
	})
	
	dist.Option:AddColorPicker({
		Name = "color",
		Default = Color3.new(1,1,1),
		Transparency = 1,
		Flag = "esp_dist_col",
		Callback = function(c, t)
			esp.tSet.en.dCol = {c, t or 1}
		end
	})
	
	dist.Option:AddToggle({
		Name = "gradient",
		Default = false,
		Flag = "esp_dist_grd",
		Callback = function(v)
			esp.tSet.en.dGrd = v
		end
	})
	
	dist.Option:AddColorPicker({
		Name = "gradient 1",
		Default = Color3.new(1,1,1),
		Flag = "esp_dist_grd1",
		Callback = function(c)
			esp.tSet.en.dGrdCol[1] = c
		end
	})
	
	dist.Option:AddColorPicker({
		Name = "gradient 2",
		Default = Color3.new(1,0,0),
		Flag = "esp_dist_grd2",
		Callback = function(c)
			esp.tSet.en.dGrdCol[2] = c
		end
	})
	
	local skel = visuals_left:AddToggle({
		Name = "skeleton",
		Default = false,
		Flag = "esp_skel",
		Option = true,
		Callback = function(v)
			esp.tSet.en.skel = v
		end
	})
	
	skel.Option:AddColorPicker({
		Name = "color",
		Default = Color3.new(1,1,1),
		Transparency = 1,
		Flag = "esp_skel_col",
		Callback = function(c, t)
			esp.tSet.en.skelCol = {c, t or 1}
		end
	})
	
	local chams = visuals_left:AddToggle({
		Name = "glow chams",
		Default = false,
		Flag = "esp_chams",
		Option = true,
		Callback = function(v)
			esp.tSet.en.chams = v
		end
	})
	
	chams.Option:AddColorPicker({
		Name = "murder fill",
		Default = Color3.new(1,0,0),
		Transparency = 0.5,
		Flag = "esp_chams_fill_mur",
		Callback = function(c, t)
			esp.tSet.en.chamsFColMur = {c, t or 0.5}
		end
	})
	
	chams.Option:AddColorPicker({
		Name = "murder outline",
		Default = Color3.new(1,0,0),
		Transparency = 0,
		Flag = "esp_chams_out_mur",
		Callback = function(c, t)
			esp.tSet.en.chamsOColMur = {c, t or 0}
		end
	})
	
	chams.Option:AddColorPicker({
		Name = "innocent fill",
		Default = Color3.new(1,1,1),
		Transparency = 0.5,
		Flag = "esp_chams_fill_inno",
		Callback = function(c, t)
			esp.tSet.en.chamsFColInno = {c, t or 0.5}
		end
	})
	
	chams.Option:AddColorPicker({
		Name = "innocent outline",
		Default = Color3.new(1,1,1),
		Transparency = 0,
		Flag = "esp_chams_out_inno",
		Callback = function(c, t)
			esp.tSet.en.chamsOColInno = {c, t or 0}
		end
	})
	
	chams.Option:AddColorPicker({
		Name = "sheriff fill",
		Default = Color3.fromRGB(0,153,255),
		Transparency = 0.5,
		Flag = "esp_chams_fill_shf",
		Callback = function(c, t)
			esp.tSet.en.chamsFColShf = {c, t or 0.5}
		end
	})
	
	chams.Option:AddColorPicker({
		Name = "sheriff outline",
		Default = Color3.fromRGB(0,153,255),
		Transparency = 0,
		Flag = "esp_chams_out_shf",
		Callback = function(c, t)
			esp.tSet.en.chamsOColShf = {c, t or 0}
		end
	})

	local matChams = visuals_left:AddToggle({
		Name = "material chams",
		Default = false,
		Flag = "esp_mat_chams",
		Option = true,
		Callback = function(v)
			esp.tSet.en.matChams = v
		end
	})
	
	matChams.Option:AddDropdown({
		Name = "preset",
		Default = "ForceField",
		Values = {"ForceField", "Flat", "Chromatic"},
		Flag = "esp_mat_chams_type",
		Callback = function(v)
			esp.tSet.en.matChamsType = v
		end
	})
	
	matChams.Option:AddColorPicker({
		Name = "murder",
		Default = Color3.new(1,0,0),
		Flag = "esp_mat_chams_col_mur",
		Callback = function(c)
			esp.tSet.en.matChamsColMur = c
		end
	})
	
	matChams.Option:AddColorPicker({
		Name = "innocent",
		Default = Color3.new(1,1,1),
		Flag = "esp_mat_chams_col_inno",
		Callback = function(c)
			esp.tSet.en.matChamsColInno = c
		end
	})
	
	matChams.Option:AddColorPicker({
		Name = "sheriff",
		Default = Color3.fromRGB(0,153,255),
		Flag = "esp_mat_chams_col_shf",
		Callback = function(c)
			esp.tSet.en.matChamsColShf = c
		end
	})
	
	matChams.Option:AddColorPicker({
		Name = "murder visible",
		Default = Color3.new(1,0,0),
		Transparency = 0,
		Flag = "esp_mat_chams_vis_mur",
		Callback = function(c, t)
			esp.tSet.en.matChamsVisColMur = {c, t or 0}
		end
	})
	
	matChams.Option:AddColorPicker({
		Name = "murder occluded",
		Default = Color3.new(0,0,1),
		Transparency = 0,
		Flag = "esp_mat_chams_occ_mur",
		Callback = function(c, t)
			esp.tSet.en.matChamsOccColMur = {c, t or 0}
		end
	})
	
	matChams.Option:AddColorPicker({
		Name = "innocent visible",
		Default = Color3.new(1,1,1),
		Transparency = 0,
		Flag = "esp_mat_chams_vis_inno",
		Callback = function(c, t)
			esp.tSet.en.matChamsVisColInno = {c, t or 0}
		end
	})
	
	matChams.Option:AddColorPicker({
		Name = "innocent occluded",
		Default = Color3.fromRGB(77,77,77),
		Transparency = 0,
		Flag = "esp_mat_chams_occ_inno",
		Callback = function(c, t)
			esp.tSet.en.matChamsOccColInno = {c, t or 0}
		end
	})
	
	matChams.Option:AddColorPicker({
		Name = "sheriff visible",
		Default = Color3.fromRGB(0,153,255),
		Transparency = 0,
		Flag = "esp_mat_chams_vis_shf",
		Callback = function(c, t)
			esp.tSet.en.matChamsVisColShf = {c, t or 0}
		end
	})
	
	matChams.Option:AddColorPicker({
		Name = "sheriff occluded",
		Default = Color3.new(0,0,1),
		Transparency = 0,
		Flag = "esp_mat_chams_occ_shf",
		Callback = function(c, t)
			esp.tSet.en.matChamsOccColShf = {c, t or 0}
		end
	})
	
	local flags = visuals_left:AddToggle({
		Name = "flags",
		Default = false,
		Flag = "esp_flags",
		Option = true,
		Callback = function(v)
			esp.tSet.en.flag = v
		end
	})
	
	flags.Option:AddColorPicker({
		Name = "murder",
		Default = Color3.new(1,0,0),
		Transparency = 1,
		Flag = "esp_flag_mur",
		Callback = function(c, t)
			esp.tSet.en.flagMurCol = {c, t or 1}
		end
	})
	
	flags.Option:AddToggle({
		Name = "murder gradient",
		Default = false,
		Flag = "esp_flag_mur_grd",
		Callback = function(v)
			esp.tSet.en.flagMurGrd = v
		end
	})
	
	flags.Option:AddColorPicker({
		Name = "murder gradient 1",
		Default = Color3.new(1,0,0),
		Flag = "esp_flag_mur_grd1",
		Callback = function(c)
			esp.tSet.en.flagMurGrdCol[1] = c
		end
	})
	
	flags.Option:AddColorPicker({
		Name = "murder gradient 2",
		Default = Color3.fromRGB(255,128,0),
		Flag = "esp_flag_mur_grd2",
		Callback = function(c)
			esp.tSet.en.flagMurGrdCol[2] = c
		end
	})
	
	flags.Option:AddColorPicker({
		Name = "sheriff",
		Default = Color3.fromRGB(0,153,255),
		Transparency = 1,
		Flag = "esp_flag_shf",
		Callback = function(c, t)
			esp.tSet.en.flagShfCol = {c, t or 1}
		end
	})
	
	flags.Option:AddToggle({
		Name = "sheriff gradient",
		Default = false,
		Flag = "esp_flag_shf_grd",
		Callback = function(v)
			esp.tSet.en.flagShfGrd = v
		end
	})
	
	flags.Option:AddColorPicker({
		Name = "sheriff gradient 1",
		Default = Color3.fromRGB(0,153,255),
		Flag = "esp_flag_shf_grd1",
		Callback = function(c)
			esp.tSet.en.flagShfGrdCol[1] = c
		end
	})
	
	flags.Option:AddColorPicker({
		Name = "sheriff gradient 2",
		Default = Color3.fromRGB(0,255,255),
		Flag = "esp_flag_shf_grd2",
		Callback = function(c)
			esp.tSet.en.flagShfGrdCol[2] = c
		end
	})
	
	do
		local run = game:GetService("RunService")
		local core = game:GetService("CoreGui")
		local players = game:GetService("Players")

		local gun_esp_on = false
		local gun_text_on = false
		local gun_text_col = Color3.fromRGB(255, 255, 255)
		local gun_text_grd = false
		local gun_grd_c1 = Color3.fromRGB(255, 255, 255)
		local gun_grd_c2 = Color3.fromRGB(255, 0, 0)
		local gun_hl_on = false
		local gun_hl_col = Color3.fromRGB(255, 255, 255)

		local function gun_grad(p)
			return gun_grd_c1:Lerp(gun_grd_c2, math.sin(p * 3.1416 + os.clock() * 2) * 0.5 + 0.5)
		end

		local gun_cache = {}
		local gun_parts = {}
		local gun_scan_acc = 0
		local gun_candidates = {}
		local gun_render_conn = nil
		local gun_added_conn = nil
		local gun_removing_conn = nil

		local GUN_TEXT_CHARS = { "G", "u", "n" }
		local GUN_TEXT_LEN = 3

		local function in_character(obj)
			local node = obj.Parent
			while node and node ~= workspace do
				if node:IsA("Model") and players:GetPlayerFromCharacter(node) then
					return true
				end
				node = node.Parent
			end
			return false
		end

		local function render_part(obj)
			if obj:IsA("BasePart") then return obj end
			if obj:IsA("Model") then return obj.PrimaryPart or obj:FindFirstChildWhichIsA("BasePart", true) end
			return obj:FindFirstChild("Handle") or obj:FindFirstChildWhichIsA("BasePart", true)
		end

		local function gun_candidate_added(obj)
			if obj.Name ~= "GunDrop" then return end
			if obj:IsA("BasePart") or obj:IsA("Model") or obj:IsA("Tool") then
				gun_candidates[obj] = true
			end
		end

		local function gun_candidate_removing(obj)
			if obj.Name ~= "GunDrop" then return end
			gun_candidates[obj] = nil
		end

		local function seed_gun_candidates()
			table.clear(gun_candidates)
			for _, obj in ipairs(workspace:GetDescendants()) do
				if obj.Name == "GunDrop"
					and (obj:IsA("BasePart") or obj:IsA("Model") or obj:IsA("Tool")) then
					gun_candidates[obj] = true
				end
			end
		end

		local function collect_guns()
			local list = {}
			for obj in pairs(gun_candidates) do
				if obj.Name == "GunDrop"
					and obj.Parent
					and not in_character(obj) then
					local part = render_part(obj)
					if part then
						local adorn = (obj:IsA("BasePart") or obj:IsA("Model")) and obj or part
						list[#list + 1] = { obj = obj, part = part, adorn = adorn }
					end
				end
			end
			return list
		end

		local function clear_gun(obj)
			local e = gun_cache[obj]
			if e then
				if e.hl then pcall(function() e.hl:Destroy() end) end
				if e.txt then pcall(function() e.txt:Remove() end) end
				if e.gtxt then
					for i = 1, #e.gtxt do pcall(function() e.gtxt[i]:Remove() end) end
				end
				gun_cache[obj] = nil
			end
		end

		local function clear_guns()
			for obj in pairs(gun_cache) do clear_gun(obj) end
			gun_parts = {}
		end

		local function gun_render(dt)
			if not gun_esp_on then
				if next(gun_cache) then clear_guns() end
				return
			end
			gun_scan_acc = gun_scan_acc + dt
			if gun_scan_acc >= 0.25 then
				gun_scan_acc = 0
				gun_parts = collect_guns()
				local set = {}
				for _, entry in ipairs(gun_parts) do set[entry.obj] = true end
				for obj in pairs(gun_cache) do
					if not set[obj] then clear_gun(obj) end
				end
			end
			local cam = workspace.CurrentCamera
			for _, entry in ipairs(gun_parts) do
				local obj = entry.obj
				local part = entry.part
				if obj.Parent and part and part.Parent then
					local e = gun_cache[obj]
					if not e then e = {} gun_cache[obj] = e end
					if gun_hl_on then
						if not e.hl then
							local hl = Instance.new("Highlight")
							hl.FillTransparency = 1
							hl.DepthMode = Enum.HighlightDepthMode.AlwaysOnTop
							hl.Parent = core
							e.hl = hl
						end
						e.hl.Adornee = entry.adorn
						e.hl.OutlineColor = gun_hl_col
						e.hl.OutlineTransparency = 0
						e.hl.Enabled = true
					elseif e.hl then
						e.hl.Enabled = false
					end
					if gun_text_on then
						local sp = cam:WorldToViewportPoint(part.Position)
						if gun_text_grd then
							if e.txt then e.txt.Visible = false end
							if sp.Z > 0 then
								local pool = e.gtxt
								if not pool then pool = {} e.gtxt = pool end
								local widths = e.gw
								if not widths then widths = {} e.gw = widths end
								local wch = e.gwc
								if not wch then wch = {} e.gwc = wch end
								local wsz = e.gws
								if not wsz then wsz = {} e.gws = wsz end
								local wfn = e.gwf
								if not wfn then wfn = {} e.gwf = wfn end
								local n = GUN_TEXT_LEN
								local total = 0
								for i = 1, n do
									local o = pool[i]
									if not o then
										o = Drawing.new("Text")
										o.Center = false
										o.Outline = true
										o.Size = 13
										pool[i] = o
									end
									local ch = GUN_TEXT_CHARS[i]
									local sz = o.Size
									local fn = o.Font
									if wch[i] ~= ch or wsz[i] ~= sz or wfn[i] ~= fn then
										o.Text = ch
										wch[i] = ch
										wsz[i] = sz
										wfn[i] = fn
										widths[i] = o.TextBounds.X
									end
									total = total + widths[i]
								end
								for i = n + 1, #pool do pool[i].Visible = false end
								local x = sp.X - total * 0.5
								for i = 1, n do
									local o = pool[i]
									o.Color = gun_grad(n > 1 and (i-1)/(n-1) or 0)
									o.Position = Vector2.new(x, sp.Y)
									o.Visible = true
									x = x + widths[i]
								end
							elseif e.gtxt then
								for i = 1, #e.gtxt do e.gtxt[i].Visible = false end
							end
						else
							if e.gtxt then
								for i = 1, #e.gtxt do e.gtxt[i].Visible = false end
							end
							if not e.txt then
								local t = Drawing.new("Text")
								t.Center = true
								t.Outline = true
								t.Size = 13
								e.txt = t
							end
							if sp.Z > 0 then
								e.txt.Position = Vector2.new(sp.X, sp.Y)
								e.txt.Text = "Gun"
								e.txt.Color = gun_text_col
								e.txt.Visible = true
							else
								e.txt.Visible = false
							end
						end
					else
						if e.txt then e.txt.Visible = false end
						if e.gtxt then
							for i = 1, #e.gtxt do e.gtxt[i].Visible = false end
						end
					end
				else
					clear_gun(obj)
				end
			end
		end

		local function gun_esp_stop()
			if gun_render_conn then
				pcall(function() gun_render_conn:Disconnect() end)
				gun_render_conn = nil
			end
			if gun_added_conn then
				pcall(function() gun_added_conn:Disconnect() end)
				gun_added_conn = nil
			end
			if gun_removing_conn then
				pcall(function() gun_removing_conn:Disconnect() end)
				gun_removing_conn = nil
			end
			table.clear(gun_candidates)
		end

		local function gun_esp_start()
			if gun_render_conn then return end
			gun_esp_stop()
			seed_gun_candidates()
			gun_scan_acc = 0.25
			gun_added_conn = workspace.DescendantAdded:Connect(gun_candidate_added)
			gun_removing_conn = workspace.DescendantRemoving:Connect(gun_candidate_removing)
			gun_render_conn = run.RenderStepped:Connect(gun_render)
		end

		local gun_esp = visuals_left:AddToggle({
			Name = "gun",
			Default = false,
			Flag = "esp_gun",
			Option = true,
			Callback = function(v)
				gun_esp_on = v
				if v then
					gun_esp_start()
				else
					gun_esp_stop()
					clear_guns()
				end
			end
		})

		gun_esp.Option:AddToggle({
			Name = "text",
			Default = false,
			Flag = "esp_gun_text",
			Callback = function(v)
				gun_text_on = v
			end
		})

		gun_esp.Option:AddColorPicker({
			Name = "text",
			Default = Color3.fromRGB(255, 255, 255),
			Flag = "esp_gun_text_col",
			Callback = function(c)
				gun_text_col = c
			end
		})

		gun_esp.Option:AddToggle({
			Name = "text gradient",
			Default = false,
			Flag = "esp_gun_text_grd",
			Callback = function(v)
				gun_text_grd = v
			end
		})

		gun_esp.Option:AddColorPicker({
			Name = "gradient color 1",
			Default = Color3.fromRGB(255, 255, 255),
			Flag = "esp_gun_grd_col1",
			Callback = function(c)
				gun_grd_c1 = c
			end
		})

		gun_esp.Option:AddColorPicker({
			Name = "gradient color 2",
			Default = Color3.fromRGB(255, 0, 0),
			Flag = "esp_gun_grd_col2",
			Callback = function(c)
				gun_grd_c2 = c
			end
		})

		gun_esp.Option:AddToggle({
			Name = "highlight",
			Default = false,
			Flag = "esp_gun_hl",
			Callback = function(v)
				gun_hl_on = v
			end
		})

		gun_esp.Option:AddColorPicker({
			Name = "highlight",
			Default = Color3.fromRGB(255, 255, 255),
			Flag = "esp_gun_hl_col",
			Callback = function(c)
				gun_hl_col = c
			end
		})

		getgenv().GUN_ESP_UNLOAD = function()
			gun_esp_on = false
			gun_esp_stop()
			clear_guns()
		end
	end

	
	visuals_left:AddToggle({
		Name = "allow local",
		Default = false,
		Flag = "esp_allow_local",
		Callback = function(v)
			esp.allowlocal = v
		end
	})
	
end

do
	local sv = visuals:AddSection({
		Name = "local",
		Position = 'left'
	})

	local players = game:GetService("Players")
	local run = game:GetService("RunService")
	local stats = game:GetService("Stats")
	local tween = game:GetService("TweenService")
	local debris = game:GetService("Debris")
	local lp = players.LocalPlayer
	local ws = workspace

	local bt_on, sc_on, tc_on = false, false, false
	local bt_col = Color3.fromRGB(255, 60, 60)
	local sc_col = Color3.fromRGB(0, 200, 255)
	local tc_col = Color3.fromRGB(255, 200, 0)
	local sc_type, tc_type = "ForceField", "ForceField"
	local sc_flat, tc_flat = {}, {}
	local sc_surfs, tc_surfs = {}, {}
	local tc_roots = {}
	local sc_chrom, tc_chrom = {}, {}
	local chrom_view, chrom_world, chrom_conn
	local CHROM_SCALE, CHROM_ALPHA = 1.012, 0.025
	local bt_model = nil
	local BT_CAP = 256
	local bt_hist = table.create(BT_CAP)
	for i = 1, BT_CAP do bt_hist[i] = { 0, CFrame.identity } end
	local bt_first = 1
	local bt_count = 0
	local bt_ping = 0.15
	local bt_ping_at = 0
	local bt_pairs = {}
	local sc_cache, tc_cache = {}, {}
	local sc_surf = {}
	local tc_surf = {}
	local sc_parts = {}
	local sc_char = nil
	local sc_valid = false
	local sc_conns = {}
	local tc_parts = {}
	local tc_char = nil
	local tc_valid = false
	local tc_conns = {}
	local lc_on = false
	local lc_col = Color3.new(1, 1, 1)
	local lc_tr = 1
	local lc_dur = 0.82
	local lc_con = nil
	local ch_on = false
	local ch_col = Color3.fromRGB(170, 85, 255)

	local function bt_read_ping()
		return stats.Network.ServerStatsItem["Data Ping"]:GetValue() / 1000
	end

	local function bt_destroy()
		if bt_model then
			if _G.BACKTRACK_CLONES then _G.BACKTRACK_CLONES[bt_model] = nil end
			pcall(function() bt_model:Destroy() end)
			bt_model = nil
		end
		bt_pairs = {}
		bt_first = 1
		bt_count = 0
	end

	local function bt_build()
		bt_destroy()
		local char = lp.Character
		if not char then return end
		local rhrp = char:FindFirstChild("HumanoidRootPart")
		if not rhrp then return end
		char.Archivable = true
		local ok, m = pcall(function() return char:Clone() end)
		char.Archivable = false
		if not ok or not m then return end
		_G.BACKTRACK_CLONES = _G.BACKTRACK_CLONES or {}
		local rparts = {}
		for _, o in char:GetDescendants() do
			if o:IsA("BasePart") then rparts[#rparts + 1] = o end
		end
		local ci = 0
		for _, o in m:GetDescendants() do
			if o:IsA("Script") or o:IsA("LocalScript") then
				pcall(function() o:Destroy() end)
			elseif o:IsA("Decal") or o:IsA("Texture") or o:IsA("SurfaceAppearance") then
				pcall(function() o:Destroy() end)
			elseif o:IsA("ParticleEmitter") or o:IsA("Beam") or o:IsA("Trail") or o:IsA("PointLight") or o:IsA("SpotLight") or o:IsA("SurfaceLight") then
				pcall(function() o:Destroy() end)
			elseif o:IsA("BasePart") then
				o.Anchored = true
				o.CanCollide = false
				o.CanQuery = false
				o.Massless = true
				o.CastShadow = false
				if o.Name == "HumanoidRootPart" then
					o.Transparency = 1
				else
					o.Material = Enum.Material.ForceField
					o.Color = bt_col
					o.Transparency = 0
				end
				ci = ci + 1
				bt_pairs[#bt_pairs + 1] = {o, rparts[ci]}
			end
		end
		local hum = m:FindFirstChildOfClass("Humanoid")
		if hum then pcall(function() hum:Destroy() end) end
		m.Parent = ws
		bt_model = m
		_G.BACKTRACK_CLONES[m] = true
	end

	local function bt_update()
		local char = lp.Character
		local rhrp = char and char:FindFirstChild("HumanoidRootPart")
		if not rhrp then return end
		if getgenv().FAKE_POS_ACTIVE then
			if bt_model and bt_model.Parent then bt_model.Parent = nil end
			return
		end
		if not bt_model then
			bt_build()
			if not bt_model then return end
		end
		if not bt_model.Parent then bt_model.Parent = ws end
		local now = os.clock()
		local base_cf = rhrp.CFrame
		if bt_count < BT_CAP then
			bt_count = bt_count + 1
		else
			bt_first = bt_first % BT_CAP + 1
		end
		local slot = bt_hist[(bt_first + bt_count - 2) % BT_CAP + 1]
		slot[1] = now
		slot[2] = base_cf
		if now - bt_ping_at >= 0.2 then
			bt_ping_at = now
			local ok, value = pcall(bt_read_ping)
			bt_ping = math.clamp((ok and value) or 0.15, 0.05, 0.6)
		end
		local ping = bt_ping
		local target = now - ping
		local cf = base_cf
		for k = bt_count, 1, -1 do
			local s = bt_hist[(bt_first + k - 2) % BT_CAP + 1]
			if s[1] <= target then
				cf = s[2]
				break
			end
		end
		while bt_count > 0 and bt_hist[bt_first][1] < now - 1 do
			bt_first = bt_first % BT_CAP + 1
			bt_count = bt_count - 1
		end
		local baseInv = rhrp.CFrame:Inverse()
		for i = 1, #bt_pairs do
			local cp, rp = bt_pairs[i][1], bt_pairs[i][2]
			if cp and cp.Parent and rp and rp.Parent then
				cp.CFrame = cf * (baseInv * rp.CFrame)
			end
		end
	end

	local function chrom_ensure()
		if chrom_world and chrom_world.Parent then return end
		local host = Instance.new("ScreenGui")
		host.Name = tostring(math.random(1e6, 9e6))
		host.ResetOnSpawn = false
		host.IgnoreGuiInset = true
		host.DisplayOrder = 100
		pcall(function() host.Parent = gethui and gethui() or game:GetService("CoreGui") end)
		chrom_view = Instance.new("ViewportFrame")
		chrom_view.Size = UDim2.fromScale(1, 1)
		chrom_view.BackgroundTransparency = 1
		chrom_view.BorderSizePixel = 0
		chrom_view.Ambient = Color3.new(1, 1, 1)
		chrom_view.LightColor = Color3.new(1, 1, 1)
		chrom_view.LightDirection = Vector3.new(-1, -1, -1)
		chrom_view.CurrentCamera = ws.CurrentCamera
		chrom_view.Parent = host
		local sky = game:GetService("Lighting"):FindFirstChildOfClass("Sky")
		if sky then pcall(function() sky:Clone().Parent = chrom_view end) end
		chrom_world = Instance.new("WorldModel")
		chrom_world.Parent = chrom_view
	end

	local CHAMS_BODY = {
		Head = true, UpperTorso = true, LowerTorso = true, Torso = true,
		LeftUpperArm = true, LeftLowerArm = true, LeftHand = true,
		RightUpperArm = true, RightLowerArm = true, RightHand = true,
		LeftUpperLeg = true, LeftLowerLeg = true, LeftFoot = true,
		RightUpperLeg = true, RightLowerLeg = true, RightFoot = true,
		["Left Arm"] = true, ["Right Arm"] = true,
		["Left Leg"] = true, ["Right Leg"] = true
	}

	local function chams_deformable(p)
		if p:FindFirstChildWhichIsA("WrapLayer") then return true end
		if CHAMS_BODY[p.Name] then return false end
		if p:FindFirstChildWhichIsA("Bone") then return true end
		local ok, skinned = pcall(function() return p.HasSkinnedMesh end)
		return ok and skinned == true
	end

	local function chams_shell(source, scale)
		local archivable = source.Archivable
		if not archivable then
			if not pcall(function() source.Archivable = true end) then return nil end
		end
		local ok, clone = pcall(function() return source:Clone() end)
		if not archivable then
			pcall(function() source.Archivable = archivable end)
		end
		if not ok or not clone then return nil end
		for _, child in clone:GetChildren() do
			if not child:IsA("DataModelMesh") then child:Destroy() end
		end
		local mesh = clone:FindFirstChildWhichIsA("DataModelMesh")
		if mesh then
			pcall(function() mesh.Scale = mesh.Scale * scale end)
			pcall(function() mesh.TextureId = "" end)
		else
			clone.Size = clone.Size * scale
		end
		pcall(function() clone.TextureID = "" end)
		pcall(function() clone.MaterialVariant = "" end)
		clone.CanCollide = false
		clone.CanQuery = false
		clone.CanTouch = false
		clone.Massless = true
		clone.CastShadow = false
		clone.LocalTransparencyModifier = 0
		return clone
	end

	local function flat_clear(state)
		if state.model then state.model:Destroy() end
		if state.occ then state.occ:Destroy() end
		if state.los then
			for i = 1, #state.los do state.los[i]:Destroy() end
		end
		state.model, state.occ, state.los, state.count, state.key = nil, nil, nil, nil, nil
	end

	local function flat_apply(state, parts, roots, col)
		local key = roots[1]
		if state.key ~= key or state.count ~= #parts or not state.model or not state.model.Parent then
			flat_clear(state)
			local model = Instance.new("Model")
			model.Name = "\0"
			for i = 1, #parts do
				local source = parts[i]
				local clone = not chams_deformable(source) and chams_shell(source, 0.99) or nil
				if clone then
					clone.Anchored = false
					clone.CFrame = source.CFrame
					clone.Parent = model
					local weld = Instance.new("WeldConstraint")
					weld.Part0 = clone
					weld.Part1 = source
					weld.Parent = clone
				end
			end
			model.Parent = ws
			local occ = Instance.new("Highlight")
			occ.DepthMode = Enum.HighlightDepthMode.AlwaysOnTop
			occ.OutlineTransparency = 1
			occ.Adornee = model
			occ.Parent = model
			local los = {}
			for i = 1, #roots do
				local hl = Instance.new("Highlight")
				hl.DepthMode = Enum.HighlightDepthMode.Occluded
				hl.OutlineTransparency = 1
				hl.Adornee = roots[i]
				hl.Parent = model
				los[i] = hl
			end
			state.model, state.occ, state.los = model, occ, los
			state.count, state.key = #parts, key
		end
		state.occ.FillColor = col
		state.occ.FillTransparency = 0
		for i = 1, #state.los do
			state.los[i].FillColor = col
			state.los[i].FillTransparency = 0
		end
	end

	local function chrom_clear(state)
		if state.model then state.model:Destroy() end
		state.model, state.entries, state.count, state.key, state.col = nil, nil, nil, nil, nil
	end

	local function chrom_apply(state, parts, key, col)
		if state.key ~= key or state.count ~= #parts or not state.model or not state.model.Parent then
			chrom_clear(state)
			chrom_ensure()
			local model = Instance.new("Model")
			model.Name = "\0"
			local entries = {}
			for i = 1, #parts do
				local source = parts[i]
				local clone = not chams_deformable(source) and chams_shell(source, CHROM_SCALE) or nil
				if clone then
					clone.Anchored = true
					clone.Material = Enum.Material.Foil
					clone.Reflectance = 0.12
					clone.Transparency = CHROM_ALPHA
					clone.Color = col
					clone.CFrame = source.CFrame
					clone.Parent = model
					entries[#entries + 1] = { source, clone }
				end
			end
			model.Parent = chrom_world
			state.model, state.entries = model, entries
			state.count, state.key, state.col = #parts, key, col
		elseif state.col ~= col then
			state.col = col
			local entries = state.entries
			if entries then
				for i = 1, #entries do
					entries[i][2].Color = col
				end
			end
		end
	end

	local function chrom_sync(state)
		local entries = state.entries
		if not entries then return end
		for i = 1, #entries do
			local source, clone = entries[i][1], entries[i][2]
			if source.Parent then
				clone.CFrame = source.CFrame
				local hidden = math.max(source.Transparency, source.LocalTransparencyModifier) >= 1
				local target_trans = hidden and 1 or CHROM_ALPHA
				if clone.Transparency ~= target_trans then
					clone.Transparency = target_trans
				end
			elseif clone.Transparency ~= 1 then
				clone.Transparency = 1
			end
		end
	end

	local function sc_restore()
		for part, d in pairs(sc_cache) do
			if part and part.Parent then
				part.Material = d[1]
				part.Color = d[2]
			end
		end
		sc_cache = {}
		for sa, par in pairs(sc_surf) do
			if sa then pcall(function() sa.Parent = par end) end
		end
		sc_surf = {}
		sc_valid = false
	end

	local function sc_detach(p)
		p.Parent = nil
	end

	local function sc_parts_for(char)
		if sc_char ~= char then
			sc_char = char
			sc_valid = false
			for i = 1, #sc_conns do
				pcall(function() sc_conns[i]:Disconnect() end)
			end
			table.clear(sc_conns)
			local function dirty()
				sc_valid = false
			end
			sc_conns[1] = char.DescendantAdded:Connect(dirty)
			sc_conns[2] = char.DescendantRemoving:Connect(dirty)
		end
		if not sc_valid then
			table.clear(sc_parts)
			table.clear(sc_surfs)
			local n, s = 0, 0
			for _, p in char:GetDescendants() do
				if p:IsA("BasePart") and p.Name ~= "HumanoidRootPart" then
					n = n + 1
					sc_parts[n] = p
				elseif p:IsA("SurfaceAppearance") then
					s = s + 1
					sc_surfs[s] = p
				end
			end
			sc_valid = true
		end
		return sc_parts
	end

	local function surfs_detach(list, store)
		for i = 1, #list do
			local sa = list[i]
			if sa.Parent and not store[sa] then
				store[sa] = sa.Parent
				pcall(sc_detach, sa)
			end
		end
	end

	local function sc_apply()
		local char = lp.Character
		if not char then return end
		local parts = sc_parts_for(char)
		if sc_type == "Flat" then
			chrom_clear(sc_chrom)
			if next(sc_cache) or next(sc_surf) then sc_restore() end
			flat_apply(sc_flat, parts, { char }, sc_col)
		elseif sc_type == "Chromatic" then
			flat_clear(sc_flat)
			if next(sc_cache) or next(sc_surf) then sc_restore() end
			chrom_apply(sc_chrom, parts, char, sc_col)
		else
			flat_clear(sc_flat)
			chrom_clear(sc_chrom)
			surfs_detach(sc_surfs, sc_surf)
			for i = 1, #parts do
				local p = parts[i]
				if p.Parent then
					if not sc_cache[p] then sc_cache[p] = {p.Material, p.Color} end
					p.Material = Enum.Material.ForceField
					p.Color = sc_col
				end
			end
		end
	end

	getgenv().SELF_CHAMS_CLEAN = function(model, source)
		if not sc_on or not model or not source then return end
		local srcDesc = source:GetDescendants()
		local mdlDesc = model:GetDescendants()
		if #srcDesc ~= #mdlDesc then return end
		local map = {}
		for i = 1, #srcDesc do
			local sp = srcDesc[i]
			local mp = mdlDesc[i]
			map[sp] = mp
			if sp:IsA("BasePart") and mp:IsA("BasePart") then
				local orig = sc_cache[sp]
				if orig then
					mp.Material = orig[1]
					mp.Color = orig[2]
				end
			end
		end
		for sa, par in pairs(sc_surf) do
			local mp = map[par]
			if mp then
				pcall(function()
					local c = sa:Clone()
					c.Parent = mp
				end)
			end
		end
	end

	getgenv().SELF_CHAMS_FIXCLONE = function(pairsmap)
		if type(pairsmap) ~= "table" then return end
		local map = {}
		for i = 1, #pairsmap do
			local row = pairsmap[i]
			local src, dst = row and row[1], row and row[2]
			if src and dst and dst.Parent then
				map[src] = dst
				local orig = sc_cache[src]
				if orig then
					dst.Material = orig[1]
					dst.Color = orig[2]
				end
			end
		end
		for sa, par in pairs(sc_surf) do
			local dst = map[par]
			if dst and not dst:FindFirstChildOfClass("SurfaceAppearance") then
				pcall(function()
					local c = sa:Clone()
					c.Parent = dst
				end)
			end
		end
	end

	local function tc_restore()
		for part, d in pairs(tc_cache) do
			if part and part.Parent then
				part.Material = d[1]
				part.Color = d[2]
			end
		end
		tc_cache = {}
		for sa, par in pairs(tc_surf) do
			if sa then pcall(function() sa.Parent = par end) end
		end
		tc_surf = {}
		tc_valid = false
	end

	local function tc_parts_for(char)
		if tc_char ~= char then
			tc_char = char
			tc_valid = false
			for i = 1, #tc_conns do
				pcall(function() tc_conns[i]:Disconnect() end)
			end
			table.clear(tc_conns)
			local function dirty()
				tc_valid = false
			end
			tc_conns[1] = char.DescendantAdded:Connect(dirty)
			tc_conns[2] = char.DescendantRemoving:Connect(dirty)
		end
		if not tc_valid then
			table.clear(tc_parts)
			table.clear(tc_surfs)
			table.clear(tc_roots)
			local n, s, r = 0, 0, 0
			for _, t in char:GetChildren() do
				if t:IsA("Tool") then
					r = r + 1
					tc_roots[r] = t
					for _, p in t:GetDescendants() do
						if p:IsA("BasePart") then
							n = n + 1
							tc_parts[n] = p
						elseif p:IsA("SurfaceAppearance") then
							s = s + 1
							tc_surfs[s] = p
						end
					end
				end
			end
			tc_valid = true
		end
		return tc_parts
	end

	local function tc_apply()
		local char = lp.Character
		if not char then return end
		local parts = tc_parts_for(char)
		if #parts == 0 then
			flat_clear(tc_flat)
			chrom_clear(tc_chrom)
			if next(tc_cache) or next(tc_surf) then tc_restore() end
			return
		end
		if tc_type == "Flat" then
			chrom_clear(tc_chrom)
			if next(tc_cache) or next(tc_surf) then tc_restore() end
			flat_apply(tc_flat, parts, tc_roots, tc_col)
		elseif tc_type == "Chromatic" then
			flat_clear(tc_flat)
			if next(tc_cache) or next(tc_surf) then tc_restore() end
			chrom_apply(tc_chrom, parts, tc_roots[1], tc_col)
		else
			flat_clear(tc_flat)
			chrom_clear(tc_chrom)
			surfs_detach(tc_surfs, tc_surf)
			for i = 1, #parts do
				local p = parts[i]
				if p.Parent then
					if not tc_cache[p] then tc_cache[p] = {p.Material, p.Color} end
					p.Material = Enum.Material.ForceField
					p.Color = tc_col
				end
			end
		end
	end

	local function lc_hit(char, root)
		local prm = RaycastParams.new()
		prm.FilterType = Enum.RaycastFilterType.Exclude
		prm.FilterDescendantsInstances = {char}
		prm.IgnoreWater = true
		local sum, nor, cnt = Vector3.zero, Vector3.zero, 0
		for _, name in ipairs({"LeftFoot", "RightFoot", "Left Leg", "Right Leg"}) do
			local foot = char:FindFirstChild(name)
			if foot and foot:IsA("BasePart") then
				local hit = ws:Raycast(foot.Position + Vector3.new(0, 0.35, 0), Vector3.new(0, -7, 0), prm)
				if hit then
					sum += hit.Position
					nor += hit.Normal
					cnt += 1
				end
			end
		end
		if cnt > 0 then return sum/cnt, nor.Unit end
		local hit = ws:Raycast(root.Position + Vector3.new(0, 1, 0), Vector3.new(0, -16, 0), prm)
		if hit then return hit.Position, hit.Normal end
	end

	local function lc_make(p, n)
		local ref = math.abs(n.Y) > 0.98 and Vector3.xAxis or Vector3.yAxis
		local right = n:Cross(ref).Unit
		local front = right:Cross(n).Unit
		local part = Instance.new("Part")
		part.Name = "LandingCircle"
		part.Anchored = true
		part.CanCollide = false
		part.CanQuery = false
		part.CanTouch = false
		part.CastShadow = false
		part.Transparency = 1
		part.Size = Vector3.new(0.3, 0.01, 0.3)
		part.CFrame = CFrame.fromMatrix(p + n*0.012, right, n, front)
		part.Parent = ws
		local sg = Instance.new("SurfaceGui")
		sg.Face = Enum.NormalId.Top
		sg.AlwaysOnTop = true
		sg.LightInfluence = 0
		sg.ZOffset = 4
		sg.CanvasSize = Vector2.new(1024, 1024)
		sg.Parent = part
		local img = Instance.new("ImageLabel")
		img.BackgroundTransparency = 1
		img.Size = UDim2.fromScale(1, 1)
		img.Image = "rbxassetid://7185003058"
		img.ImageColor3 = lc_col
		img.ImageTransparency = 1 - lc_tr
		img.ScaleType = Enum.ScaleType.Stretch
		img.Parent = sg
		local info = TweenInfo.new(lc_dur, Enum.EasingStyle.Quint, Enum.EasingDirection.Out)
		tween:Create(part, info, {Size = Vector3.new(6.4, 0.01, 6.4)}):Play()
		tween:Create(img, info, {ImageTransparency = 1}):Play()
		debris:AddItem(part, lc_dur + 0.2)
	end

	local function lc_bind()
		if lc_con then pcall(function() lc_con:Disconnect() end) lc_con = nil end
		if not lc_on then return end
		local char = lp.Character
		local hum = char and char:FindFirstChildOfClass("Humanoid")
		local root = char and char:FindFirstChild("HumanoidRootPart")
		if not hum or not root then return end
		local air = false
		lc_con = hum.StateChanged:Connect(function(_, state)
			if state == Enum.HumanoidStateType.Jumping or state == Enum.HumanoidStateType.Freefall then
				air = true
				return
			end
			if state == Enum.HumanoidStateType.Landed and air and lc_on then
				air = false
				local p, n = lc_hit(char, root)
				if p and n then lc_make(p, n) end
			end
		end)
	end

	local mg_on = false
	local mg_color = Color3.fromRGB(242, 242, 242)
	local mg_width = 280
	local mg_height = 72
	local mg_offset = 105
	local mg_thickness = 1
	local mg_span = 2.8
	local mg_step = 1 / 45
	local mg_accum = 0
	local mg_smooth = 0
	local mg_history = {}
	local mg_lines = {}
	local mg_shadows = {}
	local mg_labels = {}
	local mg_current = nil
	local mg_conn = nil

	local function mg_remove(obj)
		if obj then pcall(function() obj:Remove() end) end
	end

	local function mg_speed()
		local char = lp.Character
		local root = char and char:FindFirstChild("HumanoidRootPart")
		if not root then return 0 end
		local velocity = root.AssemblyLinearVelocity
		return Vector3.new(velocity.X, 0, velocity.Z).Magnitude
	end

	local function mg_reference()
		local char = lp.Character
		local hum = char and char:FindFirstChildOfClass("Humanoid")
		return math.max(1, hum and hum.WalkSpeed or 16)
	end

	local function mg_new_line(color, thickness, zindex, transparency)
		local line = Drawing.new("Line")
		line.Color = color
		line.Thickness = thickness
		line.Transparency = transparency
		line.ZIndex = zindex
		line.Visible = false
		return line
	end

	local function mg_new_text()
		local text = Drawing.new("Text")
		text.Center = true
		text.Outline = true
		text.Color = mg_color
		text.Size = 12
		text.ZIndex = 904
		text.Visible = false
		return text
	end

	local function mg_sync_pool(needed)
		while #mg_lines < needed do
			mg_shadows[#mg_shadows + 1] = mg_new_line(Color3.new(0, 0, 0), mg_thickness + 2, 901, 0.45)
			mg_lines[#mg_lines + 1] = mg_new_line(mg_color, mg_thickness, 902, 1)
		end
		while #mg_lines > needed do
			mg_remove(table.remove(mg_lines))
			mg_remove(table.remove(mg_shadows))
		end
	end

	local function mg_create()
		if mg_current then return end
		mg_current = mg_new_text()
		mg_current.Center = false
		for i = 1, 6 do
			mg_labels[i] = mg_new_text()
		end
	end

	local function mg_hide()
		if mg_current then mg_current.Visible = false end
		for i = 1, #mg_lines do
			mg_lines[i].Visible = false
			mg_shadows[i].Visible = false
		end
		for i = 1, #mg_labels do
			mg_labels[i].Visible = false
		end
	end

	local function mg_clear()
		if mg_conn then
			pcall(function() mg_conn:Disconnect() end)
			mg_conn = nil
		end
		mg_remove(mg_current)
		mg_current = nil
		for i = 1, #mg_lines do
			mg_remove(mg_lines[i])
			mg_remove(mg_shadows[i])
		end
		for i = 1, #mg_labels do
			mg_remove(mg_labels[i])
		end
		table.clear(mg_lines)
		table.clear(mg_shadows)
		table.clear(mg_labels)
		table.clear(mg_history)
		mg_accum = 0
	end

	local function mg_reset_history()
		table.clear(mg_history)
		local now = os.clock()
		local speed = mg_speed()
		mg_smooth = speed
		local count = math.ceil(mg_span / mg_step)
		for i = 0, count do
			mg_history[#mg_history + 1] = {
				t = now - mg_span + i * mg_step,
				v = speed
			}
		end
		mg_sync_pool(#mg_history)
	end

	local function mg_apply_style()
		if mg_current then mg_current.Color = mg_color end
		for i = 1, #mg_lines do
			mg_lines[i].Color = mg_color
			mg_lines[i].Thickness = mg_thickness
			mg_shadows[i].Thickness = mg_thickness + 2
		end
		for i = 1, #mg_labels do
			mg_labels[i].Color = mg_color
		end
	end

	local function mg_y(value, center, height, reference)
		local normalized = math.clamp(value / reference - 1, -1, 1)
		return center - normalized * height * 0.44
	end

	local function mg_render(now)
		local camera = ws.CurrentCamera
		if not mg_on or not camera or #mg_history < 2 then
			mg_hide()
			return
		end
		local viewport = camera.ViewportSize
		local width = math.min(mg_width, math.max(120, viewport.X - 48))
		local height = math.min(mg_height, math.max(36, viewport.Y - 32))
		local left = math.floor(viewport.X * 0.5 - width * 0.5)
		local center = math.clamp(math.floor(viewport.Y * 0.5 + mg_offset), height * 0.5 + 8, viewport.Y - height * 0.5 - 8)
		local reference = mg_reference()
		local start_time = now - mg_span
		local count = #mg_history
		mg_sync_pool(count)
		for i = 1, count - 1 do
			local a = mg_history[i]
			local b = mg_history[i + 1]
			local ap = math.clamp((a.t - start_time) / mg_span, 0, 1)
			local bp = math.clamp((b.t - start_time) / mg_span, 0, 1)
			local fade = math.clamp(math.min((ap + bp) * 6, (2 - ap - bp) * 5), 0, 1)
			local from = Vector2.new(left + ap * width, mg_y(a.v, center, height, reference))
			local to = Vector2.new(left + bp * width, mg_y(b.v, center, height, reference))
			local line = mg_lines[i]
			local shadow = mg_shadows[i]
			line.From, line.To = from, to
			line.Transparency = fade
			line.Visible = fade > 0.02
			shadow.From, shadow.To = from, to
			shadow.Transparency = fade * 0.42
			shadow.Visible = fade > 0.02
		end
		local last = mg_history[count]
		local lpct = math.clamp((last.t - start_time) / mg_span, 0, 1)
		local from = Vector2.new(left + lpct * width, mg_y(last.v, center, height, reference))
		local to = Vector2.new(left + width, mg_y(mg_smooth, center, height, reference))
		local tail = mg_lines[count]
		local tail_shadow = mg_shadows[count]
		tail.From, tail.To = from, to
		tail.Transparency = 0.72
		tail.Visible = true
		tail_shadow.From, tail_shadow.To = from, to
		tail_shadow.Transparency = 0.3
		tail_shadow.Visible = true
		for i = count + 1, #mg_lines do
			mg_lines[i].Visible = false
			mg_shadows[i].Visible = false
		end
		mg_current.Text = tostring(math.floor(mg_smooth + 0.5))
		mg_current.Position = Vector2.new(left + width + 5, to.Y - 7)
		mg_current.Color = mg_color
		mg_current.Visible = true
		while #mg_labels < 12 do
			mg_labels[#mg_labels + 1] = mg_new_text()
		end
		local threshold = math.max(0.8, reference * 0.08)
		local min_label_gap = 0.42
		for i = 5, count - 4 do
			local point = mg_history[i]
			if not point.checked then
				point.checked = true
				local before = point.v - mg_history[i - 4].v
				local after = mg_history[i + 4].v - point.v
				if math.abs(before) >= threshold and (before * after <= 0 or math.abs(after) < threshold * 0.35) then
					local nearby = nil
					for j = i - 1, 1, -1 do
						local previous = mg_history[j]
						if point.t - previous.t > min_label_gap then break end
						if previous.label ~= nil then
							nearby = previous
							break
						end
					end
					local score = math.abs(before) - math.abs(after)
					if not nearby then
						point.label = math.floor(point.v + 0.5)
						point.label_score = score
					elseif score > (nearby.label_score or -math.huge) then
						nearby.label = nil
						nearby.label_score = nil
						point.label = math.floor(point.v + 0.5)
						point.label_score = score
					end
				end
			end
		end
		for i = 1, #mg_labels do
			mg_labels[i].Visible = false
		end
		local placed = {}
		local label_count = 0
		for i = count, 1, -1 do
			local point = mg_history[i]
			if point.label ~= nil and label_count < #mg_labels then
				local pct = (point.t - start_time) / mg_span
				if pct > 0.04 and pct < 0.82 then
					local value = tostring(point.label)
					local x = left + pct * width
					local y = mg_y(point.v, center, height, reference) - 15
					local half_width = math.max(8, #value * 3.5 + 2)
					local blocked = false
					for j = 1, #placed do
						local other = placed[j]
						if x + half_width + 5 > other.x1 and x - half_width - 5 < other.x2 and y + 13 > other.y1 and y - 3 < other.y2 then
							blocked = true
							break
						end
					end
					if not blocked then
						label_count = label_count + 1
						local text = mg_labels[label_count]
						text.Text = value
						text.Position = Vector2.new(x, y)
						text.Color = mg_color
						text.Visible = true
						placed[#placed + 1] = {
							x1 = x - half_width,
							x2 = x + half_width,
							y1 = y - 3,
							y2 = y + 13
						}
					end
				end
			end
		end
	end

	mg_offset = 180

	local function mg_start()
		mg_clear()
		mg_create()
		mg_reset_history()
		mg_apply_style()
		mg_conn = run.RenderStepped:Connect(function(dt)
			if not mg_on then
				mg_hide()
				return
			end
			local raw = mg_speed()
			mg_smooth = mg_smooth + (raw - mg_smooth) * (1 - math.exp(-dt * 18))
			mg_accum = mg_accum + dt
			local now = os.clock()
			if mg_accum >= mg_step then
				mg_accum = mg_accum % mg_step
				mg_history[#mg_history + 1] = { t = now, v = mg_smooth }
				local cutoff = now - mg_span
				while #mg_history > 2 and mg_history[2].t < cutoff do
					table.remove(mg_history, 1)
				end
			end
			mg_render(now)
		end)
	end

	

	

	local CH_RADIUS, CH_HEIGHT, CH_DROP = 1.55, 0.82, 0.02
	local CH_SEGMENTS = 48
	local CH_TAU = math.pi * 2
	local CH_ALPHA = 0.72
	local CH_MAX_ROWS = 220

	local ch = {
		rows = {},
		px = table.create(CH_SEGMENTS + 1),
		py = table.create(CH_SEGMENTS + 1),
		cos = table.create(CH_SEGMENTS),
		sin = table.create(CH_SEGMENTS),
		ord = table.create(CH_SEGMENTS + 1),
		stack = table.create(CH_SEGMENTS + 2),
		shown = {},
		cpos = {},
		csize = {},
		ccol = {},
		white = Color3.new(1, 1, 1),
		black = Color3.new(0, 0, 0),
		eps = 0.75
	}

	for i = 1, CH_SEGMENTS do
		local angle = (i - 1) / CH_SEGMENTS * CH_TAU
		ch.cos[i] = math.cos(angle) * CH_RADIUS
		ch.sin[i] = math.sin(angle) * CH_RADIUS
	end

	ch.order = function(i, j)
		LPH_ATTRIBUTES(VM(NONE))
		local px, py = ch.px, ch.py
		local ax, bx = px[i], px[j]
		return ax == bx and py[i] < py[j] or ax < bx
	end

	ch.hull = function(n)
		LPH_ATTRIBUTES(VM(NONE))
		local px, py, ord, st = ch.px, ch.py, ch.ord, ch.stack
		for i = 1, n do ord[i] = i end
		table.sort(ord, ch.order)
		local m = 0
		for k = 1, n do
			local i = ord[k]
			local x, y = px[i], py[i]
			while m >= 2 do
				local o, a = st[m - 1], st[m]
				local ox, oy = px[o], py[o]
				if (px[a] - ox) * (y - oy) - (py[a] - oy) * (x - ox) > 0 then break end
				m = m - 1
			end
			m = m + 1
			st[m] = i
		end
		local lower = m
		for k = n - 1, 1, -1 do
			local i = ord[k]
			local x, y = px[i], py[i]
			while m > lower do
				local o, a = st[m - 1], st[m]
				local ox, oy = px[o], py[o]
				if (px[a] - ox) * (y - oy) - (py[a] - oy) * (x - ox) > 0 then break end
				m = m - 1
			end
			m = m + 1
			st[m] = i
		end
		return m - 1
	end

	ch.visible = function(state)
		LPH_ATTRIBUTES(VM(NONE))
		local rows, shown = ch.rows, ch.shown
		for i = 1, #rows do
			if shown[i] ~= state then
				rows[i].Visible = state
				shown[i] = state
			end
		end
	end

	ch.clear = function()
		LPH_ATTRIBUTES(VM(NONE))
		local rows = ch.rows
		for i = 1, #rows do
			pcall(function() rows[i]:Remove() end)
		end
		table.clear(rows)
		table.clear(ch.shown)
		table.clear(ch.cpos)
		table.clear(ch.csize)
		table.clear(ch.ccol)
		ch.head, ch.pos, ch.cf = nil, nil, nil
		ch.fov, ch.vx, ch.vy, ch.col = nil, nil, nil, nil
	end

	ch.build = function()
		LPH_ATTRIBUTES(VM(NONE))
		ch.clear()
	end

	ch.row = function(index)
		LPH_ATTRIBUTES(VM(NONE))
		local rows = ch.rows
		local row = rows[index]
		if row then return row end
		row = Drawing.new("Square")
		row.Filled = true
		row.Thickness = 0
		row.Transparency = CH_ALPHA
		row.Visible = false
		row.ZIndex = 1
		rows[index] = row
		ch.shown[index] = false
		return row
	end

	ch.update = function(camera)
		LPH_ATTRIBUTES(VM(NONE))
		local char = lp.Character
		local head = char and char:FindFirstChild("Head")
		if not head or not head:IsA("BasePart") or not camera then
			ch.visible(false)
			return
		end
		local headPos = head.Position
		local camCF = camera.CFrame
		local fov = camera.FieldOfView
		local view = camera.ViewportSize
		local viewX, viewY = view.X, view.Y
		if ch.head == head and ch.pos == headPos and ch.cf == camCF
			and ch.fov == fov and ch.vx == viewX and ch.vy == viewY and ch.col == ch_col then
			return
		end
		ch.head, ch.pos, ch.cf = head, headPos, camCF
		ch.fov, ch.vx, ch.vy, ch.col = fov, viewX, viewY, ch_col
		local px, py, cosT, sinT = ch.px, ch.py, ch.cos, ch.sin
		local baseY = headPos.Y + head.Size.Y * 0.5 - CH_DROP
		local center = Vector3.new(headPos.X, baseY, headPos.Z)
		local apex = camera:WorldToViewportPoint(center + Vector3.new(0, CH_HEIGHT, 0))
		if apex.Z <= 0 then
			ch.visible(false)
			return
		end
		local probe = camera:WorldToViewportPoint(center + Vector3.new(cosT[1], 0, sinT[1]))
		if probe.Z <= 0 then
			ch.visible(false)
			return
		end
		px[1], py[1] = apex.X, apex.Y
		px[2], py[2] = probe.X, probe.Y
		local camPos = camCF.Position
		local rv, uv, lv = camCF.RightVector, camCF.UpVector, camCF.LookVector
		local ox, oy, oz = center.X - camPos.X, center.Y - camPos.Y, center.Z - camPos.Z
		local baseR = ox * rv.X + oy * rv.Y + oz * rv.Z
		local baseU = ox * uv.X + oy * uv.Y + oz * uv.Z
		local baseD = ox * lv.X + oy * lv.Y + oz * lv.Z
		local rvx, rvz, uvx, uvz, lvx, lvz = rv.X, rv.Z, uv.X, uv.Z, lv.X, lv.Z
		local scale = viewY * 0.5 / math.tan(math.rad(fov * 0.5))
		local midX, midY = viewX * 0.5, viewY * 0.5
		local eps = ch.eps
		local exact = false
		local dep = baseD + CH_HEIGHT * lv.Y
		if dep > 0 then
			local inv = scale / dep
			if math.abs(midX + (baseR + CH_HEIGHT * rv.Y) * inv - apex.X) <= eps
				and math.abs(midY - (baseU + CH_HEIGHT * uv.Y) * inv - apex.Y) <= eps then
				local c, s = cosT[1], sinT[1]
				dep = baseD + c * lvx + s * lvz
				if dep > 0 then
					inv = scale / dep
					if math.abs(midX + (baseR + c * rvx + s * rvz) * inv - probe.X) <= eps
						and math.abs(midY - (baseU + c * uvx + s * uvz) * inv - probe.Y) <= eps then
						exact = true
					end
				end
			end
		end
		if exact then
			for i = 2, CH_SEGMENTS do
				local c, s = cosT[i], sinT[i]
				local d = baseD + c * lvx + s * lvz
				if d <= 0 then
					ch.visible(false)
					return
				end
				local inv = scale / d
				px[i + 1] = midX + (baseR + c * rvx + s * rvz) * inv
				py[i + 1] = midY - (baseU + c * uvx + s * uvz) * inv
			end
		else
			for i = 2, CH_SEGMENTS do
				local point = camera:WorldToViewportPoint(center + Vector3.new(cosT[i], 0, sinT[i]))
				if point.Z <= 0 then
					ch.visible(false)
					return
				end
				px[i + 1] = point.X
				py[i + 1] = point.Y
			end
		end
		local hn = ch.hull(CH_SEGMENTS + 1)
		if hn < 3 then
			ch.visible(false)
			return
		end
		local st = ch.stack
		local minY, maxY = math.huge, -math.huge
		for i = 1, hn do
			local y = py[st[i]]
			if y < minY then minY = y end
			if y > maxY then maxY = y end
		end
		local firstY = math.max(0, math.floor(minY))
		local lastY = math.min(viewY, math.ceil(maxY))
		if lastY - firstY < 2 then
			ch.visible(false)
			return
		end
		local step = math.max(1, math.ceil((lastY - firstY) / CH_MAX_ROWS))
		local span = math.max(1, maxY - minY)
		local rows, shown = ch.rows, ch.shown
		local cpos, csize, ccol = ch.cpos, ch.csize, ch.ccol
		local white, black = ch.white, ch.black
		local used = 0
		for y0 = firstY, lastY - 1, step do
			local height = math.min(step, lastY - y0)
			local y = y0 + height * 0.5
			local left, right = math.huge, -math.huge
			local ax, ay = px[st[hn]], py[st[hn]]
			for i = 1, hn do
				local ix = st[i]
				local bx, by = px[ix], py[ix]
				if (ay <= y and by > y) or (by <= y and ay > y) then
					local x = ax + (y - ay) * (bx - ax) / (by - ay)
					if x < left then left = x end
					if x > right then right = x end
				end
				ax, ay = bx, by
			end
			local width = right - left
			if width >= 2.5 then
				used = used + 1
				local row = ch.row(used)
				local t = (y - minY) / span
				local light = 1 - t * 1.35
				local dark = (t - 0.58) / 0.42
				if light < 0 then light = 0 end
				if dark < 0 then dark = 0 end
				local color = ch_col:Lerp(white, light * 0.26):Lerp(black, dark * 0.1)
				local pos = Vector2.new(left, y0)
				local size = Vector2.new(width, height)
				if cpos[used] ~= pos then
					row.Position = pos
					cpos[used] = pos
				end
				if csize[used] ~= size then
					row.Size = size
					csize[used] = size
				end
				if ccol[used] ~= color then
					row.Color = color
					ccol[used] = color
				end
				if not shown[used] then
					row.Visible = true
					shown[used] = true
				end
			end
		end
		for i = used + 1, #rows do
			if shown[i] then
				rows[i].Visible = false
				shown[i] = false
			end
		end
	end

	local vis_conn = run.Heartbeat:Connect(function()
		LPH_ATTRIBUTES(VM(NONE))
		if bt_on then bt_update() end
		if sc_on then sc_apply() end
		if tc_on then tc_apply() end
	end)

	chrom_conn = run.RenderStepped:Connect(function()
		LPH_ATTRIBUTES(VM(NONE))
		local cam = ws.CurrentCamera
		if ch_on then ch.update(cam) end
		if not chrom_world then return end
		if chrom_view.CurrentCamera ~= cam then chrom_view.CurrentCamera = cam end
		if sc_on and sc_type == "Chromatic" then chrom_sync(sc_chrom) end
		if tc_on and tc_type == "Chromatic" then chrom_sync(tc_chrom) end
	end)

	local char_conn = lp.CharacterAdded:Connect(function()
		task.wait(0.4)
		if bt_on then bt_build() end
		if lc_on then lc_bind() end
		if mg_on then mg_reset_history() end
	end)

	getgenv().LOCAL_VIS_UNLOAD = function()
		bt_on, sc_on, tc_on, lc_on, mg_on, ch_on = false, false, false, false, false, false
		mg_clear()
		pcall(ch.clear)
		if vis_conn then
			pcall(function() vis_conn:Disconnect() end)
			vis_conn = nil
		end
		if char_conn then
			pcall(function() char_conn:Disconnect() end)
			char_conn = nil
		end
		if lc_con then
			pcall(function() lc_con:Disconnect() end)
			lc_con = nil
		end
		for i = 1, #sc_conns do
			pcall(function() sc_conns[i]:Disconnect() end)
		end
		table.clear(sc_conns)
		for i = 1, #tc_conns do
			pcall(function() tc_conns[i]:Disconnect() end)
		end
		table.clear(tc_conns)
		sc_char, tc_char = nil, nil
		sc_valid, tc_valid = false, false
		if chrom_conn then
			pcall(function() chrom_conn:Disconnect() end)
			chrom_conn = nil
		end
		pcall(function() flat_clear(sc_flat) end)
		pcall(function() flat_clear(tc_flat) end)
		pcall(function() chrom_clear(sc_chrom) end)
		pcall(function() chrom_clear(tc_chrom) end)
		if chrom_view then
			pcall(function() chrom_view.Parent:Destroy() end)
			chrom_view, chrom_world = nil, nil
		end
		pcall(sc_restore)
		pcall(tc_restore)
		pcall(bt_destroy)
	end

	local ch_tgl = sv:AddToggle({
		Name = "china hat",
		Default = false,
		Flag = "local_china_hat",
		Option = true,
		Callback = function(v)
			ch_on = v
			if v then
				ch.build()
			else
				ch.clear()
			end
		end
	})

	ch_tgl.Option:AddColorPicker({
		Name = "color",
		Default = ch_col,
		Flag = "local_china_hat_col",
		Callback = function(c)
			ch_col = c
		end
	})

	local bt_tgl = sv:AddToggle({
		Name = "backtrack",
		ToolTip = "Shows ur server position",
		Default = false,
		Flag = "Backtrack",
		Option = true,
		Callback = function(v)
			bt_on = v
			if v then
				if not bt_model then bt_build() end
			else
				bt_destroy()
			end
		end
	})

	bt_tgl.Option:AddColorPicker({
		Name = "color",
		Default = bt_col,
		Flag = "local_backtrack_col",
		Callback = function(c)
			bt_col = c
			if bt_model then
				for _, p in bt_model:GetDescendants() do
					if p:IsA("BasePart") and p.Name ~= "HumanoidRootPart" then p.Color = c end
				end
			end
		end
	})

	local sc_tgl = sv:AddToggle({
		Name = "self chams",
		Default = false,
		Flag = "Self Chams",
		Option = true,
		Callback = function(v)
			sc_on = v
			if not v then
				flat_clear(sc_flat)
				chrom_clear(sc_chrom)
				sc_restore()
			end
		end
	})

	sc_tgl.Option:AddDropdown({
		Name = "preset",
		Default = "ForceField",
		Values = {"ForceField", "Flat", "Chromatic"},
		Flag = "local_self_chams_type",
		Callback = function(v)
			sc_type = v
		end
	})

	sc_tgl.Option:AddColorPicker({
		Name = "color",
		Default = sc_col,
		Flag = "local_self_chams_col",
		Callback = function(c)
			sc_col = c
		end
	})

	local tc_tgl = sv:AddToggle({
		Name = "tool chams",
		Default = false,
		Flag = "Tool Chams",
		Option = true,
		Callback = function(v)
			tc_on = v
			if not v then
				flat_clear(tc_flat)
				chrom_clear(tc_chrom)
				tc_restore()
			end
		end
	})

	tc_tgl.Option:AddDropdown({
		Name = "preset",
		Default = "ForceField",
		Values = {"ForceField", "Flat", "Chromatic"},
		Flag = "local_tool_chams_type",
		Callback = function(v)
			tc_type = v
		end
	})

	tc_tgl.Option:AddColorPicker({
		Name = "color",
		Default = tc_col,
		Flag = "local_tool_chams_col",
		Callback = function(c)
			tc_col = c
		end
	})

	local lc_tgl = sv:AddToggle({
		Name = "landing circle",
		Default = false,
		Flag = "local_landing_circle",
		Option = true,
		Callback = function(v)
			lc_on = v
			if v then
				lc_bind()
			elseif lc_con then
				lc_con:Disconnect()
				lc_con = nil
			end
		end
	})

	lc_tgl.Option:AddColorPicker({
		Name = "color",
		Default = lc_col,
		Flag = "local_landing_circle_col",
		Callback = function(c)
			lc_col = c
		end
	})

	lc_tgl.Option:AddSlider({
		Name = "transp",
		Min = 0,
		Max = 1,
		Default = 1,
		Round = 2,
		Flag = "local_landing_circle_tr",
		Callback = function(v)
			lc_tr = v
		end
	})

	lc_tgl.Option:AddSlider({
		Name = "duration",
		Min = 0.1,
		Max = 3,
		Default = 0.82,
		Round = 2,
		Flag = "local_landing_circle_dur",
		Callback = function(v)
			lc_dur = v
		end
	})
	local mg_tgl = sv:AddToggle({
		Name = "mov graph",
		Default = false,
		Flag = "local_movement_graph",
		Option = true,
		Callback = function(v)
			mg_on = v
			if v then mg_start() else mg_clear() end
		end
	})

	mg_tgl.Option:AddColorPicker({
		Name = "color",
		Default = mg_color,
		Flag = "local_movement_graph_color",
		Callback = function(c)
			mg_color = c
			mg_apply_style()
		end
	})

	mg_tgl.Option:AddSlider({
		Name = "width",
		Min = 180,
		Max = 420,
		Default = 280,
		Round = 0,
		Type = "px",
		Flag = "local_movement_graph_width",
		Callback = function(v) mg_width = v end
	})

	mg_tgl.Option:AddSlider({
		Name = "height",
		Min = 40,
		Max = 120,
		Default = 72,
		Round = 0,
		Type = "px",
		Flag = "local_movement_graph_height",
		Callback = function(v) mg_height = v end
	})

	mg_tgl.Option:AddSlider({
		Name = "y",
		Min = -200,
		Max = 400,
		Default = 180,
		Round = 0,
		Type = "px",
		Flag = "local_movement_graph_y_position",
		Callback = function(v) mg_offset = v end
	})
end

do
	local players = game:GetService("Players")
	local rs = game:GetService("ReplicatedStorage")
	local ws = workspace
	local kill_lp = players.LocalPlayer

	local kill_sec = visuals:AddSection({
		Name = "effects",
		Position = 'right'
	})
	getgenv().__SHITARO_EFFECTS_SEC = kill_sec

	local murder_on, clone_on, particle_on, emitter_on, murder_col = false, false, false, false, Color3.fromRGB(255, 0, 0)
	local particle_col = Color3.fromRGB(255, 0, 0)
	local emitter_col = Color3.fromRGB(255, 100, 100)
	local clone_duration = 3
	local emitter_duration = 1.2
	local kill_clones, death_conns, role_map = {}, {}, {}
	local add_conn, poll_thread = nil, nil
	local role_remote = nil
	local tween = game:GetService("TweenService")
	
	local emitter_active = {}
	local emitter_active_count = 0

	local function remove_emitter_effect(record)
		for i = 1, emitter_active_count do
			if emitter_active[i] == record then
				emitter_active[i] = emitter_active[emitter_active_count]
				emitter_active[emitter_active_count] = nil
				emitter_active_count = emitter_active_count - 1
				break
			end
		end
		if record.part and record.part.Parent then record.part:Destroy() end
	end

	local function spawn_neverlose_emitter(char, tint, duration, channel)
		if not char or not char.Parent then return end
		if emitter_active_count >= 3 then
			remove_emitter_effect(emitter_active[1])
		end

		duration = math.max(duration, 0.2)
		local body_parts = {}
		for _, source in ipairs(char:GetChildren()) do
			if source:IsA("BasePart") and source.Name ~= "HumanoidRootPart" and #body_parts < 15 then
				body_parts[#body_parts + 1] = source
			end
		end
		if #body_parts == 0 then return end

		local root = Instance.new("Folder")
		root.Name = "\0"
		root.Parent = ws
		local record = {part = root, balls = {}, channel = channel}
		emitter_active_count = emitter_active_count + 1
		emitter_active[emitter_active_count] = record

		local random = math.random
		local pi2 = math.pi * 2
		local golden_angle = math.pi * (3 - math.sqrt(5))
		local function surface_position(source, radius, index, count, head_seed)
			local size = source.Size
			local padding = radius * 0.92
			if source.Name == "Head" then
				local y = 1 - 2 * ((index - 0.5) / count)
				local angle = index * golden_angle + head_seed
				local radial = math.sqrt(math.max(0, 1 - y * y))
				local dir = Vector3.new(radial * math.cos(angle), y, radial * math.sin(angle))
				local half = size * 0.5
				return source.CFrame:PointToWorldSpace(Vector3.new(
					dir.X * (half.X + padding),
					dir.Y * (half.Y + padding),
					dir.Z * (half.Z + padding)
				))
			end

			local area_x = size.Y * size.Z
			local area_y = size.X * size.Z
			local area_z = size.X * size.Y
			local pick = random() * (area_x + area_y + area_z)
			local pos
			if pick < area_x then
				local side = random() < 0.5 and -1 or 1
				pos = Vector3.new(side * (size.X * 0.5 + padding), (random() - 0.5) * size.Y, (random() - 0.5) * size.Z)
			elseif pick < area_x + area_y then
				local side = random() < 0.5 and -1 or 1
				pos = Vector3.new((random() - 0.5) * size.X, side * (size.Y * 0.5 + padding), (random() - 0.5) * size.Z)
			else
				local side = random() < 0.5 and -1 or 1
				pos = Vector3.new((random() - 0.5) * size.X, (random() - 0.5) * size.Y, side * (size.Z * 0.5 + padding))
			end
			return source.CFrame:PointToWorldSpace(pos)
		end

		local min_y = math.huge
		local max_y = -math.huge
		for _, source in ipairs(body_parts) do
			local half_y = source.Size.Y * 0.5
			min_y = math.min(min_y, source.Position.Y - half_y)
			max_y = math.max(max_y, source.Position.Y + half_y)
		end

		local phase_count = 8
		local groups = {}
		for i = 1, phase_count do groups[i] = {} end
		local head_seed = random() * pi2
		local height = math.max(max_y - min_y, 0.01)
		local created = 0
		for _, source in ipairs(body_parts) do
			local size = source.Size
			local surface = 2 * (size.X * size.Y + size.X * size.Z + size.Y * size.Z)
			local count = source.Name == "Head" and 24 or math.clamp(math.floor(surface * 0.65 + 0.5), 7, 12)
			count = math.min(count, 140 - created)
			for index = 1, count do
				local diameter = source.Name == "Head" and (0.115 + random() * 0.045) or (0.13 + random() * 0.06)
				local target_size = Vector3.new(diameter, diameter, diameter)
				local position = surface_position(source, diameter * 0.5, index, count, head_seed)
				local ball = Instance.new("Part")
				ball.Name = "\0"
				ball.Shape = Enum.PartType.Ball
				ball.Material = Enum.Material.Neon
				ball.Color = tint
				ball.Size = Vector3.new(0.015, 0.015, 0.015)
				ball.Position = position
				ball.Anchored = true
				ball.CanCollide = false
				ball.CanQuery = false
				ball.CanTouch = false
				ball.CastShadow = false
				ball.Massless = true
				ball.Transparency = 1
				ball.Parent = root
				record.balls[#record.balls + 1] = ball
				created = created + 1

				local vertical = math.clamp((position.Y - min_y) / height, 0, 1)
				local phase = math.clamp(math.floor(vertical * (phase_count - 1) + 1.5) + random(-1, 1), 1, phase_count)
				groups[phase][#groups[phase] + 1] = {ball = ball, size = target_size}
			end
			if created >= 140 then break end
		end

		local reveal_window = math.min(0.34, duration * 0.26)
		local reveal_time = math.min(0.2, duration * 0.18)
		local fade_begin = math.max(reveal_window + reveal_time + 0.06, duration * 0.42)
		local fade_window = math.min(0.28, duration * 0.18)
		local fade_time = math.max(duration - fade_begin - fade_window, 0.1)
		for phase = 1, phase_count do
			local alpha = (phase - 1) / (phase_count - 1)
			local group = groups[phase]
			task.delay(reveal_window * alpha, function()
				if not root.Parent then return end
				for _, item in ipairs(group) do
					if item.ball.Parent then
						tween:Create(item.ball, TweenInfo.new(reveal_time, Enum.EasingStyle.Sine, Enum.EasingDirection.Out), {Size = item.size, Transparency = 0.05}):Play()
					end
				end
			end)
			task.delay(fade_begin + fade_window * alpha, function()
				if not root.Parent then return end
				for _, item in ipairs(group) do
					if item.ball.Parent then
						tween:Create(item.ball, TweenInfo.new(fade_time, Enum.EasingStyle.Sine, Enum.EasingDirection.InOut), {Size = item.size * 0.58, Transparency = 1}):Play()
					end
				end
			end)
		end

		task.delay(duration + 0.12, function()
			remove_emitter_effect(record)
		end)
	end

	local function spawn_emitter(char)
		spawn_neverlose_emitter(char, emitter_col, emitter_duration, "emitter")
	end

	local function fade_clone(clone, dur)
		task.delay(dur, function()
			if not clone.Parent then return end
			for _, d in ipairs(clone:GetDescendants()) do
				if d:IsA("BasePart") and d.Name ~= "HumanoidRootPart" then
					pcall(function()
						tween:Create(d, TweenInfo.new(1.5, Enum.EasingStyle.Linear), {Transparency = 1}):Play()
					end)
				end
			end
			task.delay(1.6, function()
				for i = #kill_clones, 1, -1 do
					if kill_clones[i] == clone then table.remove(kill_clones, i) end
				end
				if clone.Parent then clone:Destroy() end
			end)
		end)
	end

	local function make_clone(char)
		local ok, clone = pcall(function() return char:Clone() end)
		if not ok or not clone then return end
		for _, d in ipairs(clone:GetDescendants()) do
			if d:IsA("BasePart") then
				d.Anchored = true
				d.CanCollide = false
				d.CanQuery = false
				d.CanTouch = false
				if d.Name == "HumanoidRootPart" then
					d.Transparency = 1
				else
					d.Material = Enum.Material.ForceField
					d.Color = murder_col
				end
			elseif d:IsA("Humanoid") or d:IsA("Script") or d:IsA("LocalScript") or d:IsA("ModuleScript") or d:IsA("Sound") then
				pcall(function() d:Destroy() end)
			elseif d:IsA("SurfaceAppearance") then
				pcall(function() d:Destroy() end)
			elseif d:IsA("ParticleEmitter") or d:IsA("Trail") or d:IsA("Beam") or d:IsA("Smoke") or d:IsA("Fire") or d:IsA("Sparkles")
				or d:IsA("PointLight") or d:IsA("SpotLight") or d:IsA("SurfaceLight") or d:IsA("Highlight") then
				pcall(function() d:Destroy() end)
			end
		end
		if getgenv().SELF_CHAMS_CLEAN then
			pcall(getgenv().SELF_CHAMS_CLEAN, clone, char)
		end
		clone.Name = "\0"
		clone.Parent = ws
		kill_clones[#kill_clones+1] = clone
		fade_clone(clone, clone_duration)
	end

	local function spawn_particles(char)
		spawn_neverlose_emitter(char, particle_col, 1.2, "particle")
	end

	local function on_death(char)
		if clone_on then make_clone(char) end
		if particle_on then spawn_particles(char) end
		if emitter_on then spawn_emitter(char) end
	end

	local function hook_player(pl)
		local function on_char(char)
			local hum = char:WaitForChild("Humanoid", 5)
			if not hum then return end
			death_conns[#death_conns+1] = hum.Died:Connect(function()
				if murder_on and role_map[pl.Name] == "Murderer" then
					on_death(char)
				end
			end)
		end
		if pl.Character then task.spawn(on_char, pl.Character) end
		death_conns[#death_conns+1] = pl.CharacterAdded:Connect(on_char)
	end

	local function stop()
		for _, c in ipairs(death_conns) do pcall(function() c:Disconnect() end) end
		death_conns = {}
		for i = 1, emitter_active_count do
			local p = emitter_active[i]
			if p then pcall(function() p.part:Destroy() end) end
			emitter_active[i] = nil
		end
		emitter_active_count = 0
		if add_conn then pcall(function() add_conn:Disconnect() end) add_conn = nil end
		for _, cl in ipairs(kill_clones) do pcall(function() cl:Destroy() end) end
		kill_clones = {}
	end

	local murder_tgl = kill_sec:AddToggle({
		Name = "murder",
		ToolTip = "Shows the consequences for the murderer if he is killed",
		Default = false,
		Flag = "Murder Effect",
		Option = true,
		Callback = function(v)
			murder_on = v
			if v then
				poll_thread = task.spawn(function()
					while murder_on do
						pcall(function()
							local f = role_remote
							if not f or not f.Parent then
								f = rs:FindFirstChild("GetPlayerData", true)
								role_remote = f
							end
							local data = f and f:InvokeServer()
							if type(data) == "table" then
								local m = {}
								for name, d in pairs(data) do
									if type(d) == "table" and d.Role then m[name] = d.Role end
								end
								role_map = m
							end
						end)
						task.wait(1)
					end
				end)
				for _, pl in ipairs(players:GetPlayers()) do
					if pl ~= kill_lp then hook_player(pl) end
				end
				add_conn = players.PlayerAdded:Connect(function(pl)
					if pl ~= kill_lp then hook_player(pl) end
				end)
			else
				stop()
			end
		end
	})

	murder_tgl.Option:AddToggle({
		Name = "clone",
		Default = false,
		Flag = "Murder Clone",
		ToolTip = "Creates a clone of the murderer when he die",	
		Callback = function(v)
			clone_on = v
		end
	})

	murder_tgl.Option:AddColorPicker({
		Name = "color",
		Default = murder_col,
		Flag = "kill_murder_col",
		Callback = function(c)
			murder_col = c
			for _, cl in ipairs(kill_clones) do
				for _, d in ipairs(cl:GetDescendants()) do
					if d:IsA("BasePart") and d.Name ~= "HumanoidRootPart" then d.Color = c end
				end
			end
		end
	})

	murder_tgl.Option:AddSlider({
		Name = "duration",
		Min = 1,
		Max = 5,
		Default = 3,
		Increment = 0.1,
		Flag = "Murder Clone Duration",
		Callback = function(v)
			clone_duration = v
		end
	})

	murder_tgl.Option:AddToggle({
		Name = "particle",
		Default = false,
		Flag = "Murder Particle",
		ToolTip = "Shows a particle effect when the murderer is killed",
		Callback = function(v)
			particle_on = v
		end
	})

	murder_tgl.Option:AddColorPicker({
		Name = "color",
		Default = particle_col,
		Flag = "kill_murder_particle_col",
		Callback = function(c)
			particle_col = c
		end
	})

	murder_tgl.Option:AddToggle({
		Name = "emitter",
		Default = false,
		Flag = "Murder Emitter",
		ToolTip = "Shows an emitter particle effect when the murderer is killed",
		Callback = function(v)
			emitter_on = v
		end
	})

	murder_tgl.Option:AddColorPicker({
		Name = "color",
		Default = emitter_col,
		Flag = "kill_murder_emitter_col",
		Callback = function(c)
			emitter_col = c
			for i = 1, emitter_active_count do
				local effect = emitter_active[i]
				if effect and effect.channel == "emitter" then
					for _, ball in ipairs(effect.balls) do
						if ball.Parent then ball.Color = c end
					end
				end
			end
		end
	})

	murder_tgl.Option:AddSlider({
		Name = "duration",
		Min = 1,
		Max = 5,
		Default = 1,
		Increment = 0.1,
		Flag = "Murder Emitter Duration",
		Callback = function(v)
			emitter_duration = v
		end
	})

	getgenv().KILL_UNLOAD = function()
		murder_on = false
		stop()
	end
end

do
	local players = game:GetService("Players")
	local rs = game:GetService("ReplicatedStorage")
	local ws = workspace
	local lp = players.LocalPlayer
	local tween = game:GetService("TweenService")

	local players_death_on, players_clone_on, players_particle_on, players_emitter_on = false, false, false, false
	local players_clone_col = Color3.fromRGB(255, 0, 0)
	local players_particle_col = Color3.fromRGB(255, 0, 0)
	local players_emitter_col = Color3.fromRGB(255, 100, 100)
	local players_clone_duration = 3
	local players_emitter_duration = 1.2
	local players_clones = {}
	local victim_tracking = {}
	local player_roles = {}
	local role_poll_thread = nil
	
	local players_emitter_active = {}
	local players_emitter_active_count = 0

	local function remove_players_emitter_effect(record)
		for i = 1, players_emitter_active_count do
			if players_emitter_active[i] == record then
				players_emitter_active[i] = players_emitter_active[players_emitter_active_count]
				players_emitter_active[players_emitter_active_count] = nil
				players_emitter_active_count = players_emitter_active_count - 1
				break
			end
		end
		if record.part and record.part.Parent then record.part:Destroy() end
	end

	local function spawn_players_neverlose_emitter(char, tint, duration, channel)
		if not char or not char.Parent then return end
		if players_emitter_active_count >= 3 then
			remove_players_emitter_effect(players_emitter_active[1])
		end

		duration = math.max(duration, 0.2)
		local body_parts = {}
		for _, source in ipairs(char:GetChildren()) do
			if source:IsA("BasePart") and source.Name ~= "HumanoidRootPart" and #body_parts < 15 then
				body_parts[#body_parts + 1] = source
			end
		end
		if #body_parts == 0 then return end

		local root = Instance.new("Folder")
		root.Name = "\0"
		root.Parent = ws
		local record = {part = root, balls = {}, channel = channel}
		players_emitter_active_count = players_emitter_active_count + 1
		players_emitter_active[players_emitter_active_count] = record

		local random = math.random
		local pi2 = math.pi * 2
		local golden_angle = math.pi * (3 - math.sqrt(5))
		local function surface_position(source, radius, index, count, head_seed)
			local size = source.Size
			local padding = radius * 0.92
			if source.Name == "Head" then
				local y = 1 - 2 * ((index - 0.5) / count)
				local angle = index * golden_angle + head_seed
				local radial = math.sqrt(math.max(0, 1 - y * y))
				local dir = Vector3.new(radial * math.cos(angle), y, radial * math.sin(angle))
				local half = size * 0.5
				return source.CFrame:PointToWorldSpace(Vector3.new(
					dir.X * (half.X + padding),
					dir.Y * (half.Y + padding),
					dir.Z * (half.Z + padding)
				))
			end

			local area_x = size.Y * size.Z
			local area_y = size.X * size.Z
			local area_z = size.X * size.Y
			local pick = random() * (area_x + area_y + area_z)
			local pos
			if pick < area_x then
				local side = random() < 0.5 and -1 or 1
				pos = Vector3.new(side * (size.X * 0.5 + padding), (random() - 0.5) * size.Y, (random() - 0.5) * size.Z)
			elseif pick < area_x + area_y then
				local side = random() < 0.5 and -1 or 1
				pos = Vector3.new((random() - 0.5) * size.X, side * (size.Y * 0.5 + padding), (random() - 0.5) * size.Z)
			else
				local side = random() < 0.5 and -1 or 1
				pos = Vector3.new((random() - 0.5) * size.X, (random() - 0.5) * size.Y, side * (size.Z * 0.5 + padding))
			end
			return source.CFrame:PointToWorldSpace(pos)
		end

		local min_y = math.huge
		local max_y = -math.huge
		for _, source in ipairs(body_parts) do
			local half_y = source.Size.Y * 0.5
			min_y = math.min(min_y, source.Position.Y - half_y)
			max_y = math.max(max_y, source.Position.Y + half_y)
		end

		local phase_count = 8
		local groups = {}
		for i = 1, phase_count do groups[i] = {} end
		local head_seed = random() * pi2
		local height = math.max(max_y - min_y, 0.01)
		local created = 0
		for _, source in ipairs(body_parts) do
			local size = source.Size
			local surface = 2 * (size.X * size.Y + size.X * size.Z + size.Y * size.Z)
			local count = source.Name == "Head" and 24 or math.clamp(math.floor(surface * 0.65 + 0.5), 7, 12)
			count = math.min(count, 140 - created)
			for index = 1, count do
				local diameter = source.Name == "Head" and (0.115 + random() * 0.045) or (0.13 + random() * 0.06)
				local target_size = Vector3.new(diameter, diameter, diameter)
				local position = surface_position(source, diameter * 0.5, index, count, head_seed)
				local ball = Instance.new("Part")
				ball.Name = "\0"
				ball.Shape = Enum.PartType.Ball
				ball.Material = Enum.Material.Neon
				ball.Color = tint
				ball.Size = Vector3.new(0.015, 0.015, 0.015)
				ball.Position = position
				ball.Anchored = true
				ball.CanCollide = false
				ball.CanQuery = false
				ball.CanTouch = false
				ball.CastShadow = false
				ball.Massless = true
				ball.Transparency = 1
				ball.Parent = root
				record.balls[#record.balls + 1] = ball
				created = created + 1

				local vertical = math.clamp((position.Y - min_y) / height, 0, 1)
				local phase = math.clamp(math.floor(vertical * (phase_count - 1) + 1.5) + random(-1, 1), 1, phase_count)
				groups[phase][#groups[phase] + 1] = {ball = ball, size = target_size}
			end
			if created >= 140 then break end
		end

		local reveal_window = math.min(0.34, duration * 0.26)
		local reveal_time = math.min(0.2, duration * 0.18)
		local fade_begin = math.max(reveal_window + reveal_time + 0.06, duration * 0.42)
		local fade_window = math.min(0.28, duration * 0.18)
		local fade_time = math.max(duration - fade_begin - fade_window, 0.1)
		for phase = 1, phase_count do
			local alpha = (phase - 1) / (phase_count - 1)
			local group = groups[phase]
			task.delay(reveal_window * alpha, function()
				if not root.Parent then return end
				for _, item in ipairs(group) do
					if item.ball.Parent then
						tween:Create(item.ball, TweenInfo.new(reveal_time, Enum.EasingStyle.Sine, Enum.EasingDirection.Out), {Size = item.size, Transparency = 0.05}):Play()
					end
				end
			end)
			task.delay(fade_begin + fade_window * alpha, function()
				if not root.Parent then return end
				for _, item in ipairs(group) do
					if item.ball.Parent then
						tween:Create(item.ball, TweenInfo.new(fade_time, Enum.EasingStyle.Sine, Enum.EasingDirection.InOut), {Size = item.size * 0.58, Transparency = 1}):Play()
					end
				end
			end)
		end

		task.delay(duration + 0.12, function()
			remove_players_emitter_effect(record)
		end)
	end

	local function spawn_players_emitter(char)
		spawn_players_neverlose_emitter(char, players_emitter_col, players_emitter_duration, "emitter")
	end

	local pd_remote = nil

	local function poll_roles()
		pcall(function()
			local f = pd_remote
			if not f or not f.Parent then
				f = rs:FindFirstChild("GetPlayerData", true)
				pd_remote = f
			end
			local data = f and f:InvokeServer()
			if type(data) == "table" then
				local m = {}
				for name, d in pairs(data) do
					if type(d) == "table" and d.Role then m[name] = d.Role end
				end
				player_roles = m
			end
		end)
	end

	local function fade_players_clone(clone)
		task.delay(players_clone_duration, function()
			if not clone.Parent then return end
			for _, d in ipairs(clone:GetDescendants()) do
				if d:IsA("BasePart") and d.Name ~= "HumanoidRootPart" then
					pcall(function()
						tween:Create(d, TweenInfo.new(1.5, Enum.EasingStyle.Linear), {Transparency = 1}):Play()
					end)
				end
			end
			task.delay(1.6, function()
				for i = #players_clones, 1, -1 do
					if players_clones[i] == clone then table.remove(players_clones, i) end
				end
				if clone.Parent then clone:Destroy() end
			end)
		end)
	end

	local function make_players_clone(char)
		local ok, clone = pcall(function() return char:Clone() end)
		if not ok or not clone then return end
		for _, d in ipairs(clone:GetDescendants()) do
			if d:IsA("BasePart") then
				d.Anchored = true
				d.CanCollide = false
				d.CanQuery = false
				d.CanTouch = false
				if d.Name == "HumanoidRootPart" then
					d.Transparency = 1
				else
					d.Material = Enum.Material.ForceField
					d.Color = players_clone_col
				end
			elseif d:IsA("Humanoid") or d:IsA("Script") or d:IsA("LocalScript") or d:IsA("ModuleScript") or d:IsA("Sound") then
				pcall(function() d:Destroy() end)
			elseif d:IsA("SurfaceAppearance") then
				pcall(function() d:Destroy() end)
			elseif d:IsA("ParticleEmitter") or d:IsA("Trail") or d:IsA("Beam") or d:IsA("Smoke") or d:IsA("Fire") or d:IsA("Sparkles")
				or d:IsA("PointLight") or d:IsA("SpotLight") or d:IsA("SurfaceLight") or d:IsA("Highlight") then
				pcall(function() d:Destroy() end)
			end
		end
		if getgenv().SELF_CHAMS_CLEAN then
			pcall(getgenv().SELF_CHAMS_CLEAN, clone, char)
		end
		clone.Name = "\0"
		clone.Parent = ws
		players_clones[#players_clones+1] = clone
		fade_players_clone(clone)
	end

	local function spawn_players_particles(char)
		spawn_players_neverlose_emitter(char, players_particle_col, 1.2, "particle")
	end

	local function on_player_die(victim_char, victim_name)
		local role = player_roles[victim_name]
		if role == "Murderer" then return end
		if players_clone_on then make_players_clone(victim_char) end
		if players_particle_on then spawn_players_particles(victim_char) end
		if players_emitter_on then spawn_players_emitter(victim_char) end
	end

	local function track_player(victim_player)
		if victim_tracking[victim_player] then return end
		local function watch_char(char)
			local hum = char:WaitForChild("Humanoid", 5)
			if not hum then return end
			local conn = hum.Died:Connect(function()
				if players_death_on then
					on_player_die(char, victim_player.Name)
				end
			end)
			victim_tracking[victim_player] = conn
		end
		if victim_player.Character then
			task.spawn(watch_char, victim_player.Character)
		end
		victim_player.CharacterAdded:Connect(watch_char)
	end

	local function stop_players_effects()
		for _, conn in pairs(victim_tracking) do
			pcall(function() conn:Disconnect() end)
		end
		victim_tracking = {}
		for i = 1, players_emitter_active_count do
			local p = players_emitter_active[i]
			if p then pcall(function() p.part:Destroy() end) end
			players_emitter_active[i] = nil
		end
		players_emitter_active_count = 0
		for _, cl in ipairs(players_clones) do
			pcall(function() cl:Destroy() end)
		end
		players_clones = {}
		if role_poll_thread then
			pcall(function() task.cancel(role_poll_thread) end)
			role_poll_thread = nil
		end
		player_roles = {}
	end

	local players_death_tgl = getgenv().__SHITARO_EFFECTS_SEC:AddToggle({
		Name = "players",
		ToolTip = "Shows effects when any player dies (except murderer)",
		Default = false,
		Flag = "Players Deaths",
		Option = true,
		Callback = function(v)
			players_death_on = v
			if v then
				role_poll_thread = task.spawn(function()
					while players_death_on do
						poll_roles()
						task.wait(1)
					end
				end)
				for _, pl in ipairs(players:GetPlayers()) do
					if pl ~= lp then track_player(pl) end
				end
				players.PlayerAdded:Connect(function(pl)
					if players_death_on and pl ~= lp then track_player(pl) end
				end)
			else
				stop_players_effects()
			end
		end
	})

	players_death_tgl.Option:AddToggle({
		Name = "clone",
		Default = false,
		Flag = "Players Deaths Clone",
		ToolTip = "Creates a clone when a player dies",
		Callback = function(v)
			players_clone_on = v
		end
	})

	players_death_tgl.Option:AddColorPicker({
		Name = "color",
		Default = players_clone_col,
		Flag = "players_death_clone_col",
		Callback = function(c)
			players_clone_col = c
			for _, cl in ipairs(players_clones) do
				for _, d in ipairs(cl:GetDescendants()) do
					if d:IsA("BasePart") and d.Name ~= "HumanoidRootPart" then d.Color = c end
				end
			end
		end
	})

	players_death_tgl.Option:AddSlider({
		Name = "duration",
		Min = 1,
		Max = 5,
		Default = 3,
		Increment = 0.1,
		Flag = "Players Deaths Clone Duration",
		Callback = function(v)
			players_clone_duration = v
		end
	})

	players_death_tgl.Option:AddToggle({
		Name = "particle",
		Default = false,
		Flag = "Players Deaths Particle",
		ToolTip = "Shows a particle effect when a player dies",
		Callback = function(v)
			players_particle_on = v
		end
	})

	players_death_tgl.Option:AddColorPicker({
		Name = "color",
		Default = players_particle_col,
		Flag = "players_death_particle_col",
		Callback = function(c)
			players_particle_col = c
		end
	})

	players_death_tgl.Option:AddToggle({
		Name = "emitter",
		Default = false,
		Flag = "Players Deaths Emitter",
		ToolTip = "Shows an emitter particle effect when a player dies",
		Callback = function(v)
			players_emitter_on = v
		end
	})

	players_death_tgl.Option:AddColorPicker({
		Name = "color",
		Default = players_emitter_col,
		Flag = "players_death_emitter_col",
		Callback = function(c)
			players_emitter_col = c
			for i = 1, players_emitter_active_count do
				local effect = players_emitter_active[i]
				if effect and effect.channel == "emitter" then
					for _, ball in ipairs(effect.balls) do
						if ball.Parent then ball.Color = c end
					end
				end
			end
		end
	})

	players_death_tgl.Option:AddSlider({
		Name = "duration",
		Min = 1,
		Max = 5,
		Default = 1,
		Increment = 0.1,
		Flag = "Players Deaths Emitter Duration",
		Callback = function(v)
			players_emitter_duration = v
		end
	})

	getgenv().PLAYERS_DEATH_UNLOAD = function()
		players_death_on = false
		stop_players_effects()
	end
end

do
	local run_service = game:GetService("RunService")
	local players_service = game:GetService("Players")
	local local_player = players_service.LocalPlayer

	local render_stepped = run_service.RenderStepped
	local render_stepped_wait = render_stepped.Wait
	local vector3_new = Vector3.new
	local cframe_new = CFrame.new
	local vector3_zero = Vector3.zero
	local cframe_angles = CFrame.Angles
	local math_random = math.random
	local rad = math.rad
	local clock = os.clock
	local floor = math.floor
	local spawn = task.spawn
	local wait = task.wait

	local function round(num, decimals)
		local mult = 10^(decimals or 0)
		return floor(num * mult + 0.5 - (num < 0 and 1 or 0)) / mult
	end

	local local_server_position = cframe_new()
	local local_client_position = cframe_new()
	local local_parts = {}
	local local_fps = 200
	local anti_aim = {}
	local vehicle = nil
	local purchasing = nil
	local stomping = false
	local fake_pos_active = false

	getgenv().FAKE_POS_ACTIVE = false
	getgenv().FAKE_POS_MULTI_AXIS = {X = true, Y = true, Z = true}
	getgenv().FAKE_POS_RANGE_X = 9e9
	getgenv().FAKE_POS_RANGE_Y = 9e9
	getgenv().FAKE_POS_RANGE_Z = 9e9

	local function remove(tbl, index)
		local length = #tbl
		for i = index, length - 1 do
			tbl[i] = tbl[i + 1]
		end
		tbl[length] = nil
	end

	local hrp_protected = {}
	local part_protected = {}
	local humanoid_protected = {}
	local hooked_metatables = {}

	local function apply_hrp_fix(hrp)
		if hrp_protected[hrp] then return end
		hrp_protected[hrp] = true
		local old = getrawmetatable(hrp)
		if not old then return end
		local old_index = old.__index
		local old_newindex = old.__newindex

		hooked_metatables[hrp] = {mt = old, target = hrp}

		local new = {
			__index = newcclosure(function(self, index)
				if not checkcaller() and self and index == "CFrame" and (#anti_aim ~= 0 or purchasing) and not vehicle then
					return local_client_position
				end
				return old_index(self, index)
			end),
			__newindex = newcclosure(function(self, index, value)
				if not checkcaller() and self then
					if index == "Anchored" then
						return
					end
					if (index == "CFrame" or index == "Position") and (#anti_aim ~= 0 or purchasing) then
						return
					end
				end
				return old_newindex(self, index, value)
			end)
		}

		for k, v in old do
			if not new[k] then
				new[k] = v
			end
		end

		setrawmetatable(hrp, new)
	end

	local function protect_part(part)
		if part_protected[part] then return end
		part_protected[part] = true
		local old_mt = getrawmetatable(part)
		if not old_mt then return end
		local old_newindex = old_mt.__newindex
		if not old_newindex then return end

		hooked_metatables[part] = {mt = old_mt, target = part}

		local new_mt = {}
		for k, v in old_mt do new_mt[k] = v end

		new_mt.__newindex = newcclosure(function(self, index, value)
			if not checkcaller() and self then
				if index == "Anchored" or index == "CanCollide" then
					return
				end
			end
			return old_newindex(self, index, value)
		end)

		setrawmetatable(part, new_mt)
	end

	local function protect_humanoid(humanoid)
		if humanoid_protected[humanoid] then return end
		humanoid_protected[humanoid] = true
		local old_mt = getrawmetatable(humanoid)
		if not old_mt then return end
		local old_newindex = old_mt.__newindex
		if not old_newindex then return end

		hooked_metatables[humanoid] = {mt = old_mt, target = humanoid}

		local new_mt = {}
		for k, v in old_mt do new_mt[k] = v end

		new_mt.__newindex = newcclosure(function(self, index, value)
			if not checkcaller() and self and fake_pos_active then
				if index == "Health" and type(value) == "number" and value <= 0 then
					return
				end
			end
			return old_newindex(self, index, value)
		end)

		setrawmetatable(humanoid, new_mt)
	end

	local update_server_position = function(hrp)
		local_server_position = hrp.CFrame
	end

	local fake_position_sitting = false
	local local_fake_position = nil
	local orig_display_pos = nil
	local fake_position_sender_rate_old
	pcall(function()
		fake_position_sender_rate_old = getfflag("S2PhysicsSenderRate")
	end)
	local fake_position_refresh_connection = nil
	local fake_position_refresh_connection2 = nil
	local fake_position_refresh_connection3 = nil

	local fallen_height_old = nil

	local marker_enabled = true
	local marker_color = Color3.fromRGB(193, 247, 255)

	local b64set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	local function b64dec(data)
		data = data:gsub("[^" .. b64set .. "=]", "")
		return (data:gsub(".", function(x)
			if x == "=" then return "" end
			local r, f = "", b64set:find(x) - 1
			for i = 6, 1, -1 do r = r .. (f % 2 ^ i - f % 2 ^ (i - 1) > 0 and "1" or "0") end
			return r
		end):gsub("%d%d%d?%d?%d?%d?%d?%d?", function(x)
			if #x ~= 8 then return "" end
			local c = 0
			for i = 1, 8 do c = c + (x:sub(i, i) == "1" and 2 ^ (8 - i) or 0) end
			return string.char(c)
		end))
	end

	local marker_data = b64dec("iVBORw0KGgoAAAANSUhEUgAAAB0AAAAdCAMAAABhTZc9AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAPUExURQAAAP///wwMDP39/QAAAJn0DigAAAAFdFJOU/////8A+7YOUwAAAAlwSFlzAABLlgAAS5YBPIKNxAAAABh0RVh0U29mdHdhcmUAUGFpbnQuTkVUIDUuMS4y+7wDtgAAALZlWElmSUkqAAgAAAAFABoBBQABAAAASgAAABsBBQABAAAAUgAAACgBAwABAAAAAgAAADEBAgAQAAAAWgAAAGmHBAABAAAAagAAAAAAAAD7fwcA6AMAAPt/BwDoAwAAUGFpbnQuTkVUIDUuMS4yAAMAAJAHAAQAAAAwMjMwAaADAAEAAAABAAAABaAEAAEAAACUAAAAAAAAAAIAAQACAAQAAABSOTgAAgAHAAQAAAAwMTAwAAAAAFgdiCkiK10LAAAAZ0lEQVQ4T+XT0QqAMAgF0Gv5/9/cdJrXPYweopeEoe5MGKOgHMDSR/aAiPSNyBaGnT9S4Oi3pnqOtuEqE5kfaiHxG8pYTJoHrMzdzFu1h0qt57oLH58a/YhFfUU/4s967tT/Iv4mVS+LEAmXjonxPAAAAABJRU5ErkJggg==")

	local marker_bad_prop = {}
	local function marker_set(obj, prop, value)
		if marker_bad_prop[prop] then return end
		if not pcall(function() obj[prop] = value end) then
			marker_bad_prop[prop] = true
		end
	end

	local marker_glow = Drawing.new("Image")
	marker_set(marker_glow, "Data", marker_data)
	marker_set(marker_glow, "Color", marker_color)
	marker_set(marker_glow, "Transparency", 0.35)
	marker_set(marker_glow, "ZIndex", 1)
	marker_set(marker_glow, "Visible", false)

	local marker_icon = Drawing.new("Image")
	marker_set(marker_icon, "Data", marker_data)
	marker_set(marker_icon, "Color", marker_color)
	marker_set(marker_icon, "Transparency", 1)
	marker_set(marker_icon, "ZIndex", 2)
	marker_set(marker_icon, "Visible", false)

	local function hide_marker()
		marker_set(marker_glow, "Visible", false)
		marker_set(marker_icon, "Visible", false)
	end

	local function draw_marker(cx, cy)
		local gs = 46
		marker_set(marker_glow, "Size", Vector2.new(gs, gs))
		marker_set(marker_glow, "Position", Vector2.new(cx - gs / 2, cy - gs / 2))
		marker_set(marker_glow, "Color", marker_color)
		marker_set(marker_glow, "Visible", true)
		local isz = 30
		marker_set(marker_icon, "Size", Vector2.new(isz, isz))
		marker_set(marker_icon, "Position", Vector2.new(cx - isz / 2, cy - isz / 2))
		marker_set(marker_icon, "Color", marker_color)
		marker_set(marker_icon, "Visible", true)
	end

	local function set_world_limits(disable)
		if disable then
			pcall(function() fallen_height_old = gethiddenproperty(workspace, "FallenPartsDestroyHeight") end)
			pcall(function() sethiddenproperty(workspace, "FallenPartsDestroyHeight", -9e9) end)
		else
			pcall(function() sethiddenproperty(workspace, "FallenPartsDestroyHeight", fallen_height_old or -500) end)
		end
	end

	local ltm_parts = {}
	local ltm_char = nil
	local ltm_valid = false
	local ltm_conns = {}

	local function ltm_parts_for(character)
		if ltm_char ~= character then
			ltm_char = character
			ltm_valid = false
			for i = 1, #ltm_conns do
				pcall(function() ltm_conns[i]:Disconnect() end)
			end
			table.clear(ltm_conns)
			if character then
				local function dirty(d)
					if d:IsA("BasePart") then ltm_valid = false end
				end
				ltm_conns[1] = character.DescendantAdded:Connect(dirty)
				ltm_conns[2] = character.DescendantRemoving:Connect(dirty)
			end
		end
		if not ltm_valid then
			table.clear(ltm_parts)
			local n = 0
			for _, part in character:GetDescendants() do
				if part:IsA("BasePart") and part.Name ~= "HumanoidRootPart" then
					n = n + 1
					ltm_parts[n] = part
				end
			end
			ltm_valid = true
		end
		return ltm_parts
	end

	local function set_local_body_transparency(value)
		local character = local_player.Character
		if not character then return end
		local parts = ltm_parts_for(character)
		local target = value and 0.6 or 0
		for i = 1, #parts do
			local part = parts[i]
			if part.Parent then
				part.LocalTransparencyModifier = target
			end
		end
	end

	local do_refresh_fake_position = function()
		if local_server_position then
			local_fake_position = local_server_position.p
		end
	end

	local pending_teleport = nil
	local tp_settle_until = 0

	local do_fake_position = function(dt, hrp)
		LPH_ATTRIBUTES(VM(NONE))
		pcall(function() setfflag("S2PhysicsSenderRate", tostring(round(local_fps, 1))) end)
		if fake_position_sitting then
			local_fake_position = nil
			return
		end
		if dt > 0.45 then
			return
		end
		if hrp then
			pcall(function() sethiddenproperty(hrp, "NetworkIsSleeping", false) end)
			pcall(function()
				if hrp.AssemblyLinearVelocity.Magnitude < 1 then
					hrp.AssemblyLinearVelocity = vector3_new(0, 0.1, 0)
				end
			end)
		end

		local axes = getgenv().FAKE_POS_MULTI_AXIS
		local rx = getgenv().FAKE_POS_RANGE_X
		local ry = getgenv().FAKE_POS_RANGE_Y
		local rz = getgenv().FAKE_POS_RANGE_Z
		local base = local_client_position and local_client_position.p or vector3_zero
		local x = axes.X and ((math.random() * 2 - 1) * rx) or base.X
		local y = axes.Y and (-(math.random()) * ry) or base.Y
		local z = axes.Z and ((math.random() * 2 - 1) * rz) or base.Z

		if pending_teleport then
			pcall(function()
				hrp.CFrame = pending_teleport
				hrp.AssemblyLinearVelocity = vector3_zero
				hrp.AssemblyAngularVelocity = vector3_zero
			end)
			local_client_position = pending_teleport
			pending_teleport = nil
		end

		local old = hrp.CFrame
		local fake_cf = cframe_new(vector3_new(x, y, z)) * cframe_angles(rad(math_random(1,359)), rad(math_random(1,359)), rad(math_random(1,359)))
		orig_display_pos = fake_cf.Position
		hrp.CFrame = fake_cf
		render_stepped_wait(render_stepped)
		hrp.CFrame = old
	end

	getgenv().SHITARO_TELEPORT = function(cf)
		if typeof(cf) == "Vector3" then cf = cframe_new(cf) end
		if typeof(cf) ~= "CFrame" then return false end
		local hrp = local_parts["HumanoidRootPart"]
		if not hrp then return false end
		if fake_pos_active then
			cf = cframe_new(cf.Position)
			tp_settle_until = clock() + 0.35
			pending_teleport = cf
		else
			pcall(function() hrp.CFrame = cf end)
			local_client_position = cf
		end
		return true
	end

	local function fake_position_stop_sitting(character)
		local humanoid = local_parts["Humanoid"]
		if not humanoid then return end
		fake_position_sitting = humanoid.Sit

		if fake_position_refresh_connection3 then
			pcall(function() fake_position_refresh_connection3:Disconnect() end)
			fake_position_refresh_connection3 = nil
		end

		fake_position_refresh_connection3 = humanoid:GetPropertyChangedSignal("Sit"):Connect(function()
			fake_position_sitting = humanoid.Sit
			if not fake_position_sitting then
				spawn(do_refresh_fake_position)
			else
				local_fake_position = local_client_position and local_client_position.p
			end
		end)
	end

	local function fake_position_enable(value)
		local_fake_position = nil
		pending_teleport = nil
		fake_pos_active = value
		getgenv().FAKE_POS_ACTIVE = value

		for i = 1, #anti_aim do
			if anti_aim[i] == do_fake_position then
				remove(anti_aim, i)
				break
			end
		end

		if fake_position_refresh_connection then
			pcall(function() fake_position_refresh_connection:Disconnect() end)
			fake_position_refresh_connection = nil
		end
		if fake_position_refresh_connection2 then
			pcall(function() fake_position_refresh_connection2:Disconnect() end)
			fake_position_refresh_connection2 = nil
		end
		if fake_position_refresh_connection3 then
			pcall(function() fake_position_refresh_connection3:Disconnect() end)
			fake_position_refresh_connection3 = nil
		end

		set_local_body_transparency(value)

		if value then
			set_world_limits(true)
			anti_aim[#anti_aim+1] = do_fake_position

			local hrp = local_parts["HumanoidRootPart"]
			if hrp then
				pcall(function()
					sethiddenproperty(hrp, "NetworkIsSleeping", false)
					hrp.AssemblyLinearVelocity = vector3_new(0, 0.1, 0)
				end)
			end

			fake_position_refresh_connection = local_player.CharacterAdded:Connect(function()
				task.wait(0.5)
				spawn(do_refresh_fake_position)
				if local_parts["Humanoid"] then
					fake_position_stop_sitting(local_player.Character)
				end
				if fake_pos_active then
					set_local_body_transparency(true)
				end
			end)

			if local_player.Character then
				fake_position_stop_sitting(local_player.Character)
			end

			spawn(do_refresh_fake_position)
		else
			set_world_limits(false)
			pcall(function() setfflag("S2PhysicsSenderRate", fake_position_sender_rate_old or "15") end)
			pcall(function() setfpscap(0) end)
			local hrp = local_parts["HumanoidRootPart"]
			if hrp and local_client_position then
				pcall(function()
					sethiddenproperty(hrp, "NetworkIsSleeping", false)
					hrp.CFrame = local_client_position
					hrp.AssemblyLinearVelocity = vector3_new(0, 0.1, 0)
				end)
			end
			orig_display_pos = nil
			hide_marker()
		end
	end

	local function init_character(character)
		if not character then return end
		local hrp = character:WaitForChild("HumanoidRootPart", 5)
		if hrp then
			local_parts["HumanoidRootPart"] = hrp
			local humanoid = character:WaitForChild("Humanoid", 5)
			local_parts["Humanoid"] = humanoid
			apply_hrp_fix(hrp)
			if humanoid then
				protect_humanoid(humanoid)
			end

			for _, part in character:GetDescendants() do
				if part:IsA("BasePart") then
					protect_part(part)
				end
			end
			character.DescendantAdded:Connect(function(part)
				if part:IsA("BasePart") then
					protect_part(part)
				elseif part:IsA("Humanoid") then
					protect_humanoid(part)
				end
			end)

			if fake_pos_active then
				set_local_body_transparency(true)
			end
		end
	end

	init_character(local_player.Character)
	local char_added_conn = local_player.CharacterAdded:Connect(init_character)

	local last_fps = clock()
	local heartbeat_conn = run_service.Heartbeat:Connect(function(dt)
		local_fps = 1/(clock() - last_fps)
		last_fps = clock()

		local hrp = vehicle or local_parts["HumanoidRootPart"]

		if hrp then
			local_client_position = hrp.CFrame
		end

		if hrp and clock() < tp_settle_until then
			pcall(function()
				hrp.AssemblyLinearVelocity = vector3_zero
				hrp.AssemblyAngularVelocity = vector3_zero
			end)
		end

		for i = 1, #anti_aim do
			local func = anti_aim[i]
			if func then
				spawn(func, dt, hrp)
			end
		end

		if hrp then
			local_server_position = hrp.CFrame
		end
	end)

	local transparency_conn = run_service.RenderStepped:Connect(function()
		
		if fake_pos_active then
			set_local_body_transparency(true)
			if marker_enabled and orig_display_pos then
				local cam = workspace.CurrentCamera
				local pos = cam:WorldToViewportPoint(orig_display_pos)
				if pos.Z > 0 then
					draw_marker(pos.X, pos.Y)
				else
					hide_marker()
				end
			else
				hide_marker()
			end
		else
			hide_marker()
		end
	end)

	local function read_part_position(p)
		return p.Position
	end

	run_service:BindToRenderStep("shitaro_fakepos_cam", Enum.RenderPriority.Camera.Value - 1, function()
		if not fake_pos_active then return end
		local hrp = local_parts["HumanoidRootPart"]
		if not hrp or not local_client_position then return end
		local ok, pos = pcall(read_part_position, hrp)
		if ok and (pos - local_client_position.p).Magnitude > 500 then
			pcall(function() hrp.CFrame = local_client_position end)
		end
	end)

	getgenv().FAKE_POS_UNLOAD = function()
		if fake_pos_active then
			fake_position_enable(false)
		end
		if heartbeat_conn then
			pcall(function() heartbeat_conn:Disconnect() end)
			heartbeat_conn = nil
		end
		if transparency_conn then
			pcall(function() transparency_conn:Disconnect() end)
			transparency_conn = nil
		end
		pcall(function() run_service:UnbindFromRenderStep("shitaro_fakepos_cam") end)
		if char_added_conn then
			pcall(function() char_added_conn:Disconnect() end)
			char_added_conn = nil
		end
		set_world_limits(false)
		set_local_body_transparency(false)
		for i = 1, #ltm_conns do
			pcall(function() ltm_conns[i]:Disconnect() end)
		end
		table.clear(ltm_conns)
		ltm_char = nil
		ltm_valid = false
		orig_display_pos = nil
		pcall(function() marker_glow:Remove() end)
		pcall(function() marker_icon:Remove() end)
		for target, data in pairs(hooked_metatables) do
			pcall(function()
				setrawmetatable(target, data.mt)
			end)
		end
		hooked_metatables = {}
		hrp_protected = {}
		part_protected = {}
		humanoid_protected = {}
		anti_aim = {}
		pcall(function()
			setfflag("S2PhysicsSenderRate", fake_position_sender_rate_old or "15")
		end)
		pcall(function() setfpscap(0) end)
	end
	local fakeposs = CreateIndicator({
		Name = "FAKE",
		Icon = "heart",
		Color = "Green",
	})
	local velocity_desync_type = "low"
	local velocity_desync_rotate = false

	local do_velocity_desync = function(dt, hrp)
		LPH_ATTRIBUTES(VM(NONE))
		if hrp and not stomping and not purchasing and (getgenv().FLING_ACTIVE or 0) == 0 then
			pcall(function() setfflag("S2PhysicsSenderRate", tostring(round(local_fps, 1))) end)
			pcall(function() sethiddenproperty(hrp, "NetworkIsSleeping", false) end)
			local old_lin = hrp.AssemblyLinearVelocity
			local old_ang = hrp.AssemblyAngularVelocity
			local vel = velocity_desync_type == "y high" and vector3_new(0, 16384, 0)
				or velocity_desync_type == "limit" and vector3_new(
					math_random(-9223372036854775808, 9223372036854775807),
					math_random(-9223372036854775808, 9223372036854775807),
					math_random(-9223372036854775808, 9223372036854775807)
				)
				or velocity_desync_type == "low" and vector3_new(
					math_random(1,2) == 1 and -300 or 300,
					math_random(1,2) == 1 and -300 or 300,
					math_random(1,2) == 1 and -300 or 300
				)
				or velocity_desync_type == "high" and vector3_new(
					math_random(1,2) == 1 and -16384 or 16384,
					math_random(1,2) == 1 and -14384 or 16384,
					math_random(1,2) == 1 and -16384 or 16384
				)
				or velocity_desync_type == "zero" and vector3_zero
				or vector3_zero

			getgenv().VELOCITY_DESYNC_UNTIL = clock() + 0.35
			hrp.AssemblyLinearVelocity = vel
			if velocity_desync_rotate then
				hrp.AssemblyAngularVelocity = vel
			end

			render_stepped_wait(render_stepped)
			hrp.AssemblyLinearVelocity = old_lin
			hrp.AssemblyAngularVelocity = old_ang
			getgenv().VELOCITY_DESYNC_UNTIL = clock() + 0.05
		end
	end

	local function velocity_desync_enable(value)
		for i = 1, #anti_aim do
			if anti_aim[i] == do_velocity_desync then
				remove(anti_aim, i)
				break
			end
		end
		if value then
			anti_aim[#anti_aim+1] = do_velocity_desync
		else
			pcall(function() setfflag("S2PhysicsSenderRate", fake_position_sender_rate_old or "15") end)
		end
	end

	getgenv().__PLR_QUEUE("misc", "fake", function(sec)
		local fake_pos_toggle = sec:AddToggle({
			Name = "fake",
			ToolTip = "Randomizes your position on the server to make it harder\nfor others to hit you",
			Default = false,
			Flag = "Fake Position",
			Option = true,
			Callback = function(v)
				fakeposs:Set(v)
				fake_position_enable(v)
			end
		})

		fake_pos_toggle.Option:AddSlider({
			Name = "x",
			Default = 9,
			Min = 1,
			Max = 9,
			Round = 0,
			Flag = "player_fake_pos_range_x",
			Callback = function(v)
				getgenv().FAKE_POS_RANGE_X = v * 1e9
			end
		})

		fake_pos_toggle.Option:AddSlider({
			Name = "y",
			Default = 9,
			Min = 1,
			Max = 9,
			Round = 0,
			Flag = "player_fake_pos_range_y",
			Callback = function(v)
				getgenv().FAKE_POS_RANGE_Y = v * 1e9
			end
		})

		fake_pos_toggle.Option:AddSlider({
			Name = "z",
			Default = 9,
			Min = 1,
			Max = 9,
			Round = 0,
			Flag = "player_fake_pos_range_z",
			Callback = function(v)
				getgenv().FAKE_POS_RANGE_Z = v * 1e9
			end
		})

		fake_pos_toggle.Option:AddToggle({
			Name = "marker",
			Default = true,
			Flag = "Marker",
			Callback = function(v)
				marker_enabled = v
				if not v then hide_marker() end
			end
		})

		fake_pos_toggle.Option:AddColorPicker({
			Name = "color",
			Default = Color3.fromRGB(193, 247, 255),
			Flag = "player_fake_pos_marker_col",
			Callback = function(c)
				marker_color = c
			end
		})
	end)

	getgenv().__PLR_QUEUE("misc", "velocity spoof", function(sec)
		local vel_toggle = sec:AddToggle({
			Name = "velocity spoof",
			ToolTip = "Randomizes your velocity(breaks the prediction logic of fling and aim)",
			Default = false,
			Flag = "player_vel_desync",
			Option = true,
			Callback = function(v)
				velocity_desync_enable(v)
			end
		})

		vel_toggle.Option:AddDropdown({
			Name = "preset",
			Default = "low",
			Values = {"low", "high", "y high", "limit", "zero"},
			Flag = "player_vel_desync_type",
			Callback = function(v)
				velocity_desync_type = v
			end
		})

		
	end)
end

do
	local sec = player_tab:AddSection({
		Name = "misc",
		Position = 'left'
	})

	local char_sec = player_tab:AddSection({
		Name = "character",
		Position = 'right'
	})

	getgenv().__PLAYER_CHAR_SEC = char_sec

	local players = game:GetService("Players")
	local run = game:GetService("RunService")
	local uis = game:GetService("UserInputService")
	local vu = game:GetService("VirtualUser")
	local cs = game:GetService("CollectionService")
	local rs = game:GetService("ReplicatedStorage")
	local ws = workspace
	local lp = players.LocalPlayer

	local function get_hrp()
		local c = lp.Character
		return c and c:FindFirstChild("HumanoidRootPart")
	end

	local anti_master, afk_set, fling_set, void_set, coin_set, fade_set, trap_set = false, false, false, false, false, false, false
	local anti_afk, anti_fling, anti_void, anti_trap = false, false, false, false
	local coin_on = false
	local fade_on = false
	local void_original = ws.FallenPartsDestroyHeight
	local noclip_on, fly_on = false, false
	local inf_jump_on, wallhop_on = false, false
	local fly_speed = 60
	local fly_gravity = ws.Gravity
	local fly_up_on, fly_down_on = true, true
	local fly_up_kc, fly_down_kc = Enum.KeyCode.Space, Enum.KeyCode.LeftControl
	local noclip_cache = {}
	local fling_cache = {}
	local last_coin_backup = nil

	local function kill_container(d)
		pcall(function()
			d.Archivable = true
			last_coin_backup = { clone = d:Clone(), parent = d.Parent }
			d:Destroy()
		end)
	end

	local function wipe_coins()
		for _, v in ipairs(cs:GetTagged("CoinVisual")) do
			pcall(function() v:Destroy() end)
		end
		for _, d in ipairs(ws:GetDescendants()) do
			if d.Name == "CoinContainer" then
				kill_container(d)
			end
		end
	end

	local function restore_coins()
		if last_coin_backup and last_coin_backup.clone then
			pcall(function()
				last_coin_backup.clone.Parent = last_coin_backup.parent or ws
			end)
			last_coin_backup = nil
		end
	end

	local player_gui = lp:FindFirstChildOfClass("PlayerGui")
	local fade_cache = {}
	local fade_conns = {}

	local FADE_GUI_NAMES = { CameraFade = true, SpawnFade = true, Fade = true, DeathFade = true }
	local fade_desc_conn = nil

	local function fade_gui()
		if player_gui and player_gui.Parent then return player_gui end
		player_gui = lp:FindFirstChildOfClass("PlayerGui")
		return player_gui
	end

	local function fade_hide(frame)
		if not frame or not frame.Parent or not frame:IsA("GuiObject") then return end
		if fade_cache[frame] == nil then fade_cache[frame] = frame.Visible end
		if frame.Visible then pcall(function() frame.Visible = false end) end
		if not fade_conns[frame] then
			fade_conns[frame] = frame:GetPropertyChangedSignal("Visible"):Connect(function()
				if fade_on and frame.Visible then
					pcall(function() frame.Visible = false end)
				end
			end)
		end
	end

	local function fade_match(inst)
		if not inst:IsA("GuiObject") then return false end
		local parent = inst.Parent
		if not parent then return false end
		if (inst.Name == "Fade" or inst.Name == "Frame") and parent:IsA("ScreenGui") and FADE_GUI_NAMES[parent.Name] then
			return true
		end
		if inst.Name == "Fade" and parent.Name == "Game" then
			return true
		end
		return false
	end

	local function fade_targets()
		local list = {}
		local gui = fade_gui()
		if not gui then return list end
		for _, child in ipairs(gui:GetChildren()) do
			if child:IsA("ScreenGui") and FADE_GUI_NAMES[child.Name] then
				for _, sub in ipairs(child:GetChildren()) do
					if sub:IsA("GuiObject") and (sub.Name == "Fade" or sub.Name == "Frame") then
						list[#list + 1] = sub
					end
				end
			end
		end
		local main = gui:FindFirstChild("MainGUI")
		local gg = main and main:FindFirstChild("Game")
		local gf = gg and gg:FindFirstChild("Fade")
		if gf and gf:IsA("GuiObject") then list[#list + 1] = gf end
		return list
	end

	local function fade_watch()
		if fade_desc_conn then return end
		local gui = fade_gui()
		if not gui then return end
		fade_desc_conn = gui.DescendantAdded:Connect(function(d)
			if not fade_on then return end
			if not fade_match(d) then return end
			task.defer(function()
				if fade_on and d.Parent then pcall(fade_hide, d) end
			end)
		end)
	end

	local function fade_apply()
		fade_watch()
		for _, frame in ipairs(fade_targets()) do
			pcall(fade_hide, frame)
		end
	end

	local function fade_restore()
		for _, conn in pairs(fade_conns) do
			pcall(function() conn:Disconnect() end)
		end
		fade_conns = {}
		for frame, v in pairs(fade_cache) do
			if frame and frame.Parent then
				pcall(function()
					frame.BackgroundTransparency = 1
					frame.Visible = v
				end)
			end
		end
		fade_cache = {}
	end

	local FLING_MAX_VEL = 700
	local FLING_MAX_ANG = 90
	local FLING_SNAP_DIST = 60
	local FLING_HOLD = 0.25
	local FLING_SAFE_VEL = 250

	local fling_reg = {}
	local fling_conns = {}
	local fling_attached = false
	local fling_safe_cf = nil
	local fling_hold_until = 0

	local fling_active_since = 0

	local function fling_busy()
		if fly_on then return true end
		if os.clock() < (getgenv().VELOCITY_DESYNC_UNTIL or 0) then return true end
		if (getgenv().FLING_ACTIVE or 0) > 0 then
			local now = os.clock()
			if fling_active_since == 0 then fling_active_since = now end
			if now - fling_active_since < 20 then return true end
			getgenv().FLING_ACTIVE = 0
			fling_active_since = 0
			return false
		end
		fling_active_since = 0
		return false
	end

	local function fling_kill_part(p)
		if fling_cache[p] == nil then fling_cache[p] = p.CanCollide end
		if p.CanCollide then p.CanCollide = false end
	end

	local function fling_unregister(model)
		local entry = fling_reg[model]
		if not entry then return end
		fling_reg[model] = nil
		for i = 1, #entry.conns do
			pcall(function() entry.conns[i]:Disconnect() end)
		end
		for p in pairs(entry.parts) do
			local v = fling_cache[p]
			fling_cache[p] = nil
			if v ~= nil and p.Parent then
				pcall(function() p.CanCollide = v end)
			end
		end
		table.clear(entry.parts)
	end

	local function fling_register(model)
		if not anti_fling or not model then return end
		if fling_reg[model] or model == lp.Character then return end
		local entry = { parts = {}, conns = {} }
		fling_reg[model] = entry
		local function add(d)
			if d:IsA("BasePart") and not entry.parts[d] then
				entry.parts[d] = true
				if anti_fling then pcall(fling_kill_part, d) end
			end
		end
		for _, d in model:GetDescendants() do
			pcall(add, d)
		end
		local function push(c) entry.conns[#entry.conns + 1] = c end
		push(model.DescendantAdded:Connect(function(d)
			if anti_fling then pcall(add, d) end
		end))
		push(model.DescendantRemoving:Connect(function(d)
			if entry.parts[d] then
				entry.parts[d] = nil
				fling_cache[d] = nil
			end
		end))
		push(model.AncestryChanged:Connect(function(_, parent)
			if not parent then fling_unregister(model) end
		end))
	end

	local function fling_is_body(m)
		return m ~= lp.Character
			and m:IsA("Model")
			and m:FindFirstChildOfClass("Humanoid") ~= nil
	end

	local function fling_scan()
		for _, pl in players:GetPlayers() do
			if pl ~= lp and pl.Character then fling_register(pl.Character) end
		end
		for _, m in ws:GetChildren() do
			if fling_is_body(m) then fling_register(m) end
		end
	end

	local function fling_sweep()
		for model, entry in pairs(fling_reg) do
			if not model.Parent or model == lp.Character then
				fling_unregister(model)
			else
				for p in pairs(entry.parts) do
					if p.Parent then
						if p.CanCollide then
							if fling_cache[p] == nil then fling_cache[p] = true end
							p.CanCollide = false
						end
					else
						entry.parts[p] = nil
						fling_cache[p] = nil
					end
				end
			end
		end
	end

	local function fling_guard(full)
		local hrp = get_hrp()
		if not hrp or not hrp.Parent then
			fling_safe_cf = nil
			return
		end
		if fling_busy() then
			fling_safe_cf = nil
			return
		end
		local lin = hrp.AssemblyLinearVelocity
		local ang = hrp.AssemblyAngularVelocity
		local spike = lin.Magnitude > FLING_MAX_VEL or ang.Magnitude > FLING_MAX_ANG
		local now = os.clock()
		if spike then fling_hold_until = now + FLING_HOLD end
		if spike or now < fling_hold_until then
			hrp.AssemblyLinearVelocity = Vector3.zero
			hrp.AssemblyAngularVelocity = Vector3.zero
			if full and fling_safe_cf then
				if (hrp.Position - fling_safe_cf.Position).Magnitude > FLING_SNAP_DIST then
					hrp.CFrame = fling_safe_cf
				end
			end
		elseif full and lin.Magnitude < FLING_SAFE_VEL then
			fling_safe_cf = hrp.CFrame
		end
	end

	local function fling_detach()
		fling_attached = false
		for i = 1, #fling_conns do
			pcall(function() fling_conns[i]:Disconnect() end)
		end
		table.clear(fling_conns)
	end

	local function fling_attach()
		if fling_attached then return end
		fling_attached = true
		local function push(c) fling_conns[#fling_conns + 1] = c end
		local function watch(pl)
			if pl == lp then return end
			push(pl.CharacterAdded:Connect(function(c)
				if anti_fling then fling_register(c) end
			end))
			push(pl.CharacterRemoving:Connect(function(c)
				fling_unregister(c)
			end))
		end
		for _, pl in players:GetPlayers() do watch(pl) end
		push(players.PlayerAdded:Connect(function(pl)
			watch(pl)
			if anti_fling and pl.Character then fling_register(pl.Character) end
		end))
		push(players.PlayerRemoving:Connect(function(pl)
			if pl.Character then fling_unregister(pl.Character) end
		end))
		push(ws.ChildAdded:Connect(function(m)
			if not anti_fling then return end
			task.defer(function()
				if anti_fling and m.Parent == ws and fling_is_body(m) then
					fling_register(m)
				end
			end)
		end))
		push(lp.CharacterAdded:Connect(function(c)
			fling_unregister(c)
			fling_safe_cf = nil
			fling_hold_until = 0
			if anti_fling then task.defer(fling_scan) end
		end))
		fling_scan()
	end

	local function fling_restore()
		fling_detach()
		for model in pairs(fling_reg) do
			fling_unregister(model)
		end
		table.clear(fling_reg)
		for p, v in pairs(fling_cache) do
			if p and p.Parent then pcall(function() p.CanCollide = v end) end
		end
		table.clear(fling_cache)
		fling_safe_cf = nil
		fling_hold_until = 0
	end

	local TRAP_LOCK = 1
	local TRAP_HOLD = 5
	local trap_window = 0
	local trap_busy = false
	local trap_speed_cache = 16
	local trap_jump_cache = 50
	local trap_hit_conn = nil

	local function trap_hum()
		local c = lp.Character
		return c and c:FindFirstChildOfClass("Humanoid")
	end

	local function trap_kill_gui()
		local gui = fade_gui()
		if not gui then return end
		for _, child in ipairs(gui:GetChildren()) do
			if child.Name == "TrapGUI" then
				pcall(function() child:Destroy() end)
			end
		end
	end

	local function trap_unlock(hum)
		if not hum or not hum.Parent then return end
		pcall(function()
			if hum.WalkSpeed <= TRAP_LOCK then hum.WalkSpeed = trap_speed_cache end
			if hum.JumpPower <= TRAP_LOCK then hum.JumpPower = trap_jump_cache end
		end)
	end

	local function trap_engage()
		if not anti_trap then return end
		trap_window = os.clock() + TRAP_HOLD
		local hum = trap_hum()
		if hum then
			if hum.WalkSpeed > TRAP_LOCK then trap_speed_cache = hum.WalkSpeed end
			if hum.JumpPower > TRAP_LOCK then trap_jump_cache = hum.JumpPower end
		end
		trap_kill_gui()
		if trap_busy then return end
		trap_busy = true
		task.spawn(function()
			while anti_trap and os.clock() < trap_window do
				trap_unlock(trap_hum())
				trap_kill_gui()
				run.Heartbeat:Wait()
			end
			trap_busy = false
		end)
	end

	local function trap_attach()
		if trap_hit_conn then return end
		local ok, remote = pcall(function()
			local sys = rs:FindFirstChild("TrapSystem")
			return sys and sys:FindFirstChild("TrapHitLocal")
		end)
		if not ok or not remote then return end
		trap_hit_conn = remote.OnClientEvent:Connect(function()
			task.spawn(trap_engage)
		end)
	end

	local function trap_detach()
		if trap_hit_conn then
			pcall(function() trap_hit_conn:Disconnect() end)
			trap_hit_conn = nil
		end
		trap_window = 0
		trap_unlock(trap_hum())
	end

	local function upd_anti()
		anti_afk = anti_master and afk_set
		local new_void = anti_master and void_set
		if new_void ~= anti_void then
			anti_void = new_void
			pcall(function()
				ws.FallenPartsDestroyHeight = anti_void and -9e9 or void_original
			end)
		end
		local new_fling = anti_master and fling_set
		if new_fling ~= anti_fling then
			anti_fling = new_fling
			if anti_fling then fling_attach() else fling_restore() end
		end
		local new_coin = anti_master and coin_set
		if new_coin ~= coin_on then
			coin_on = new_coin
			if coin_on then wipe_coins() else restore_coins() end
		end
		local new_fade = anti_master and fade_set
		if new_fade ~= fade_on then
			fade_on = new_fade
			if fade_on then fade_apply() else fade_restore() end
		end
		local new_trap = anti_master and trap_set
		if new_trap ~= anti_trap then
			anti_trap = new_trap
			if anti_trap then trap_attach() else trap_detach() end
		end
	end

	local idle_conn = lp.Idled:Connect(function()
		if anti_afk then
			pcall(function()
				vu:CaptureController()
				vu:ClickButton2(Vector2.new())
			end)
		end
	end)

	local coin_conn = cs:GetInstanceAddedSignal("CoinVisual"):Connect(function(v)
		if coin_on then
			task.wait()
			if coin_on then pcall(function() v:Destroy() end) end
		end
	end)

	local coin_desc_conn = ws.DescendantAdded:Connect(function(d)
		if coin_on and d.Name == "CoinContainer" then
			task.wait()
			if coin_on then kill_container(d) end
		end
	end)

	local function noclip_restore()
		for p, v in pairs(noclip_cache) do
			if p and p.Parent then p.CanCollide = v end
		end
		noclip_cache = {}
	end

	local part_index = setmetatable({}, { __mode = "k" })

	local function char_parts(char)
		local entry = part_index[char]
		if not entry then
			entry = { list = {}, valid = false }
			part_index[char] = entry
			local function dirty(d)
				if d:IsA("BasePart") then entry.valid = false end
			end
			entry.added = char.DescendantAdded:Connect(dirty)
			entry.removing = char.DescendantRemoving:Connect(dirty)
		end
		if not entry.valid then
			local list = entry.list
			table.clear(list)
			local n = 0
			for _, p in char:GetDescendants() do
				if p:IsA("BasePart") then
					n = n + 1
					list[n] = p
				end
			end
			entry.valid = true
		end
		return entry.list
	end

	local function release_part_index()
		for _, entry in pairs(part_index) do
			if entry.added then pcall(function() entry.added:Disconnect() end) end
			if entry.removing then pcall(function() entry.removing:Disconnect() end) end
		end
		part_index = setmetatable({}, { __mode = "k" })
	end

	local step_conn = run.Stepped:Connect(function()
		if anti_fling then
			if not fling_attached then pcall(fling_attach) end
			pcall(fling_sweep)
			pcall(fling_guard, true)
		end
		if noclip_on then
			if (getgenv().FLING_ACTIVE or 0) == 0 then
				local c = lp.Character
				if c then
					local list = char_parts(c)
					for i = 1, #list do
						local p = list[i]
						if p.Parent and p.CanCollide then
							if noclip_cache[p] == nil then noclip_cache[p] = p.CanCollide end
							p.CanCollide = false
						end
					end
				end
			elseif next(noclip_cache) then
				noclip_restore()
			end
		end
	end)

	local fling_beat_conn = run.Heartbeat:Connect(function()
		if anti_fling then
			pcall(fling_guard, false)
		end
	end)

	local controls_ref = nil
	local function get_controls()
		if controls_ref then return controls_ref end
		local ok, res = pcall(function()
			local ps = lp:FindFirstChild("PlayerScripts")
			local pm = ps and ps:FindFirstChild("PlayerModule")
			if not pm then return nil end
			return require(pm):GetControls()
		end)
		if ok and res then controls_ref = res end
		return controls_ref
	end

	local function flat_unit(v)
		local f = Vector3.new(v.X, 0, v.Z)
		if f.Magnitude > 0 then return f.Unit end
		return Vector3.zero
	end

	local function get_move_vector(cam)
		local c = get_controls()
		if c then
			local ok, v = pcall(function() return c:GetMoveVector() end)
			if ok and typeof(v) == "Vector3" and v.Magnitude > 0.05 then
				return v
			end
		end
		local ch = lp.Character
		local hum = ch and ch:FindFirstChildOfClass("Humanoid")
		if hum and cam then
			local md = hum.MoveDirection
			if md.Magnitude > 0.05 then
				local ff, fr = flat_unit(cam.CFrame.LookVector), flat_unit(cam.CFrame.RightVector)
				return Vector3.new(md:Dot(fr), 0, -md:Dot(ff))
			end
		end
		return Vector3.zero
	end

	local hop_params = RaycastParams.new()
	hop_params.FilterType = Enum.RaycastFilterType.Exclude
	hop_params.IgnoreWater = true
	local hop_ang = { 0, 0.45, -0.45, 0.9, -0.9, 1.4, -1.4, 2, -2, 2.6, -2.6, 3.14 }

	local function hop_wall(hrp, hum)
		local cam = ws.CurrentCamera
		local base = flat_unit(hum.MoveDirection)
		if base == Vector3.zero then
			base = cam and flat_unit(cam.CFrame.LookVector) or Vector3.zero
		end
		if base == Vector3.zero then return nil end
		hop_params.FilterDescendantsInstances = { lp.Character }
		local pos = hrp.Position
		for i = 1, #hop_ang do
			local c, s = math.cos(hop_ang[i]), math.sin(hop_ang[i])
			local dir = Vector3.new(base.X * c + base.Z * s, 0, base.Z * c - base.X * s) * 3
			local hit = ws:Raycast(pos, dir, hop_params)
			if not hit then
				hit = ws:Raycast(pos - Vector3.new(0, 2, 0), dir, hop_params)
			end
			if hit and math.abs(hit.Normal.Y) < 0.5 then return hit end
		end
		return nil
	end

	local jump_hold_t = 0
	local hop_scan_t = 0
	local jump_conn = uis.JumpRequest:Connect(function()
		jump_hold_t = os.clock()
		if fly_on or (not inf_jump_on and not wallhop_on) then return end
		local hrp = get_hrp()
		local ch = lp.Character
		local hum = ch and ch:FindFirstChildOfClass("Humanoid")
		if not hrp or not hum or hum.Health <= 0 then return end
		if inf_jump_on then
			hum:ChangeState(Enum.HumanoidStateType.Jumping)
			return
		end
		if hum.FloorMaterial ~= Enum.Material.Air then return end
		local now = os.clock()
		if now - hop_scan_t < 0.1 then return end
		hop_scan_t = now
		local wall = hop_wall(hrp, hum)
		if not wall then return end
		local n = flat_unit(wall.Normal)
		hum:ChangeState(Enum.HumanoidStateType.Jumping)
		local v = hrp.AssemblyLinearVelocity
		hrp.AssemblyLinearVelocity = Vector3.new(v.X + n.X * 3, v.Y, v.Z + n.Z * 3)
	end)

	local fly_conn = run.RenderStepped:Connect(function()
		if not fly_on then return end
		local h = get_hrp()
		if not h then return end
		local cam = ws.CurrentCamera
		local dir = Vector3.zero
		if uis:IsKeyDown(Enum.KeyCode.W) then dir = dir + cam.CFrame.LookVector end
		if uis:IsKeyDown(Enum.KeyCode.S) then dir = dir - cam.CFrame.LookVector end
		if uis:IsKeyDown(Enum.KeyCode.A) then dir = dir - cam.CFrame.RightVector end
		if uis:IsKeyDown(Enum.KeyCode.D) then dir = dir + cam.CFrame.RightVector end
		local mv = get_move_vector(cam)
		if mv.Magnitude > 0.05 then
			dir = dir + cam.CFrame.LookVector * (-mv.Z) + cam.CFrame.RightVector * mv.X
		end
		local jump_held = (os.clock() - jump_hold_t) < 0.2
		if fly_up_on and (uis:IsKeyDown(fly_up_kc) or jump_held) then dir = dir + Vector3.yAxis end
		if fly_down_on and uis:IsKeyDown(fly_down_kc) then dir = dir - Vector3.yAxis end
		if dir.Magnitude > 0 then dir = dir.Unit * fly_speed end
		h.AssemblyLinearVelocity = dir
	end)

	getgenv().MISC_UNLOAD = function()
		anti_master, anti_afk, anti_fling, anti_void = false, false, false, false
		coin_set, coin_on = false, false
		fade_set, fade_on = false, false
		trap_set, anti_trap = false, false
		pcall(function() ws.FallenPartsDestroyHeight = void_original end)
		noclip_on, fly_on = false, false
		inf_jump_on, wallhop_on = false, false
		if idle_conn then pcall(function() idle_conn:Disconnect() end) idle_conn = nil end
		if coin_conn then pcall(function() coin_conn:Disconnect() end) coin_conn = nil end
		if coin_desc_conn then pcall(function() coin_desc_conn:Disconnect() end) coin_desc_conn = nil end
		if fade_desc_conn then pcall(function() fade_desc_conn:Disconnect() end) fade_desc_conn = nil end
		if step_conn then pcall(function() step_conn:Disconnect() end) step_conn = nil end
		if fling_beat_conn then pcall(function() fling_beat_conn:Disconnect() end) fling_beat_conn = nil end
		if fly_conn then pcall(function() fly_conn:Disconnect() end) fly_conn = nil end
		if jump_conn then pcall(function() jump_conn:Disconnect() end) jump_conn = nil end
		trap_detach()
		restore_coins()
		fade_restore()
		noclip_restore()
		fling_restore()
		release_part_index()
		ws.Gravity = fly_gravity
	end
	getgenv().__PLR_QUEUE("char", "fly", function(target)
		local fly = target:AddToggle({
			Name = "fly",
			Default = false,
			Flag = "Fly",
			Option = true,
			Callback = function(v)
				fly_on = v
				if v then
					ws.Gravity = 0
				else
					ws.Gravity = fly_gravity
					local h = get_hrp()
					if h then h.AssemblyLinearVelocity = Vector3.zero end
				end
			end
		})

		fly.Option:AddSlider({
			Name = "speed",
			Default = 60,
			Min = 10,
			Max = 300,
			Round = 0,
			Flag = "misc_fly_speed",
			Callback = function(v)
				fly_speed = v
			end
		})

		fly.Option:AddToggle({
			Name = "up",
			Default = true,
			Flag = "FluUp",
			Callback = function(v)
				fly_up_on = v
			end
		})

		fly.Option:AddToggle({
			Name = "down",
			Default = true,
			Flag = "FlyDown",
			Callback = function(v)
				fly_down_on = v
			end
		})

		fly.Option:AddKeybind({
			Name = "up",
			Default = "Space",
			Flag = "misc_fly_up_key",
			Callback = function(k)
				local ok, kc = pcall(function() return Enum.KeyCode[k] end)
				if ok and kc then fly_up_kc = kc end
			end
		})

		fly.Option:AddKeybind({
			Name = "down",
			Default = "LeftControl",
			Flag = "misc_fly_down_key",
			Callback = function(k)
				local ok, kc = pcall(function() return Enum.KeyCode[k] end)
				if ok and kc then fly_down_kc = kc end
			end
		})
	end)

	getgenv().__PLR_QUEUE("misc", "anti", function(target)
		local anti = target:AddToggle({
			Name = "anti",
			Default = false,
			Flag = "Anti",
			Option = true,
			Callback = function(v)
				anti_master = v
				upd_anti()
			end
		})

		anti.Option:AddToggle({
			Name = "afk",
			Default = false,
			Flag = "Afk",
			Callback = function(v)
				afk_set = v
				upd_anti()
			end
		})

		anti.Option:AddToggle({
			Name = "fling",
			Default = false,
			Flag = "AFling",
			Callback = function(v)
				fling_set = v
				upd_anti()
			end
		})

		anti.Option:AddToggle({
			Name = "void kill",
			Default = false,
			Flag = "AVoid",
			Callback = function(v)
				void_set = v
				upd_anti()
			end
		})

		anti.Option:AddToggle({
			Name = "coin",
			ToolTip = "Removes coins from the map(anti kick)",
			Default = false,
			Flag = "ACoin",
			Callback = function(v)
				coin_set = v
				upd_anti()
			end
		})

		anti.Option:AddToggle({
			Name = "fade",
			ToolTip = "Removes the black screen fade on round end/spawn",
			Default = false,
			Flag = "AFade",
			Callback = function(v)
				fade_set = v
				upd_anti()
			end
		})

		anti.Option:AddToggle({
			Name = "trap",
			ToolTip = "Ignores murderer traps",
			Default = false,
			Flag = "ATrap",
			Callback = function(v)
				trap_set = v
				upd_anti()
			end
		})
	end)

	getgenv().__PLR_QUEUE("char", "noclip", function(target)
		target:AddToggle({
			Name = "noclip",
			Default = false,
			Flag = "Noclip",
			ToolTip = "Allows you to walk through walls",
			Callback = function(v)
				noclip_on = v
				if not v then noclip_restore() end
			end
		})
	end)

	getgenv().__PLR_QUEUE("misc", "wallhop", function(target)
		target:AddToggle({
			Name = "wallhop",
			Default = false,
			Flag = "Wallhop",
			ToolTip = "Jump again off any wall you are next to",
			Callback = function(v)
				wallhop_on = v
			end
		})
	end)

	

	local surf_on = false
	local surf_speed = 34
	local surf_active = false
	local surf_sign = 0
	local surf_seen = 0
	local surf_lock = nil
	local surf_part = nil
	local surf_conn = nil
	local surf_solid = nil
	local surf_params = RaycastParams.new()
	surf_params.FilterType = Enum.RaycastFilterType.Exclude
	surf_params.IgnoreWater = true

	local SURF_RANGE = 5
	local SURF_LEN = 11
	local SURF_DEPTH = 2.6
	local SURF_THICK = 1.6
	local SURF_UP = 2.9
	local SURF_DOWN = 2.4
	local SURF_ANG = { 0, 0.3, -0.3, 0.62, -0.62, 0.95, -0.95 }
	local SURF_OFF = { -0.35, -0.15, 0.06, 0.26, 0.5, 0.85, 1.25 }
	local SURF_DROP = Vector3.new(0, -(SURF_UP + SURF_DOWN + 0.2), 0)
	local SURF_GROUND = Vector3.new(0, -(SURF_DOWN + 4), 0)

	local surf_ind = CreateIndicator({
		Name = "SURF",
		Icon = "cube-vertexes",
		Color = "White",
	})

	local function surf_platform()
		if not surf_part then
			local p = Instance.new("Part")
			p.Name = "PixelStep"
			p.Anchored = true
			p.CanCollide = false
			p.CanQuery = false
			p.CanTouch = false
			p.Transparency = 1
			p.Material = Enum.Material.SmoothPlastic
			p.TopSurface = Enum.SurfaceType.Smooth
			p.BottomSurface = Enum.SurfaceType.Smooth
			p.CustomPhysicalProperties = PhysicalProperties.new(0.01, 0, 0, 100, 1)
			p.Size = Vector3.new(SURF_LEN, SURF_THICK, SURF_DEPTH)
			surf_part = p
		end
		if surf_part.Parent ~= ws then surf_part.Parent = ws end
		return surf_part
	end

	local function surf_hide()
		if surf_part then
			if surf_part.Parent then surf_part.Parent = nil end
			if surf_solid ~= false then
				surf_solid = false
				surf_part.CanCollide = false
			end
		end
		surf_sign = 0
		surf_lock = nil
		if surf_active then
			surf_active = false
			pcall(function() surf_ind:Set(false) end)
		end
	end

	local function surf_cast(origin, dir)
		surf_params.FilterDescendantsInstances = { lp.Character, surf_part }
		return ws:Raycast(origin, dir, surf_params)
	end

	local function surf_feet(hrp, hum)
		local hip = hum.HipHeight
		if hip > 0 then
			return hrp.Position.Y - hrp.Size.Y * 0.5 - hip
		end
		return hrp.Position.Y - 3
	end

	local function surf_yaw(v, a)
		local c, s = math.cos(a), math.sin(a)
		return Vector3.new(v.X * c + v.Z * s, 0, v.Z * c - v.X * s)
	end

	local function surf_probe(origin, feet, dir)
		local hit = surf_cast(origin, dir)
		if hit and math.abs(hit.Normal.Y) < 0.45 then return hit end
		hit = surf_cast(Vector3.new(origin.X, feet + 0.8, origin.Z), dir)
		if hit and math.abs(hit.Normal.Y) < 0.45 then return hit end
		return nil
	end

	local function surf_wall(hrp, feet, move, look)
		local pos = hrp.Position
		for pass = 1, 2 do
			local base = pass == 1 and move or look
			if base ~= Vector3.zero and (pass == 1 or move == Vector3.zero or move:Dot(look) < 0.99) then
				for i = 1, #SURF_ANG do
					local hit = surf_probe(pos, feet, surf_yaw(base, SURF_ANG[i]) * SURF_RANGE)
					if hit then return hit end
				end
			end
		end
		return nil
	end

	local function surf_scan(hrp, hum, move, look, hold)
		local feet = surf_feet(hrp, hum)
		local wall = surf_wall(hrp, feet, move, look)
		if not wall then return nil end
		local n = flat_unit(wall.Normal)
		if n == Vector3.zero then return nil end
		local ground = surf_cast(hrp.Position, SURF_GROUND)
		local gy = ground and ground.Position.Y or -1e9
		local face = wall.Position
		local best, top, tp
		for i = 1, #SURF_OFF do
			local o = face + n * SURF_OFF[i]
			local hit = surf_cast(Vector3.new(o.X, feet + SURF_UP, o.Z), SURF_DROP)
			if hit and hit.Normal.Y > 0.35 then
				local y = hit.Position.Y
				if y > gy + 0.75 and y < feet + SURF_UP - 0.25 and y > feet - SURF_DOWN then
					local score
					if hold then
						score = math.abs(y - hold)
					elseif y >= feet - 0.3 then
						score = y - feet
					else
						score = 1000 - y
					end
					if not best or score < best then
						best, top, tp = score, y, hit.Position
					end
				end
			end
		end
		if not top then return nil end
		return Vector3.new(tp.X, top, tp.Z), n, feet
	end

	local function surf_step(_, dt)
		if not surf_on then return end
		local char = lp.Character
		local hrp = char and char:FindFirstChild("HumanoidRootPart")
		local hum = char and char:FindFirstChildOfClass("Humanoid")
		if not hrp or not hum or hum.Health <= 0 then
			surf_hide()
			return
		end
		local cam = ws.CurrentCamera
		local move = flat_unit(hum.MoveDirection)
		local look = cam and flat_unit(cam.CFrame.LookVector) or Vector3.zero
		local pos, n, feet = surf_scan(hrp, hum, move, look, surf_active and surf_lock and surf_lock.Y or nil)
		if not pos then
			if os.clock() - surf_seen > 0.3 then surf_hide() end
			return
		end
		local tangent = flat_unit(n:Cross(Vector3.yAxis))
		if tangent == Vector3.zero then return end
		local hp = hrp.Position
		local dx, dz = pos.X - hp.X, pos.Z - hp.Z
		local dist = math.sqrt(dx * dx + dz * dz)
		local push = move ~= Vector3.zero and move:Dot(n) or 0
		if surf_active then
			if dist > 4.5 or push > 0.5 then
				surf_hide()
				return
			end
		elseif hum.FloorMaterial ~= Enum.Material.Air or dist > 2.8 or move == Vector3.zero or push > -0.15 then
			if os.clock() - surf_seen > 0.3 then surf_hide() end
			return
		end
		surf_seen = os.clock()
		local step = math.min(dt or 0.016, 0.1)
		if surf_lock and (surf_lock - pos).Magnitude < 2 then
			pos = surf_lock:Lerp(pos, 1 - math.exp(-16 * step))
		end
		surf_lock = pos
		local p = surf_platform()
		local center = pos + n * (SURF_DEPTH * 0.5 - 0.45) - Vector3.new(0, SURF_THICK * 0.5 + 0.02, 0)
		p.CFrame = CFrame.lookAt(center, center - n)
		local solid = surf_solid
		if feet >= pos.Y - 0.06 then
			solid = true
		elseif feet < pos.Y - 0.55 then
			solid = false
		end
		if surf_solid ~= solid then
			surf_solid = solid
			p.CanCollide = solid
		end
		if not surf_active then
			surf_active = true
			surf_sign = 0
			pcall(function() surf_ind:Set(true) end)
		end
		local along = move:Dot(tangent)
		if math.abs(along) > 0.35 then
			surf_sign = along > 0 and 1 or -1
		elseif surf_sign == 0 then
			surf_sign = (look:Dot(tangent) < 0) and -1 or 1
		end
		local v = hrp.AssemblyLinearVelocity
		local err = pos.Y - feet
		local vy
		if err > 0.05 then
			vy = math.min(err * 14 + 1.5, 34)
		elseif err < -0.4 then
			vy = math.max(v.Y, err * 8)
		elseif v.Y > 0 then
			vy = v.Y
		else
			vy = err * 8
		end
		local blend = 1 - math.exp(-14 * step)
		local cur = v.X * tangent.X + v.Z * tangent.Z
		local speed = cur + (surf_speed * surf_sign - cur) * blend
		local gap = (hp.X - pos.X) * n.X + (hp.Z - pos.Z) * n.Z
		local hug = math.clamp((0.75 - gap) * 9, -9, 9)
		local glide = tangent * speed + n * hug
		hrp.AssemblyLinearVelocity = Vector3.new(glide.X, vy, glide.Z)
	end

	surf_conn = run.Stepped:Connect(surf_step)

	getgenv().PIXEL_SURF_UNLOAD = function()
		surf_on = false
		if surf_conn then pcall(function() surf_conn:Disconnect() end) surf_conn = nil end
		surf_hide()
		if surf_part then
			pcall(function() surf_part:Destroy() end)
			surf_part = nil
		end
		pcall(function() surf_ind:Set(false) end)
	end

	getgenv().__PLR_QUEUE("misc", "pixel surf", function(target)
		local surf = target:AddToggle({
			Name = "pixel surf",
			ToolTip = "Catches pixel ledges and map seams, then slides along them like surf",
			Default = false,
			Flag = "PixelSurf",
			Option = true,
			Callback = function(v)
				surf_on = v
				if not v then surf_hide() end
			end
		})

		surf.Option:AddSlider({
			Name = "speed",
			Default = 34,
			Min = 8,
			Max = 90,
			Round = 0,
			Flag = "misc_surf_speed",
			Callback = function(v)
				surf_speed = v
			end
		})
	end)

	getgenv().__PLR_QUEUE("char", "infinite jump", function(target)
		target:AddToggle({
			Name = "infinite jump",
			Default = false,
			Flag = "InfiniteJump",
			ToolTip = "Lets you keep jumping while in the air",
			Callback = function(v)
				inf_jump_on = v
			end
		})
	end)

	getgenv().__PLAYER_MISC_SEC = sec
end

do
	local players = game:GetService("Players")
	local rs = game:GetService("ReplicatedStorage")
	local lp = players.LocalPlayer

	getgenv().__MISC_TOOLS_SEC = misc:AddSection({
		Name = "tools",
		Position = 'left'
	})

	getgenv().__MISC_ALERTS_SEC = misc:AddSection({
		Name = "alerts",
		Position = 'right'
	})

	local show_on = false
	local conns = {}
	local gen = 0
	local sync = nil

	local env = getgenv()
	env.__SV_STORE = env.__SV_STORE or { pages = {}, items = {}, fails = {}, busy = {} }
	local store = env.__SV_STORE
	local prefetch_gen = 0
	local id_index = nil

	local BASE = "https://r.jina.ai/https://supremevalues.com/mm2/"
	local PAGES = {
		"godlies", "chromas", "ancients", "uniques", "vintages",
		"legendaries", "rares", "uncommons", "commons", "pets", "misc"
	}
	local RARITY_PAGE = {
		Common = "commons",
		Uncommon = "uncommons",
		Rare = "rares",
		Legendary = "legendaries",
		Godly = "godlies",
		Ancient = "ancients",
		Unique = "uniques",
		Classic = "vintages",
		Vintage = "vintages",
		Christmas = "misc",
		Halloween = "misc",
	}
	local SKIP = {
		"^Class %-", "^Range", "^Stability", "^Demand", "^Rarity", "^Change in Value",
		"^Inv%.", "^Value", "^Tier", "^Filter", "^Sort", "^Title:", "^URL Source",
		"^Published Time", "^Markdown Content", "^%*", "^!%[", "^%[", "^%-", "^Supreme",
		"^Trade your", "^The Supreme", "^Chance of"
	}

	local LOW = "<1"

	local function norm(s)
		return (string.gsub(string.lower(tostring(s)), "[^%w]", ""))
	end

	local function comma(n)
		local s = tostring(math.floor(n + 0.5))
		while true do
			local r
			s, r = string.gsub(s, "^(-?%d+)(%d%d%d)", "%1,%2")
			if r == 0 then break end
		end
		return s
	end

	local function skip_line(t)
		for _, p in ipairs(SKIP) do
			if string.match(t, p) then return true end
		end
		return string.find(t, "%]%(") ~= nil or #t > 44
	end

	local function parse_page(txt, slug)
		local out = {}
		local last = nil
		for line in string.gmatch(txt .. "\n", "([^\n]*)\n") do
			local t = string.match(line, "^%s*(.-)%s*$")
			if t ~= "" then
				local raw = string.match(t, "^Value %- %*%*(.-)%*%*")
				if raw then
					if last then
						local clean = string.gsub(raw, "[,%s]", "")
						local num = tonumber(clean)
						if not num and string.match(clean, "^x%d+T%d") then num = LOW end
						local key = norm(last)
						if num and key ~= "" then
							if out[key] == nil then out[key] = num end
							if slug == "chromas" then
								local cut = string.match(key, "^chroma(.+)") or string.match(key, "^c(.+)")
								if cut and cut ~= "" and out[cut] == nil then out[cut] = num end
							end
						end
					end
					last = nil
				elseif not skip_line(t) then
					last = t
				end
			end
		end
		return out
	end

	local function valid_body(s)
		if type(s) ~= "string" or #s < 512 then return false end
		if not string.find(s, "Markdown Content", 1, true) then return false end
		return true
	end

	local function http_get(url)
		local ok, res = pcall(function() return game:HttpGet(url, true) end)
		if ok and valid_body(res) then return res end
		local req = rawget(getfenv(), "request")
			or rawget(getfenv(), "http_request")
			or (syn and syn.request)
			or (http and http.request)
			or (fluxus and fluxus.request)
			or env.request
		if type(req) == "function" then
			local ok2, res2 = pcall(req, {
				Url = url,
				Method = "GET",
				Headers = { ["Accept"] = "text/plain", ["User-Agent"] = "Mozilla/5.0" }
			})
			if ok2 and type(res2) == "table" and valid_body(res2.Body) then return res2.Body end
		end
		return nil
	end

	local BACKOFF = { 2, 4, 6, 9 }
	local FAIL_COOLDOWN = 6

	local function get_page(slug)
		local cached = store.pages[slug]
		if cached then return cached end
		local waited = 0
		while store.busy[slug] do
			task.wait(0.2)
			waited = waited + 0.2
			if store.pages[slug] then return store.pages[slug] end
			if waited > 90 then
				store.busy[slug] = nil
				break
			end
		end
		if store.pages[slug] then return store.pages[slug] end
		local fail = store.fails[slug]
		if fail and os.clock() - fail < FAIL_COOLDOWN then return nil end
		store.busy[slug] = true
		local built = nil
		for attempt = 1, #BACKOFF + 1 do
			local txt = http_get(BASE .. slug)
			if txt then
				local ok, idx = pcall(parse_page, txt, slug)
				if ok and type(idx) == "table" and next(idx) ~= nil then
					built = idx
					break
				end
			end
			local nap = BACKOFF[attempt]
			if nap then task.wait(nap) end
		end
		store.busy[slug] = nil
		if built then
			store.pages[slug] = built
			store.fails[slug] = nil
			return built
		end
		store.fails[slug] = os.clock()
		return nil
	end

	local function item_keys(data)
		local base = norm(data.ItemName or data.Name or "")
		local keys, strict = {}, {}
		if base == "" then return keys, strict end
		local ty = data.ItemType and norm(tostring(data.ItemType)) or nil
		local yr = data.Year and norm(tostring(data.Year)) or nil
		local evo = data.EvoIndex and ("var" .. norm(tostring(data.EvoIndex))) or nil

		local seen = {}
		local function push(k, tight)
			if k == "" or seen[k] then return end
			seen[k] = true
			keys[#keys + 1] = k
			if tight then strict[#strict + 1] = k end
		end

		if evo then push(base .. evo, true) end
		if ty and yr then push(base .. ty .. yr, true) end
		if ty then push(base .. ty, true) end
		if yr then push(base .. yr, true) end
		push(base, false)
		return keys, strict
	end

	local function page_list(data, dtype)
		if dtype == "Pets" then return { "pets" } end
		if data.Chroma then return { "chromas" } end
		local p = RARITY_PAGE[data.Rarity or ""]
		if p then return { p } end
		return { "misc" }
	end

	local function match_index(idx, keys)
		for _, k in ipairs(keys) do
			local v = idx[k]
			if v ~= nil then return v end
		end
		return nil
	end

	local function resolve(dtype, id, data)
		local ck = tostring(dtype) .. "|" .. tostring(id) .. (data.Chroma and "|c" or "")
		local hit = store.items[ck]
		if hit ~= nil then return hit, true end

		local keys, strict = item_keys(data)
		if #keys == 0 then return false, true end

		local primary = page_list(data, dtype)
		local incomplete = false

		for _, slug in ipairs(primary) do
			local idx = get_page(slug)
			if idx then
				local v = match_index(idx, keys)
				if v ~= nil then
					store.items[ck] = v
					return v, true
				end
			else
				incomplete = true
			end
		end

		if #strict > 0 then
			for _, slug in ipairs(PAGES) do
				local skip = false
				for _, x in ipairs(primary) do
					if x == slug then skip = true break end
				end
				if not skip then
					local idx = store.pages[slug]
					if idx then
						local v = match_index(idx, strict)
						if v ~= nil then
							store.items[ck] = v
							return v, true
						end
					elseif not store.fails[slug] then
						incomplete = true
					end
				end
			end
		end

		if incomplete then return nil, false end
		store.items[ck] = false
		return false, true
	end

	local function prefetch()
		prefetch_gen = prefetch_gen + 1
		local my = prefetch_gen
		store.fails = {}
		task.spawn(function()
			for sweep = 1, 4 do
				local left = 0
				for _, slug in ipairs(PAGES) do
					if my ~= prefetch_gen or not show_on then return end
					if not store.pages[slug] then
						get_page(slug)
						if not store.pages[slug] then left = left + 1 end
						task.wait(0.4)
					end
				end
				if left == 0 then return end
				if my ~= prefetch_gen or not show_on then return end
				task.wait(sweep * 4)
			end
		end)
	end

	local function trade_root()
		local pg = lp:FindFirstChildOfClass("PlayerGui")
		local gui = pg and pg:FindFirstChild("TradeGUI")
		local cont = gui and gui:FindFirstChild("Container")
		return cont and cont:FindFirstChild("Trade"), gui
	end

	local function make_label(parent, name, size, pos, anchor, maxtext, align)
		local l = parent:FindFirstChild(name)
		if l then
			l.AnchorPoint = anchor
			l.Position = pos
			l.Size = size
			l.TextXAlignment = align
			local c = l:FindFirstChildOfClass("UITextSizeConstraint")
			if c then c.MaxTextSize = maxtext end
			return l
		end
		l = Instance.new("TextLabel")
		l.Name = name
		l.AnchorPoint = anchor
		l.Position = pos
		l.Size = size
		l.BackgroundTransparency = 1
		l.BorderSizePixel = 0
		l.Font = Enum.Font.GothamBold
		l.TextColor3 = Color3.fromRGB(255, 216, 110)
		l.TextStrokeColor3 = Color3.fromRGB(0, 0, 0)
		l.TextStrokeTransparency = 0.15
		l.TextXAlignment = align
		l.TextScaled = true
		l.RichText = false
		l.ZIndex = 40
		l.Text = ""
		local con = Instance.new("UITextSizeConstraint")
		con.MaxTextSize = maxtext
		con.MinTextSize = 7
		con.Parent = l
		l.Parent = parent
		return l
	end

	local function total_label(offer)
		local l = make_label(offer, "SV_Total",
			UDim2.new(0.4, 0, 0, 22), UDim2.new(0.025, 0, 1, -137),
			Vector2.new(0, 1), 22, Enum.TextXAlignment.Left)

		local width = offer.AbsoluteSize.X
		local left = width * 0.025
		local title = offer:FindFirstChild("Title")
		if title and title.TextBounds.X > 4 then
			left = (title.AbsolutePosition.X - offer.AbsolutePosition.X) + title.TextBounds.X + 10
		end
		local limit = width - left - 8
		local user = offer:FindFirstChild("Username")
		if user and user.TextBounds.X > 4 then
			local edge = (user.AbsolutePosition.X - offer.AbsolutePosition.X) + user.AbsoluteSize.X - user.TextBounds.X
			limit = math.min(limit, edge - left - 8)
		end
		l.Position = UDim2.new(0, math.floor(left), 1, -137)
		l.Size = UDim2.new(0, math.max(60, math.floor(limit)), 0, 22)
		return l
	end

	local function card_label(card)
		local l = make_label(card, "SV_Value",
			UDim2.new(0.7, 0, 0.16, 0), UDim2.new(1, -6, 0, 4),
			Vector2.new(1, 0), 18, Enum.TextXAlignment.Right)

		local inner = card:FindFirstChild("Container")
		local amt = inner and inner:FindFirstChild("Amount")
		local stacked = amt and amt.Visible and string.match(amt.Text or "", "x%s*%d") ~= nil
		l.Position = UDim2.new(1, -6, 0, stacked and 32 or 4)
		return l
	end

	local function clear_side(offer)
		if not offer then return end
		local l = offer:FindFirstChild("SV_Total")
		if l then l.Visible = false end
		local cont = offer:FindFirstChild("Container")
		if not cont then return end
		for _, ch in ipairs(cont:GetChildren()) do
			local v = ch:FindFirstChild("SV_Value")
			if v then v.Visible = false end
		end
	end

	local function wipe_labels()
		local root = trade_root()
		if not root then return end
		for _, side in ipairs({ "YourOffer", "TheirOffer" }) do
			local offer = root:FindFirstChild(side)
			if offer then
				local l = offer:FindFirstChild("SV_Total")
				if l then l:Destroy() end
				local cont = offer:FindFirstChild("Container")
				if cont then
					for _, ch in ipairs(cont:GetChildren()) do
						local v = ch:FindFirstChild("SV_Value")
						if v then v:Destroy() end
					end
				end
			end
		end
	end

	local function ensure_sync()
		if sync then return sync end
		local ok, mod = pcall(function()
			return require(rs:WaitForChild("Database"):WaitForChild("Sync"))
		end)
		if ok and type(mod) == "table" then sync = mod end
		return sync
	end

	local function build_index()
		if id_index then return id_index end
		if not ensure_sync() then return nil end
		local byid, byname = {}, {}
		local function add(map, key, rec)
			if not key or key == "" then return end
			local bucket = map[key]
			if bucket then
				bucket[#bucket + 1] = rec
			else
				map[key] = { rec }
			end
		end
		for _, dtype in ipairs({ "Weapons", "Pets" }) do
			local db = sync[dtype]
			if type(db) == "table" then
				for id, d in pairs(db) do
					if type(d) == "table" then
						local rec = { dtype = dtype, id = id, data = d }
						if d.ItemID then add(byid, tostring(d.ItemID), rec) end
						if type(d.Image) == "string" then
							local dig = string.match(d.Image, "assetId=(%d+)")
								or string.match(d.Image, "id=(%d+)")
								or string.match(d.Image, "rbxassetid://(%d+)")
							if dig then add(byid, dig, rec) end
						end
						add(byname, tostring(d.ItemName or d.Name or ""), rec)
					end
				end
			end
		end
		id_index = { byid = byid, byname = byname }
		return id_index
	end

	local function icon_id(card)
		local inner = card:FindFirstChild("Container")
		local icon = inner and inner:FindFirstChild("Icon")
		local img = icon and icon.Image or ""
		if img == "" then return nil end
		return string.match(img, "assetId=(%d+)")
			or string.match(img, "id=(%d+)")
			or string.match(img, "rbxassetid://(%d+)")
	end

	local function card_entry(card, text, chroma)
		local ix = build_index()
		if not ix then return nil end
		local iid = icon_id(card)
		local pool = iid and ix.byid[iid] or nil
		if not pool then pool = ix.byname[text] end
		if not pool then return nil end

		local fallback = nil
		for _, rec in ipairs(pool) do
			local d = rec.data
			if (d.Chroma == true) == chroma then
				if tostring(d.ItemName or d.Name or "") == text then return rec.dtype, rec.id, d end
				if not fallback then fallback = rec end
			end
		end
		if fallback then return fallback.dtype, fallback.id, fallback.data end
		if iid and ix.byid[iid] == pool then
			local rec = pool[1]
			return rec.dtype, rec.id, rec.data
		end
		return nil
	end

	local function gui_items(offer)
		local out = {}
		local cont = offer and offer:FindFirstChild("Container")
		if not cont then return out end
		local i = 1
		while true do
			local card = cont:FindFirstChild("NewItem" .. i)
			if not card or not card.Visible then break end
			local nm = card:FindFirstChild("ItemName")
			local lbl = nm and nm:FindFirstChild("Label")
			local text = lbl and lbl.Text or ""
			if text == "" then break end
			local tags = card:FindFirstChild("Tags")
			local ch = tags and tags:FindFirstChild("Chroma")
			local inner = card:FindFirstChild("Container")
			local amt_l = inner and inner:FindFirstChild("Amount")
			local amt = amt_l and tonumber(string.match(amt_l.Text or "", "x%s*(%d+)")) or 1
			local chroma = ch ~= nil and ch.Visible == true
			local dtype, id, data = card_entry(card, text, chroma)
			out[i] = {
				id = id or norm(text),
				amount = amt,
				dtype = dtype or "Weapons",
				data = data or { ItemName = text, Chroma = chroma }
			}
			i = i + 1
		end
		return out
	end

	local function collect(offer_data)
		local out = {}
		if type(offer_data) ~= "table" then return out end
		ensure_sync()
		for i, v in ipairs(offer_data) do
			local id = v[1] or v.ItemID
			local amount = v[2] or v.Amount or 1
			local dtype = v[3] or v.ItemType
			local db = sync and dtype and sync[dtype]
			local data = db and db[id]
			out[i] = { id = id, amount = amount, dtype = dtype, data = data }
		end
		return out
	end

	local function render(offer, items, my_gen)
		if not offer then return end
		local cont = offer:FindFirstChild("Container")
		if not cont then return end
		clear_side(offer)
		local total = total_label(offer)
		if #items == 0 then
			total.Visible = false
			return
		end
		total.Visible = true
		total.Text = "..."
		for i in ipairs(items) do
			local card = cont:FindFirstChild("NewItem" .. i)
			if card then
				local l = card_label(card)
				l.Visible = true
				l.Text = "..."
			end
		end
		task.spawn(function()
			local done = {}
			local deadline = os.clock() + 150
			while true do
				local pending = false
				local sum = 0
				for i, it in ipairs(items) do
					if my_gen ~= gen or not show_on then return end
					if done[i] == nil then
						if it.data then
							local val, settled = resolve(it.dtype, it.id, it.data)
							if settled then done[i] = { v = val } else pending = true end
						else
							done[i] = { v = false }
						end
					end
					if my_gen ~= gen or not show_on then return end
					local card = cont:FindFirstChild("NewItem" .. i)
					local l = card and card:FindFirstChild("SV_Value")
					local rec = done[i]
					if rec then
						local val = rec.v
						local amt = tonumber(it.amount) or 1
						if type(val) == "number" then
							sum = sum + val * amt
							if l then l.Text = comma(val) end
						elseif val == LOW then
							if l then l.Text = LOW end
						elseif l then
							l.Text = "?"
						end
					elseif l then
						l.Text = "..."
					end
				end
				if total.Parent then
					total.Text = pending and (comma(sum) .. " ...") or comma(sum)
				end
				if not pending then return end
				if os.clock() > deadline then
					for i in ipairs(items) do
						if done[i] == nil then
							local card = cont:FindFirstChild("NewItem" .. i)
							local l = card and card:FindFirstChild("SV_Value")
							if l then l.Text = "?" end
						end
					end
					if total.Parent then total.Text = comma(sum) end
					return
				end
				task.wait(2)
			end
		end)
	end

	local function update(data)
		if not show_on or type(data) ~= "table" then return end
		local mine, theirs
		if data.Player1 and data.Player1.Player == lp then
			mine, theirs = data.Player1.Offer, data.Player2 and data.Player2.Offer
		elseif data.Player2 and data.Player2.Player == lp then
			mine, theirs = data.Player2.Offer, data.Player1 and data.Player1.Offer
		else
			return
		end
		gen = gen + 1
		local my_gen = gen
		local my_items, their_items = collect(mine), collect(theirs)
		task.delay(0.05, function()
			if my_gen ~= gen or not show_on then return end
			local root = trade_root()
			if not root then return end
			render(root:FindFirstChild("YourOffer"), my_items, my_gen)
			render(root:FindFirstChild("TheirOffer"), their_items, my_gen)
		end)
	end

	local function refresh_gui()
		if not show_on then return end
		local root, gui = trade_root()
		if not root or not gui or not gui.Enabled then return end
		gen = gen + 1
		local my_gen = gen
		local mine = root:FindFirstChild("YourOffer")
		local theirs = root:FindFirstChild("TheirOffer")
		render(mine, gui_items(mine), my_gen)
		render(theirs, gui_items(theirs), my_gen)
	end

	local function hook()
		local trade = rs:FindFirstChild("Trade")
		if not trade then return end
		local upd = trade:FindFirstChild("UpdateTrade")
		local start = trade:FindFirstChild("StartTrade")
		if upd then
			conns[#conns + 1] = upd.OnClientEvent:Connect(update)
		end
		if start then
			conns[#conns + 1] = start.OnClientEvent:Connect(function(data)
				update(data)
			end)
		end
		local _, gui = trade_root()
		if gui then
			conns[#conns + 1] = gui:GetPropertyChangedSignal("Enabled"):Connect(function()
				if not gui.Enabled then
					gen = gen + 1
					local root = trade_root()
					if root then
						clear_side(root:FindFirstChild("YourOffer"))
						clear_side(root:FindFirstChild("TheirOffer"))
					end
				end
			end)
		end
	end

	local function unhook()
		for _, c in ipairs(conns) do
			pcall(function() c:Disconnect() end)
		end
		conns = {}
	end

	getgenv().__PLR_QUEUE("tools", "show values", function(target)
		target:AddToggle({
			Name = "show values",
			Default = false,
			Flag = "ShowValues",
			Callback = function(v)
				show_on = v
				gen = gen + 1
				if v then
					unhook()
					hook()
					prefetch()
					refresh_gui()
				else
					prefetch_gen = prefetch_gen + 1
					unhook()
					wipe_labels()
				end
			end
		})
	end)

	getgenv().SHOWVALUES_UNLOAD = function()
		show_on = false
		gen = gen + 1
		prefetch_gen = prefetch_gen + 1
		unhook()
		wipe_labels()
	end

end

do
	local players = game:GetService("Players")
	local run = game:GetService("RunService")
	local ws = workspace
	local lp = players.LocalPlayer

	local uis = game:GetService("UserInputService")

	local ws_on, ws_value = false, 40
	local jp_on, jp_value = false, 80
	local boost_on, boost_value = false, 40
	local boost_strafe_on = false
	local boost_auto_strafe_on = false
	local ratio_on, ratio_value = false, 100

	local ws_original, jp_original, use_jp_original = nil, nil, nil
	local ratio_multiplier = CFrame.new(0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1)
	local was_jumping = false
	local is_boosting = false
	local bhop_speed = 0
	local jump_held_at = 0

	uis.JumpRequest:Connect(function()
		jump_held_at = os.clock()
	end)

	local function jump_is_held()
		if os.clock() - jump_held_at < 0.2 then return true end
		if uis:IsKeyDown(Enum.KeyCode.Space) then return true end
		return false
	end

	local last_cam_yaw = nil

	local function cam_yaw()
		local cam = ws.CurrentCamera
		if not cam then return nil end
		local look = cam.CFrame.LookVector
		return math.atan2(-look.X, -look.Z)
	end

	local function get_hum()
		local c = lp.Character
		return c and c:FindFirstChildOfClass("Humanoid")
	end

	local function get_hrp()
		local c = lp.Character
		return c and c:FindFirstChild("HumanoidRootPart")
	end

	local apply_conn = run.Stepped:Connect(function()
		local hum = get_hum()
		if not hum then return end
		if ws_on and hum.WalkSpeed ~= ws_value then
			hum.WalkSpeed = ws_value
		end
		if jp_on then
			if not hum.UseJumpPower then hum.UseJumpPower = true end
			if hum.JumpPower ~= jp_value then hum.JumpPower = jp_value end
		end
	end)

	local boost_conn = run.Heartbeat:Connect(function()
		if not boost_on then
			was_jumping = false
			is_boosting = false
			bhop_speed = 0
			last_cam_yaw = nil
			return
		end
		local hum = get_hum()
		local hrp = get_hrp()
		if not hum or not hrp then
			was_jumping = false
			is_boosting = false
			bhop_speed = 0
			last_cam_yaw = nil
			return
		end
		local state = hum:GetState()
		local jumping = state == Enum.HumanoidStateType.Jumping
		local freefall = state == Enum.HumanoidStateType.Freefall
		local airborne = jumping or freefall

		if boost_strafe_on or boost_auto_strafe_on then
			bhop_speed = 0

			if jumping and not was_jumping then
				local dir = hum.MoveDirection
				if dir.Magnitude < 0.1 then dir = hrp.CFrame.LookVector end
				dir = Vector3.new(dir.X, 0, dir.Z)
				if dir.Magnitude > 0 then
					dir = dir.Unit
					local v = hrp.AssemblyLinearVelocity
					hrp.AssemblyLinearVelocity = Vector3.new(dir.X * boost_value, v.Y, dir.Z * boost_value)
					is_boosting = true
				end
			end

			if is_boosting and airborne then
				if boost_auto_strafe_on then
					local yaw = cam_yaw()
					if yaw and last_cam_yaw then
						local delta = yaw - last_cam_yaw
						while delta > math.pi do delta = delta - math.pi * 2 end
						while delta < -math.pi do delta = delta + math.pi * 2 end
						if math.abs(delta) > 0.0005 then
							local v = hrp.AssemblyLinearVelocity
							local xz = Vector3.new(v.X, 0, v.Z)
							if xz.Magnitude > 1 then
								local rotated = CFrame.fromEulerAnglesYXZ(0, delta, 0) * xz
								hrp.AssemblyLinearVelocity = Vector3.new(rotated.X, v.Y, rotated.Z)
							end
						end
					end
				end

				local dir = hum.MoveDirection
				if dir.Magnitude > 0.1 then
					dir = Vector3.new(dir.X, 0, dir.Z).Unit
					local v = hrp.AssemblyLinearVelocity
					local current_xz = Vector3.new(v.X, 0, v.Z)
					local target = dir * boost_value
					local new_xz = current_xz:Lerp(target, 0.3)
					hrp.AssemblyLinearVelocity = Vector3.new(new_xz.X, v.Y, new_xz.Z)
				elseif boost_auto_strafe_on then
					local v = hrp.AssemblyLinearVelocity
					local xz = Vector3.new(v.X, 0, v.Z)
					if xz.Magnitude > 0.1 and xz.Magnitude < boost_value then
						local keep = xz.Unit * boost_value
						hrp.AssemblyLinearVelocity = Vector3.new(keep.X, v.Y, keep.Z)
					end
				end
			end

			if not airborne then
				is_boosting = false
			end
		else
			local base = math.max(hum.WalkSpeed, 1)
			local cap = math.max(boost_value, base)
			local step = math.max(boost_value * 0.1, 1)
			if bhop_speed < base then bhop_speed = base end

			if jumping and not was_jumping then
				bhop_speed = math.min(bhop_speed + step, cap)
				local v = hrp.AssemblyLinearVelocity
				local xz = Vector3.new(v.X, 0, v.Z)
				local dir
				if xz.Magnitude > 0.1 then
					dir = xz.Unit
				else
					local md = hum.MoveDirection
					if md.Magnitude > 0.1 then
						dir = Vector3.new(md.X, 0, md.Z).Unit
					else
						local lv = hrp.CFrame.LookVector
						dir = Vector3.new(lv.X, 0, lv.Z)
						dir = (dir.Magnitude > 0) and dir.Unit or Vector3.new(0, 0, 0)
					end
				end
				if dir.Magnitude > 0 then
					hrp.AssemblyLinearVelocity = Vector3.new(dir.X * bhop_speed, v.Y, dir.Z * bhop_speed)
					is_boosting = true
				end
			end

			if airborne and is_boosting then
				local v = hrp.AssemblyLinearVelocity
				local xz = Vector3.new(v.X, 0, v.Z)
				local md = hum.MoveDirection
				local dir
				if md.Magnitude > 0.1 then
					dir = Vector3.new(md.X, 0, md.Z).Unit
				elseif xz.Magnitude > 0.1 then
					dir = xz.Unit
				end
				if dir then
					local speed = math.max(xz.Magnitude, bhop_speed)
					hrp.AssemblyLinearVelocity = Vector3.new(dir.X * speed, v.Y, dir.Z * speed)
				end
			end

			if not airborne then
				is_boosting = false
				if jump_is_held() then
					hum.Jump = true
				else
					bhop_speed = 0
				end
			end
		end

		last_cam_yaw = cam_yaw()
		was_jumping = jumping
	end)

	run:BindToRenderStep("shitaro_aspect", Enum.RenderPriority.Camera.Value + 1, function()
		if not ratio_on then return end
		local cam = ws.CurrentCamera
		if cam then
			cam.CFrame = cam.CFrame * ratio_multiplier
		end
	end)

	getgenv().__PLR_QUEUE("char", "walkspeed", function(target)
		local walkspeed = target:AddToggle({
			Name = "walkspeed",
			Default = false,
			Flag = "WalkSpeed",
			Option = true,
			Callback = function(v)
				local hum = get_hum()
				if v then
					if hum then ws_original = hum.WalkSpeed end
					ws_on = true
				else
					ws_on = false
					if hum and ws_original then hum.WalkSpeed = ws_original end
				end
			end
		})

		walkspeed.Option:AddSlider({
			Name = "Value",
			Default = 40,
			Min = 16,
			Max = 300,
			Round = 0,
			Flag = "char_walkspeed_value",
			Callback = function(v)
				ws_value = v
			end
		})
	end)

	getgenv().__PLR_QUEUE("char", "jumppower", function(target)
		local jumppower = target:AddToggle({
			Name = "jumppower",
			Default = false,
			Flag = "JumpPower",
			Option = true,
			Callback = function(v)
				local hum = get_hum()
				if v then
					if hum then
						use_jp_original = hum.UseJumpPower
						jp_original = hum.JumpPower
					end
					jp_on = true
				else
					jp_on = false
					if hum then
						if use_jp_original ~= nil then hum.UseJumpPower = use_jp_original end
						if jp_original then hum.JumpPower = jp_original end
					end
				end
			end
		})

		jumppower.Option:AddSlider({
			Name = "Value",
			Default = 80,
			Min = 0,
			Max = 500,
			Round = 0,
			Flag = "char_jumppower_value",
			Callback = function(v)
				jp_value = v
			end
		})
	end)

	getgenv().__PLR_QUEUE("misc", "bhop", function(target)
		local bhop = target:AddToggle({
			Name = "bhop",
			Default = false,
			Flag = "Bhop",
			Option = true,
			Callback = function(v)
				boost_on = v
			end
		})

		bhop.Option:AddSlider({
			Name = "Power",
			Default = 40,
			Min = 10,
			Max = 150,
			Round = 0,
			Flag = "char_bhop_power",
			Callback = function(v)
				boost_value = v
			end
		})

		bhop.Option:AddToggle({
			Name = "Strafe",
			Default = false,
			Flag = "BhopStrafe",
			Callback = function(v)
				boost_strafe_on = v
			end
		})

		bhop.Option:AddToggle({
			Name = "Auto Strafe",
			Default = false,
			Flag = "BhopAutoStrafe",
			Callback = function(v)
				boost_auto_strafe_on = v
			end
		})
	end)

	getgenv().__PLR_QUEUE("misc", "aspect ratio", function(target)
		local aspect = target:AddToggle({
			Name = "aspect ratio",
			Default = false,
			Flag = "Aspect Ratio",
			Option = true,
			Callback = function(v)
				ratio_on = v
			end
		})

		aspect.Option:AddSlider({
			Name = "Value",
			Default = 100,
			Min = 1,
			Max = 100,
			Round = 0,
			Flag = "char_aspect_value",
			Callback = function(v)
				ratio_value = v
				ratio_multiplier = CFrame.new(0, 0, 0, 1, 0, 0, 0, v / 100, 0, 0, 0, 1)
			end
		})
	end)

	local fov_on, fov_value = false, 70
	local fov_original = nil
	local fov_conn = nil

	getgenv().__PLR_QUEUE("misc", "custom fov", function(target)
		local customfov = target:AddToggle({
			Name = "custom fov",
			Default = false,
			Flag = "Custom Fov",
			Option = true,
			Callback = function(v)
				fov_on = v
				local cam = ws.CurrentCamera
				if v then
					if cam then
						fov_original = cam.FieldOfView
						cam.FieldOfView = fov_value
					end
					if not fov_conn then
						fov_conn = run.RenderStepped:Connect(function()
							if fov_on then
								local camera = ws.CurrentCamera
								if camera and camera.FieldOfView ~= fov_value then
									camera.FieldOfView = fov_value
								end
							end
						end)
					end
				else
					if cam and fov_original then
						cam.FieldOfView = fov_original
					end
					if fov_conn then
						pcall(function() fov_conn:Disconnect() end)
						fov_conn = nil
					end
				end
			end
		})

		customfov.Option:AddSlider({
			Name = "Value",
			Default = 70,
			Min = 30,
			Max = 120,
			Round = 0,
			Flag = "char_fov_value",
			Callback = function(v)
				fov_value = v
				if fov_on then
					local cam = ws.CurrentCamera
					if cam then
						cam.FieldOfView = v
					end
				end
			end
		})
	end)

	lp.CharacterAdded:Connect(function()
		task.wait(0.1)
		if fov_on then
			local cam = ws.CurrentCamera
			if cam then
				if not fov_original then fov_original = cam.FieldOfView end
				cam.FieldOfView = fov_value
			end
		end
	end)

	getgenv().CHARACTER_UNLOAD = function()
		ws_on, jp_on, boost_on, ratio_on, fov_on = false, false, false, false, false
		if apply_conn then pcall(function() apply_conn:Disconnect() end) apply_conn = nil end
		if boost_conn then pcall(function() boost_conn:Disconnect() end) boost_conn = nil end
		if fov_conn then pcall(function() fov_conn:Disconnect() end) fov_conn = nil end
		pcall(function() run:UnbindFromRenderStep("shitaro_aspect") end)
		local hum = get_hum()
		if hum then
			if ws_original then pcall(function() hum.WalkSpeed = ws_original end) end
			if use_jp_original ~= nil then pcall(function() hum.UseJumpPower = use_jp_original end) end
			if jp_original then pcall(function() hum.JumpPower = jp_original end) end
		end
		local cam = ws.CurrentCamera
		if cam and fov_original then
			pcall(function() cam.FieldOfView = fov_original end)
		end
	end
end

do
	local players = game:GetService("Players")
	local lp = players.LocalPlayer

	local korblox_on, headless_on = false, false
	local korblox_backup = {}
	local head_backup = {}
	local char_conn = nil

	local function restore_korblox()
		local c = lp.Character
		if not c then return end
		
		local ru = c:FindFirstChild("RightUpperLeg")
		local rl = c:FindFirstChild("RightLowerLeg")
		local rf = c:FindFirstChild("RightFoot")
		
		if ru and korblox_backup.RU then
			pcall(function()
				ru.TextureID = korblox_backup.RU.TextureID or ""
				ru.MeshId = korblox_backup.RU.MeshId or ""
			end)
		end
		if rl and korblox_backup.RL then
			pcall(function()
				rl.MeshId = korblox_backup.RL.MeshId or ""
				rl.Transparency = korblox_backup.RL.Transparency or 0
			end)
		end
		if rf and korblox_backup.RF then
			pcall(function()
				rf.MeshId = korblox_backup.RF.MeshId or ""
				rf.Transparency = korblox_backup.RF.Transparency or 0
			end)
		end
		korblox_backup = {}
	end

	local function restore_headless()
		local c = lp.Character
		if not c then return end
		local head = c:FindFirstChild("Head")
		if head and head_backup.Head then
			pcall(function()
				head.Transparency = head_backup.Head
				if head_backup.MeshId then head.MeshId = head_backup.MeshId end
				if head_backup.TextureID then head.TextureID = head_backup.TextureID end
			end)
		end
		for _, v in ipairs(head_backup.Children or {}) do
			if v.Obj and v.Obj.Parent then
				pcall(function() v.Obj.Transparency = v.Val end)
			end
		end
		head_backup = {}
	end

	local function apply_korblox()
		if not korblox_on then return end
		local c = lp.Character
		if not c then return end
		
		local ru = c:FindFirstChild("RightUpperLeg")
		local rl = c:FindFirstChild("RightLowerLeg")
		local rf = c:FindFirstChild("RightFoot")
		
		if not ru then return end
		
		korblox_backup = {}
		
		if ru then
			korblox_backup.RU = {
				MeshId = ru.MeshId,
				TextureID = ru.TextureID
			}
			pcall(function()
				ru.MeshId = "rbxassetid://902942096"
				ru.TextureID = "rbxassetid://902843398"
			end)
		end
		if rl then
			korblox_backup.RL = {
				MeshId = rl.MeshId,
				Transparency = rl.Transparency
			}
			pcall(function()
				rl.MeshId = "rbxassetid://902942093"
				rl.Transparency = 1
			end)
		end
		if rf then
			korblox_backup.RF = {
				MeshId = rf.MeshId,
				Transparency = rf.Transparency
			}
			pcall(function()
				rf.MeshId = "rbxassetid://902942089"
				rf.Transparency = 1
			end)
		end
	end

	local function apply_headless()
		if not headless_on then return end
		restore_headless()
		local c = lp.Character
		if not c then return end
		local head = c:FindFirstChild("Head")
		if not head then return end

		head_backup.Head = head.Transparency
		head_backup.MeshId = head.MeshId
		head_backup.TextureID = head.TextureID
		head_backup.Children = {}
		
		pcall(function()
			head.MeshId = "rbxassetid://6686307858"
			head.TextureID = "rbxassetid://6686307858"
			head.Transparency = 1
		end)
		
		for _, child in ipairs(head:GetDescendants()) do
			if child:IsA("BasePart") or child:IsA("Decal") or child:IsA("MeshPart") or child:IsA("SpecialMesh") then
				local hasTrans = pcall(function() return child.Transparency end)
				if hasTrans then
					local original = child.Transparency
					head_backup.Children[#head_backup.Children+1] = {Obj = child, Val = original}
					pcall(function() child.Transparency = 1 end)
				end
			end
		end
	end

	local run = game:GetService("RunService")

	local BODY_BASE = "assets"
	local BODY_NAME = "spastieslisosal"
	local BODY_CACHE = "shitaro_bodies"

	local BODY_PARTS = {
		{ Key = "Torso", File = "torso.mesh", Part = "Torso", Body = Enum.BodyPart.Torso },
		{ Key = "LeftArm", File = "leftarm.mesh", Part = "Left Arm", Body = Enum.BodyPart.LeftArm },
		{ Key = "RightArm", File = "rightarm.mesh", Part = "Right Arm", Body = Enum.BodyPart.RightArm },
		{ Key = "LeftLeg", File = "leftleg.mesh", Part = "Left Leg", Body = Enum.BodyPart.LeftLeg },
		{ Key = "RightLeg", File = "rightleg.mesh", Part = "Right Leg", Body = Enum.BodyPart.RightLeg },
	}

	local DISPLAY_REFS = { "DisplayRefKnife", "DisplayRefGun" }

	local R6_ROT = CFrame.new(0, 0, 0, -1, 0, 0, 0, 0, 1, 0, 1, 0)
	local R6_LEFT = CFrame.new(0, 0, 0, 0, 0, -1, 0, 1, 0, 1, 0, 0)
	local R6_RIGHT = CFrame.new(0, 0, 0, 0, 0, 1, 0, 1, 0, -1, 0, 0)
	local R6_GRIP = CFrame.new(0, -0.85, 0)
	local GRIP_REACH = 6

	local R6_SIZES = {
		{ Name = "Root", Size = Vector3.new(2, 2, 1) },
		{ Name = "Torso", Size = Vector3.new(2, 2, 1) },
		{ Name = "Left Arm", Size = Vector3.new(1, 2, 1) },
		{ Name = "Right Arm", Size = Vector3.new(1, 2, 1) },
		{ Name = "Left Leg", Size = Vector3.new(1, 2, 1) },
		{ Name = "Right Leg", Size = Vector3.new(1, 2, 1) },
	}

	local R6_JOINTS = {
		{ Name = "RootJoint", Holder = "Root", Part0 = "Root", Part1 = "Torso",
			C0 = CFrame.new(0, 0, 0) * R6_ROT, C1 = CFrame.new(0, 0, 0) * R6_ROT },
		{ Name = "Neck", Holder = "Torso", Part0 = "Torso", Part1 = "Head",
			C0 = CFrame.new(0, 1, 0) * R6_ROT, C1 = CFrame.new(0, -0.5, 0) * R6_ROT },
		{ Name = "Left Shoulder", Holder = "Torso", Part0 = "Torso", Part1 = "Left Arm",
			C0 = CFrame.new(-1, 0.5, 0) * R6_LEFT, C1 = CFrame.new(0.5, 0.5, 0) * R6_LEFT },
		{ Name = "Right Shoulder", Holder = "Torso", Part0 = "Torso", Part1 = "Right Arm",
			C0 = CFrame.new(1, 0.5, 0) * R6_RIGHT, C1 = CFrame.new(-0.5, 0.5, 0) * R6_RIGHT },
		{ Name = "Left Hip", Holder = "Torso", Part0 = "Torso", Part1 = "Left Leg",
			C0 = CFrame.new(-1, -1, 0) * R6_LEFT, C1 = CFrame.new(-0.5, 1, 0) * R6_LEFT },
		{ Name = "Right Hip", Holder = "Torso", Part0 = "Torso", Part1 = "Right Leg",
			C0 = CFrame.new(1, -1, 0) * R6_RIGHT, C1 = CFrame.new(0.5, 1, 0) * R6_RIGHT },
	}

	local R6_SKIN = {
		{ Part = "Torso", Field = "TorsoColor3", Source = "UpperTorso" },
		{ Part = "Left Arm", Field = "LeftArmColor3", Source = "LeftUpperArm" },
		{ Part = "Right Arm", Field = "RightArmColor3", Source = "RightUpperArm" },
		{ Part = "Left Leg", Field = "LeftLegColor3", Source = "LeftUpperLeg" },
		{ Part = "Right Leg", Field = "RightLegColor3", Source = "RightUpperLeg" },
	}

	local R6_TORSO_ATT = {
		NeckAttachment = Vector3.new(0, 1, 0),
		LeftCollarAttachment = Vector3.new(-1, 1, 0),
		RightCollarAttachment = Vector3.new(1, 1, 0),
		BodyFrontAttachment = Vector3.new(0, 0, -0.5),
		BodyBackAttachment = Vector3.new(0, 0, 0.5),
		WaistFrontAttachment = Vector3.new(0, -1, -0.5),
		WaistBackAttachment = Vector3.new(0, -1, 0.5),
		WaistCenterAttachment = Vector3.new(0, -1, 0),
	}

	local R6_ANIMS = {
		idle = "rbxassetid://180435571",
		walk = "rbxassetid://180426354",
		jump = "rbxassetid://125750702",
		fall = "rbxassetid://180436148",
		climb = "rbxassetid://180436334",
		sit = "rbxassetid://178130996",
	}

	local BODY_WANTED = {}
	for i = 1, #BODY_PARTS do
		BODY_WANTED[BODY_PARTS[i].File] = true
	end

	local body_asset = getcustomasset or getsynasset
		or (syn and syn.get_custom_asset) or (fluxus and fluxus.get_custom_asset)

	local SCAN_DEPTH = 8
	local SCAN_SLICE = 24

	local body_tree = {}
	local scan_slice = SCAN_SLICE

	local function body_yield()
		scan_slice = scan_slice - 1
		if scan_slice > 0 then return end
		scan_slice = SCAN_SLICE
		task.wait()
	end

	local function body_node(dir)
		body_yield()
		local ok, entries = pcall(listfiles, dir)
		if not ok or type(entries) ~= "table" then return nil, false end
		table.sort(entries)
		local sig = table.concat(entries, "|")
		local node = body_tree[dir]
		if node and node.Sig == sig then return node, false end
		local prev = node and node.Kind or nil
		local kind, subs, files = {}, {}, nil
		for i = 1, #entries do
			local path = entries[i]
			local isdir = prev and prev[path]
			if isdir == nil then
				isdir = false
				pcall(function() isdir = isfolder(path) end)
			end
			kind[path] = isdir
			if isdir then
				subs[#subs + 1] = path
			else
				local name = string.match(string.lower(path), "([^/\\]+)$")
				if name and BODY_WANTED[name] then
					files = files or {}
					files[name] = path
				end
			end
		end
		node = { Sig = sig, Kind = kind, Subs = subs, Files = files }
		body_tree[dir] = node
		return node, true
	end

	local function body_walk(dir, depth, seen, state)
		if depth > SCAN_DEPTH then return end
		seen[dir] = true
		local node, fresh = body_node(dir)
		if not node then
			if body_tree[dir] then
				body_tree[dir] = nil
				state.Dirty = true
			end
			return
		end
		if fresh then state.Dirty = true end
		for i = 1, #node.Subs do
			body_walk(node.Subs[i], depth + 1, seen, state)
		end
	end

	local function body_sweep(dir)
		local seen, state = {}, { Dirty = false }
		scan_slice = SCAN_SLICE
		body_walk(dir, 0, seen, state)
		for path in pairs(body_tree) do
			if not seen[path] then
				body_tree[path] = nil
				state.Dirty = true
			end
		end
		return state.Dirty
	end

	local function body_label(dir)
		local rel = string.gsub(dir, "\\", "/")
		rel = string.match(rel, "^.-" .. BODY_NAME .. "/(.+)$") or rel
		local parts, last = {}, nil
		for seg in string.gmatch(rel, "[^/]+") do
			local low = string.lower(seg)
			if low ~= last then
				parts[#parts + 1] = seg
				last = low
			end
		end
		return table.concat(parts, " / ")
	end

	local MODEL_STATIC = {
		{ Name = "Tung Tung Sahur", Kind = "asset", Id = "138151705692565" },
	}

	local MODEL_LIST = "models.txt"
	local MODEL_KINDS = { [10] = true, [32] = true, [40] = true }

	local mkt = game:GetService("MarketplaceService")

	local model_static_ids = {}
	for i = 1, #MODEL_STATIC do
		if MODEL_STATIC[i].Id then model_static_ids[MODEL_STATIC[i].Id] = true end
	end

	local model_names, model_defs = {}, {}
	for i = 1, #MODEL_STATIC do
		model_names[i] = MODEL_STATIC[i].Name
		model_defs[MODEL_STATIC[i].Name] = MODEL_STATIC[i]
	end

	local model_on = false
	local model_pick = model_names[1]
	local model_cache = {}
	local model_assets = {}
	local model_hidden = {}
	local model_paint = {}
	local model_made = {}
	local model_taken = {}
	local model_flags = {}
	local model_bind = {}
	local model_tools = {}
	local model_displays = {}
	local model_dying = false
	local model_inst = nil
	local model_conn = nil
	local model_watch = nil
	local model_files = 0
	local model_gen = 0
	local model_sig = nil
	local model_seen = false
	local model_scan_alive = true
	local model_drop = nil
	local model_grid = nil
	local model_user = {}
	local model_ids = {}
	local model_raw = nil
	local model_hush = false
	local model_apply
	local model_choose

	local function body_lookup()
		local ok, entries = pcall(listfiles, BODY_BASE)
		if ok and type(entries) == "table" then
			for _, path in ipairs(entries) do
				local name = string.match(string.lower(string.gsub(path, "\\", "/")), "([^/]+)/?$")
				if name == BODY_NAME then return path end
			end
		end
		for _, candidate in ipairs({ BODY_BASE .. "/" .. BODY_NAME, BODY_BASE .. "\\" .. BODY_NAME }) do
			local found = false
			pcall(function() found = isfolder(candidate) end)
			if found then return candidate end
		end
		return nil
	end

	local function body_ready()
		if type(body_asset) ~= "function" or type(listfiles) ~= "function" or type(isfolder) ~= "function" then
			return nil
		end
		local dir = body_lookup()
		if dir then return dir end
		if type(makefolder) ~= "function" then return nil end
		local base = false
		pcall(function() base = isfolder(BODY_BASE) end)
		if not base then pcall(makefolder, BODY_BASE) end
		pcall(makefolder, BODY_BASE .. "/" .. BODY_NAME)
		dir = body_lookup()
		if not dir then
			pcall(makefolder, BODY_BASE .. "\\" .. BODY_NAME)
			dir = body_lookup()
		end
		return dir
	end

	local function body_collect()
		local list, taken = {}, {}
		for i = 1, #MODEL_STATIC do
			list[i] = MODEL_STATIC[i]
			taken[MODEL_STATIC[i].Name] = true
		end
		local dirs = {}
		for path, node in pairs(body_tree) do
			if node.Files then dirs[#dirs + 1] = path end
		end
		table.sort(dirs)
		for i = 1, #dirs do
			local label = body_label(dirs[i])
			if label ~= "" and not taken[label] then
				taken[label] = true
				list[#list + 1] = { Name = label, Kind = "body", Files = body_tree[dirs[i]].Files }
			end
		end
		for i = 1, #model_user do
			local entry = model_user[i]
			local key = entry.Name or ("model " .. entry.Id)
			if taken[key] then key = key .. " (" .. entry.Id .. ")" end
			if not taken[key] then
				taken[key] = true
				entry.Key = key
				list[#list + 1] = { Name = key, Kind = "asset", Id = entry.Id, User = true, Ref = entry }
			end
		end
		table.sort(list, function(a, b) return a.Name < b.Name end)
		return list
	end

	local function model_rows()
		local rows = table.create(#model_names)
		for i = 1, #model_names do
			local name = model_names[i]
			local def = model_defs[name]
			rows[i] = { name = name, label = name, id = def and def.Id and tonumber(def.Id) or nil }
		end
		return rows
	end

	local function body_publish()
		local list = body_collect()
		local names = table.create(#list)
		for i = 1, #list do names[i] = list[i].Name end
		local added = nil
		if model_seen then
			added = {}
			for i = 1, #names do
				if not model_defs[names[i]] then added[#added + 1] = names[i] end
			end
		end
		local sig = table.concat(names, "|")
		table.clear(model_names)
		table.clear(model_defs)
		for i = 1, #list do
			model_names[i] = names[i]
			model_defs[names[i]] = list[i]
		end
		if sig == model_sig then return end
		model_sig = sig
		local lost = not model_defs[model_pick]
		if lost then model_pick = model_names[1] end
		if model_drop then
			pcall(function()
				model_drop:SetValues(model_names)
				model_drop:Generate()
			end)
			if lost and model_pick then
				pcall(function() model_drop:SetValue(model_pick) end)
			end
		end
		if model_grid then
			pcall(function() model_grid:SetData(model_rows()) end)
			if model_pick then
				pcall(function() model_grid:SetValue(model_pick) end)
			end
		end
		if added and #added > 0 and not model_hush then
			notification:Notify({
				Title = "SHITARO",
				Content = #added == 1 and ("Model Changer: + " .. added[1])
					or ("Model Changer: +" .. #added .. " custom skins"),
				Duration = 3,
				Icon = "person"
			})
		end
	end

	local function model_file(make)
		local dir = body_lookup()
		if not dir and make and type(makefolder) == "function" then
			local base = false
			pcall(function() base = isfolder(BODY_BASE) end)
			if not base then pcall(makefolder, BODY_BASE) end
			pcall(makefolder, BODY_BASE .. "/" .. BODY_NAME)
			dir = body_lookup()
		end
		return (dir or (BODY_BASE .. "/" .. BODY_NAME)) .. "/" .. MODEL_LIST
	end

	local function model_id_of(text)
		if type(text) ~= "string" then return nil end
		local id = string.match(text, "[?&]id=(%d+)")
			or string.match(text, "rbxassetid://(%d+)")
			or string.match(text, "/(%d+)")
		if not id then
			for run in string.gmatch(text, "%d+") do
				if not id or #run > #id then id = run end
			end
		end
		if id and #id >= 5 and #id <= 19 then return id end
		return nil
	end

	local function model_ids_in(text)
		local out, seen = {}, {}
		if type(text) ~= "string" then return out end
		for run in string.gmatch(text, "%d+") do
			if #run >= 5 and #run <= 19 and not seen[run] then
				seen[run] = true
				out[#out + 1] = run
			end
		end
		return out
	end

	local function model_info(id)
		local ok, info = pcall(function() return mkt:GetProductInfo(tonumber(id)) end)
		if ok and type(info) == "table" then return info end
		return nil
	end

	local function model_title(info, id)
		if info and type(info.Name) == "string" and info.Name ~= "" then return info.Name end
		return "model " .. id
	end

	local function model_save()
		if type(writefile) ~= "function" then return end
		local out = table.create(#model_user)
		for i = 1, #model_user do
			local entry = model_user[i]
			out[i] = (entry.Name or ("model " .. entry.Id)) .. " = " .. entry.Id
		end
		local raw = table.concat(out, "\n")
		model_raw = raw
		pcall(writefile, model_file(true), raw)
	end

	local function model_read(raw)
		table.clear(model_user)
		table.clear(model_ids)
		local blank = {}
		for line in string.gmatch(raw, "[^\r\n]+") do
			local body = string.match(line, "^%s*(.-)%s*$")
			if body ~= "" and string.sub(body, 1, 1) ~= "#" and string.sub(body, 1, 2) ~= "--" then
				local label, id = string.match(body, "^(.-)%s*[=|]%s*(%d+)%s*$")
				if not id then
					label, id = nil, model_id_of(body)
				elseif label == "" then
					label = nil
				end
				if id and not model_ids[id] and not model_static_ids[id] then
					local entry = { Name = label, Id = id }
					model_ids[id] = entry
					model_user[#model_user + 1] = entry
					if not label then blank[#blank + 1] = entry end
				end
			end
		end
		return blank
	end

	local function model_load()
		if type(readfile) ~= "function" then return false end
		local ok, raw = pcall(readfile, model_file())
		if not ok or type(raw) ~= "string" then
			if model_raw == nil then return false end
			model_raw = nil
			table.clear(model_user)
			table.clear(model_ids)
			return true
		end
		if raw == model_raw then return false end
		model_raw = raw
		local blank = model_read(raw)
		if #blank > 0 then
			task.spawn(function()
				for i = 1, #blank do
					blank[i].Name = model_title(model_info(blank[i].Id), blank[i].Id)
				end
				model_save()
				model_sig = nil
				pcall(body_publish)
			end)
		end
		return true
	end

	local function model_add(text)
		local ids = model_ids_in(text)
		if #ids == 0 then return false end
		local fresh = {}
		for i = 1, #ids do
			if not (model_ids[ids[i]] or model_static_ids[ids[i]]) then
				fresh[#fresh + 1] = ids[i]
			end
		end
		if #fresh == 0 then return false end
		task.spawn(function()
			local last, kept = nil, 0
			for i = 1, #fresh do
				local id = fresh[i]
				local info = model_info(id)
				if not (info and type(info.AssetTypeId) == "number" and not MODEL_KINDS[info.AssetTypeId]) then
					local entry = { Name = model_title(info, id), Id = id }
					model_ids[id] = entry
					model_user[#model_user + 1] = entry
					last = entry
					kept = kept + 1
				end
			end
			if kept == 0 then return end
			model_save()
			model_sig = nil
			model_hush = true
			pcall(body_publish)
			model_hush = false
			if kept == 1 and last and last.Key then
				model_choose(last.Key)
			end
		end)
		return true
	end

	local function model_forget(def)
		local entry = def and def.Ref
		if not entry then return end
		for i = 1, #model_user do
			if model_user[i] == entry then
				table.remove(model_user, i)
				break
			end
		end
		model_ids[entry.Id] = nil
		model_save()
		model_sig = nil
		if model_pick == def.Name then model_pick = nil end
		pcall(body_publish)
	end

	task.spawn(function()
		local dir = nil
		while model_scan_alive do
			if dir then
				local alive = false
				pcall(function() alive = isfolder(dir) end)
				if not alive then
					dir = nil
					table.clear(body_tree)
					model_sig = nil
				end
			end
			if not dir then dir = body_ready() end
			if dir then
				local dirty = body_sweep(dir)
				if model_load() then dirty = true end
				if dirty or not model_seen then
					pcall(body_publish)
					model_seen = true
				end
			end
			task.wait(2)
		end
	end)

	local function model_restore()
		for i = #model_hidden, 1, -1 do
			local entry = model_hidden[i]
			if entry.Obj.Parent then
				pcall(function() entry.Obj.Transparency = entry.Val end)
			end
			model_hidden[i] = nil
		end
	end

	local function model_hide(inst)
		model_hidden[#model_hidden + 1] = { Obj = inst, Val = inst.Transparency }
		pcall(function() inst.Transparency = 1 end)
	end

	local function model_in_tool(inst, c)
		local node = inst
		while node and node ~= c do
			if node:IsA("Tool") then return true end
			node = node.Parent
		end
		return false
	end

	local function model_veil(inst, c)
		if not (inst:IsA("BasePart") or inst:IsA("Decal")) then return end
		if model_in_tool(inst, c) then return end
		model_hide(inst)
	end

	local function model_hide_body(c)
		model_restore()
		for _, d in ipairs(c:GetDescendants()) do
			model_veil(d, c)
		end
	end

	local function model_detach(inst)
		model_taken[#model_taken + 1] = { Obj = inst, Parent = inst.Parent }
		pcall(function() inst.Parent = nil end)
	end

	local function model_bind_add(conn)
		if conn then model_bind[#model_bind + 1] = conn end
	end

	local function model_tool_drop(tool)
		local entry = model_tools[tool]
		if not entry then return end
		model_tools[tool] = nil
		for i = #entry.Parts, 1, -1 do
			pcall(function() entry.Parts[i]:Destroy() end)
			entry.Parts[i] = nil
		end
		for i = #entry.Hidden, 1, -1 do
			local slot = entry.Hidden[i]
			if slot.Obj.Parent then
				pcall(function() slot.Obj.Transparency = slot.Val end)
			end
			entry.Hidden[i] = nil
		end
	end

	local function model_tools_reset()
		for tool in pairs(model_tools) do
			model_tool_drop(tool)
		end
		table.clear(model_tools)
	end

	local function model_display_show(entry)
		if entry.Clone then
			pcall(function() entry.Clone:Destroy() end)
			entry.Clone = nil
		end
		for i = #entry.Hidden, 1, -1 do
			local slot = entry.Hidden[i]
			if slot.Obj.Parent then
				pcall(function() slot.Obj[slot.Key] = slot.Val end)
			end
			entry.Hidden[i] = nil
		end
	end

	local function model_displays_reset()
		for i = #model_displays, 1, -1 do
			model_display_show(model_displays[i])
			model_displays[i] = nil
		end
	end

	local function model_clear()
		_G.FAKE_MODEL_RIG = nil
		for i = #model_bind, 1, -1 do
			pcall(function() model_bind[i]:Disconnect() end)
			model_bind[i] = nil
		end
		model_tools_reset()
		model_displays_reset()
		if model_conn then
			pcall(function() model_conn:Disconnect() end)
			model_conn = nil
		end
		if model_watch then
			pcall(function() model_watch:Disconnect() end)
			model_watch = nil
		end
		if model_inst then
			pcall(function() model_inst:Destroy() end)
			model_inst = nil
		end
		for i = #model_made, 1, -1 do
			pcall(function() model_made[i]:Destroy() end)
			model_made[i] = nil
		end
		for i = #model_taken, 1, -1 do
			local entry = model_taken[i]
			pcall(function() entry.Obj.Parent = entry.Parent end)
			model_taken[i] = nil
		end
		for i = #model_paint, 1, -1 do
			local entry = model_paint[i]
			if entry.Obj.Parent then
				pcall(function() entry.Obj.Color = entry.Val end)
			end
			model_paint[i] = nil
		end
		table.clear(model_flags)
		model_restore()
	end

	local function model_mesh_id(path)
		local hit = model_assets[path]
		if hit then return hit end
		local id = nil
		if type(readfile) == "function" and type(writefile) == "function" then
			local ok_read, data = pcall(readfile, path)
			if ok_read and type(data) == "string" and #data > 0 then
				model_files = model_files + 1
				local target = BODY_CACHE .. "/" .. model_files .. ".mesh"
				if pcall(writefile, target, data) then
					local ok_asset, res = pcall(body_asset, target)
					if ok_asset and type(res) == "string" and res ~= "" then id = res end
				end
			end
		end
		if not id then
			local ok_direct, res = pcall(body_asset, path)
			if ok_direct and type(res) == "string" and res ~= "" then id = res end
		end
		if id then model_assets[path] = id end
		return id
	end

	local function model_watch_meshes(c)
		model_watch = c.ChildAdded:Connect(function(child)
			if not model_on then return end
			local strip = child:IsA("Shirt") or child:IsA("Pants") or child:IsA("ShirtGraphic")
				or (child:IsA("CharacterMesh") and model_flags[child.BodyPart])
			if not strip then return end
			task.defer(function()
				if model_on and child.Parent == c then model_detach(child) end
			end)
		end)
	end

	local function model_build_r6(def, c)
		local applied = 0
		for i = 1, #BODY_PARTS do
			local slot = BODY_PARTS[i]
			local file = def.Files[slot.File]
			local part = file and c:FindFirstChild(slot.Part)
			if part and part:IsA("BasePart") then
				local id = model_mesh_id(file)
				if id then
					for _, d in ipairs(c:GetChildren()) do
						if d:IsA("CharacterMesh") and d.BodyPart == slot.Body then model_detach(d) end
					end
					for _, d in ipairs(part:GetChildren()) do
						if d:IsA("SpecialMesh") then model_detach(d) end
					end
					model_paint[#model_paint + 1] = { Obj = part, Val = part.Color }
					part.Color = Color3.new(1, 1, 1)
					local mesh = Instance.new("SpecialMesh")
					mesh.MeshType = Enum.MeshType.FileMesh
					mesh.MeshId = id
					mesh.Scale = Vector3.one
					mesh.VertexColor = Vector3.one
					mesh.Parent = part
					model_made[#model_made + 1] = mesh
					model_flags[slot.Body] = true
					applied = applied + 1
				end
			end
		end
		if applied > 0 then
			for _, d in ipairs(c:GetChildren()) do
				if d:IsA("Shirt") or d:IsA("Pants") or d:IsA("ShirtGraphic") then model_detach(d) end
			end
		end
		return applied
	end

	local function model_scrub(inst)
		for _, d in ipairs(inst:GetDescendants()) do
			if d:IsA("JointInstance") or d:IsA("Constraint") or d:IsA("BodyMover")
				or d:IsA("LuaSourceContainer") or d:IsA("Humanoid") then
				pcall(function() d:Destroy() end)
			end
		end
	end

	local function model_soft(part)
		part.Anchored = false
		part.CanCollide = false
		part.CanQuery = false
		part.CanTouch = false
		part.Massless = true
		part.Locked = true
		part.LocalTransparencyModifier = 0
	end

	local function model_tool_veil(tool)
		local hidden = {}
		for _, d in ipairs(tool:GetDescendants()) do
			if d:IsA("BasePart") or d:IsA("Decal") then
				hidden[#hidden + 1] = { Obj = d, Val = d.Transparency }
				pcall(function() d.Transparency = 1 end)
			end
		end
		return hidden
	end

	local function model_tool_take(tool, rig, arm, hand)
		if model_tools[tool] then return true end
		local handle = tool:FindFirstChild("Handle")
		if not (handle and handle:IsA("BasePart")) then
			handle = tool:FindFirstChildWhichIsA("BasePart")
		end
		if not handle then return false end
		local clones = {}
		if rig and arm and hand and hand.Parent then
			if (handle.Position - hand.Position).Magnitude > GRIP_REACH then return false end
			local grip = R6_GRIP * hand.CFrame:Inverse() * handle.CFrame
			local base = handle.CFrame:Inverse()
			local sources = {}
			for _, d in ipairs(tool:GetDescendants()) do
				if d:IsA("BasePart") then sources[#sources + 1] = d end
			end
			local shell = tool:Clone()
			model_scrub(shell)
			local mirror = {}
			for _, d in ipairs(shell:GetDescendants()) do
				if d:IsA("BasePart") then mirror[#mirror + 1] = d end
			end
			for i = 1, #mirror do
				local src = sources[i]
				local part = mirror[i]
				if src then
					local offset = grip * (base * src.CFrame)
					model_soft(part)
					part.CastShadow = false
					part.Parent = rig
					part.CFrame = arm.CFrame * offset
					local weld = Instance.new("Weld")
					weld.Part0 = arm
					weld.Part1 = part
					weld.C0 = offset
					weld.Parent = part
					clones[#clones + 1] = part
				end
			end
			pcall(function() shell:Destroy() end)
			if #clones == 0 then return false end
		end
		model_tools[tool] = { Parts = clones, Hidden = model_tool_veil(tool) }
		return true
	end

	local function model_veil_watch(c)
		model_bind_add(c.DescendantAdded:Connect(function(d)
			if not model_on then return end
			model_veil(d, c)
		end))
	end

	local function model_tools_track(c, rig, arm)
		local hand = nil
		if rig then
			hand = c:FindFirstChild("RightHand") or c:FindFirstChild("Right Arm")
			if hand and not hand:IsA("BasePart") then hand = nil end
		end
		local function grab(tool)
			task.defer(function()
				for _ = 1, 12 do
					if not model_on or tool.Parent ~= c then return end
					if model_tool_take(tool, rig, arm, hand) then return end
					run.RenderStepped:Wait()
				end
			end)
		end
		for _, child in ipairs(c:GetChildren()) do
			if child:IsA("Tool") then grab(child) end
		end
		model_bind_add(c.ChildAdded:Connect(function(child)
			if model_on and child:IsA("Tool") then grab(child) end
		end))
		model_bind_add(c.ChildRemoved:Connect(function(child)
			if child:IsA("Tool") then model_tool_drop(child) end
		end))
	end

	local function model_display_veil(part, store)
		local list = { part }
		for _, d in ipairs(part:GetDescendants()) do
			list[#list + 1] = d
		end
		for i = 1, #list do
			local d = list[i]
			if d:IsA("BasePart") or d:IsA("Decal") then
				store[#store + 1] = { Obj = d, Key = "Transparency", Val = d.Transparency }
				pcall(function() d.Transparency = 1 end)
			elseif d:IsA("Beam") or d:IsA("ParticleEmitter") or d:IsA("Trail")
				or d:IsA("Fire") or d:IsA("Smoke") or d:IsA("Sparkles") or d:IsA("Light") then
				store[#store + 1] = { Obj = d, Key = "Enabled", Val = d.Enabled }
				pcall(function() d.Enabled = false end)
			end
		end
	end

	local function model_display_mount(part, rig, host, offset)
		local clone = part:Clone()
		model_scrub(clone)
		for _, d in ipairs(clone:GetDescendants()) do
			if d:IsA("BasePart") then
				model_soft(d)
				d.CastShadow = false
			end
		end
		model_soft(clone)
		clone.CastShadow = false
		clone.Parent = rig
		clone.CFrame = host.CFrame * offset
		local weld = Instance.new("Weld")
		weld.Part0 = host
		weld.Part1 = clone
		weld.C0 = offset
		weld.Parent = clone
		return clone
	end

	local function model_joint_rest(parent, child, name)
		local a0 = parent:FindFirstChild(name)
		local a1 = child:FindFirstChild(name)
		if a0 and a1 and a0:IsA("Attachment") and a1:IsA("Attachment") then
			return a0.CFrame * a1.CFrame:Inverse()
		end
		return nil
	end

	local function model_part_rest(c, part)
		local hrp = c:FindFirstChild("HumanoidRootPart")
		if not (hrp and part) then return nil end
		if part == hrp then return CFrame.new() end
		local lower = c:FindFirstChild("LowerTorso")
		if not lower then return nil end
		local root = model_joint_rest(hrp, lower, "RootRigAttachment")
		if not root then return nil end
		if part == lower then return root end
		if part == c:FindFirstChild("UpperTorso") then
			local waist = model_joint_rest(lower, part, "WaistRigAttachment")
			if waist then return root * waist end
		end
		return nil
	end

	local function model_display_anchor(part)
		local rc = part:FindFirstChildOfClass("RigidConstraint")
		if rc then return rc.Attachment0, rc.Attachment1 end
		return nil, nil
	end

	local function model_display_offset(c, part, a0, a1)
		if a0 and a1 and a0.Parent and a0.Parent:IsA("BasePart") and a0.Parent.Parent == c then
			local rest = model_part_rest(c, a0.Parent)
			if rest then return rest * a0.CFrame * a1.CFrame:Inverse() end
		end
		local hrp = c:FindFirstChild("HumanoidRootPart")
		if hrp then return hrp.CFrame:Inverse() * part.CFrame end
		return nil
	end

	local function model_display_take(c, rig, host, part)
		for i = 1, #model_displays do
			if model_displays[i].Obj == part then return end
		end
		local a0, a1 = model_display_anchor(part)
		local entry = { Obj = part, Hidden = {}, Clone = nil, Host = a0 }
		if rig and host and host.Parent then
			local offset = model_display_offset(c, part, a0, a1)
			if offset then
				local ok, clone = pcall(model_display_mount, part, rig, host, offset)
				if ok then entry.Clone = clone end
			end
		end
		model_display_veil(part, entry.Hidden)
		model_displays[#model_displays + 1] = entry
	end

	local function model_displays_sync(c, rig, host)
		if not (model_on and c and c.Parent) then return end
		local live = {}
		for i = 1, #DISPLAY_REFS do
			local ref = c:FindFirstChild(DISPLAY_REFS[i])
			local val = (ref and ref:IsA("ObjectValue")) and ref.Value or nil
			if val and val:IsA("BasePart") and val.Parent then live[val] = true end
		end
		for i = #model_displays, 1, -1 do
			local entry = model_displays[i]
			local stale = not live[entry.Obj] or not entry.Obj.Parent
			if not stale and entry.Clone then
				local a0 = model_display_anchor(entry.Obj)
				stale = not entry.Clone.Parent or entry.Host ~= a0
			end
			if stale then
				model_display_show(entry)
				table.remove(model_displays, i)
			end
		end
		for part in pairs(live) do
			model_display_take(c, rig, host, part)
		end
	end

	local function model_displays_track(c, rig, host)
		local function hook(ref)
			if not (ref and ref:IsA("ObjectValue")) then return end
			model_bind_add(ref.Changed:Connect(function()
				if not model_on then return end
				task.defer(function() model_displays_sync(c, rig, host) end)
			end))
		end
		for i = 1, #DISPLAY_REFS do
			hook(c:FindFirstChild(DISPLAY_REFS[i]))
		end
		model_bind_add(c.ChildAdded:Connect(function(child)
			if not model_on then return end
			if child.Name ~= "DisplayRefKnife" and child.Name ~= "DisplayRefGun" then return end
			hook(child)
			task.defer(function() model_displays_sync(c, rig, host) end)
		end))
		model_displays_sync(c, rig, host)
	end

	local function model_guard(c, hum)
		local function down()
			if not model_on or model_dying then return end
			model_dying = true
			local gen = model_gen
			task.defer(function()
				model_dying = false
				if model_on and gen == model_gen then model_clear() end
			end)
		end
		if hum then
			model_bind_add(hum.Died:Connect(down))
			model_bind_add(hum:GetPropertyChangedSignal("Health"):Connect(function()
				if hum.Health <= 0 then down() end
			end))
		end
		model_bind_add(c.AncestryChanged:Connect(function()
			if not c:IsDescendantOf(workspace) then down() end
		end))
		model_bind_add(lp.CharacterRemoving:Connect(function(char)
			if char == c then down() end
		end))
	end

	local function model_build_fake_r6(def, c, hum)
		local real_hrp = c:FindFirstChild("HumanoidRootPart")
		if not real_hrp then return 0 end

		local ids = {}
		local count = 0
		for i = 1, #BODY_PARTS do
			local slot = BODY_PARTS[i]
			local file = def.Files[slot.File]
			if file then
				local id = model_mesh_id(file)
				if id then
					ids[slot.Part] = id
					count = count + 1
				end
			end
		end
		if count == 0 then return 0 end

		local rig = Instance.new("Model")
		rig.Name = "SHITARO_R6"

		local parts = {}
		for i = 1, #R6_SIZES do
			local slot = R6_SIZES[i]
			local part = Instance.new("Part")
			part.Name = slot.Name
			part.Size = slot.Size
			part.TopSurface = Enum.SurfaceType.Smooth
			part.BottomSurface = Enum.SurfaceType.Smooth
			part.CFrame = real_hrp.CFrame
			model_soft(part)
			if slot.Name == "Root" then
				part.Anchored = true
				part.Transparency = 1
			end
			local mesh_id = ids[slot.Name]
			if mesh_id then
				part.Color = Color3.new(1, 1, 1)
				local mesh = Instance.new("SpecialMesh")
				mesh.MeshType = Enum.MeshType.FileMesh
				mesh.MeshId = mesh_id
				mesh.Scale = Vector3.one
				mesh.VertexColor = Vector3.one
				mesh.Parent = part
			end
			part.Parent = rig
			parts[slot.Name] = part
		end

		for name, offset in pairs(R6_TORSO_ATT) do
			local att = Instance.new("Attachment")
			att.Name = name
			att.Position = offset
			att.Parent = parts.Torso
		end

		local real_head = c:FindFirstChild("Head")
		local head
		if real_head and real_head:IsA("BasePart") then
			head = real_head:Clone()
			model_scrub(head)
			head.Name = "Head"
			model_soft(head)
		else
			head = Instance.new("Part")
			head.Name = "Head"
			head.Size = Vector3.new(2, 1, 1)
			model_soft(head)
			local hm = Instance.new("SpecialMesh")
			hm.MeshType = Enum.MeshType.Head
			hm.Scale = Vector3.new(1.25, 1.25, 1.25)
			hm.Parent = head
		end
		head.CFrame = real_hrp.CFrame * CFrame.new(0, 1.5, 0)
		head.Parent = rig
		parts.Head = head

		local neck_att = head:FindFirstChild("NeckRigAttachment")
		local neck_c1 = CFrame.new(neck_att and neck_att.Position or Vector3.new(0, -head.Size.Y * 0.5, 0)) * R6_ROT

		for i = 1, #R6_JOINTS do
			local def_joint = R6_JOINTS[i]
			local p0, p1 = parts[def_joint.Part0], parts[def_joint.Part1]
			if p0 and p1 then
				local motor = Instance.new("Motor6D")
				motor.Name = def_joint.Name
				motor.Part0 = p0
				motor.Part1 = p1
				motor.C0 = def_joint.C0
				motor.C1 = def_joint.Name == "Neck" and neck_c1 or def_joint.C1
				motor.Parent = parts[def_joint.Holder]
			end
		end

		local controller = Instance.new("AnimationController")
		controller.Parent = rig

		local animator = Instance.new("Animator")
		animator.Parent = controller

		rig.PrimaryPart = parts.Root
		rig.Parent = workspace.CurrentCamera or workspace
		model_made[#model_made + 1] = rig
		_G.FAKE_MODEL_RIG = rig

		local colors = c:FindFirstChildOfClass("BodyColors")
		for i = 1, #R6_SKIN do
			local slot = R6_SKIN[i]
			local part = parts[slot.Part]
			if part and not ids[slot.Part] then
				local tone = nil
				if colors then
					pcall(function() tone = colors[slot.Field] end)
				end
				if not tone then
					local source = c:FindFirstChild(slot.Source)
					if source and source:IsA("BasePart") then tone = source.Color end
				end
				if tone then part.Color = tone end
			end
		end

		local hosts = {}
		for _, part in pairs(parts) do
			for _, att in ipairs(part:GetChildren()) do
				if att:IsA("Attachment") then hosts[att.Name] = att end
			end
		end

		for _, item in ipairs(c:GetChildren()) do
			if item:IsA("Accoutrement") then
				local handle = item:FindFirstChildWhichIsA("BasePart")
				local att = handle and handle:FindFirstChildWhichIsA("Attachment")
				local host = att and hosts[att.Name]
				if host then
					local clone = handle:Clone()
					model_scrub(clone)
					model_soft(clone)
					local offset = host.CFrame * att.CFrame:Inverse()
					clone.CFrame = host.Parent.CFrame * offset
					clone.Parent = rig
					local weld = Instance.new("Weld")
					weld.Part0 = host.Parent
					weld.Part1 = clone
					weld.C0 = offset
					weld.Parent = clone
				end
			end
		end

		model_hide_body(c)
		model_veil_watch(c)
		model_tools_track(c, rig, parts["Right Arm"])
		model_displays_track(c, rig, parts.Torso)
		model_guard(c, hum)

		local tracks = {}
		for key, id in pairs(R6_ANIMS) do
			local anim = Instance.new("Animation")
			anim.Name = key
			anim.AnimationId = id
			anim.Parent = rig
			local ok, track = pcall(function() return animator:LoadAnimation(anim) end)
			if ok and track then tracks[key] = track end
		end

		local cur, cur_speed = nil, nil
		local function play(name, speed)
			local track = tracks[name]
			if cur ~= name then
				for key, other in pairs(tracks) do
					if key ~= name and other.IsPlaying then
						pcall(function() other:Stop(0.15) end)
					end
				end
				if track then pcall(function() track:Play(0.15) end) end
				cur, cur_speed = name, nil
			end
			if track and speed and speed ~= cur_speed then
				cur_speed = speed
				pcall(function() track:AdjustSpeed(speed) end)
			end
		end

		local root = parts.Root
		local display_stamp = 0

		model_conn = run.RenderStepped:Connect(function()
			if not model_on then return end
			if rig.Parent == nil then
				pcall(function() rig.Parent = workspace.CurrentCamera or workspace end)
			end
			if os.clock() - display_stamp > 0.5 then
				display_stamp = os.clock()
				model_displays_sync(lp.Character, rig, parts.Torso)
			end
			if lp.Character == c and c.Parent and rig.Parent then
				local hrp = c:FindFirstChild("HumanoidRootPart")
				if hrp then
					local cf = hrp.CFrame
					local pos = cf.Position
					local feet = pos.Y - hrp.Size.Y * 0.5 - (hum and hum.HipHeight or 0)
					root.CFrame = CFrame.new(pos.X, feet + 3, pos.Z) * cf.Rotation

					local state = hum and hum:GetState()
					local vel = hrp.AssemblyLinearVelocity
					local speed = math.sqrt(vel.X * vel.X + vel.Z * vel.Z)
					if state == Enum.HumanoidStateType.Jumping then
						play("jump")
					elseif state == Enum.HumanoidStateType.Freefall then
						play("fall")
					elseif state == Enum.HumanoidStateType.Climbing then
						play("climb", 1)
					elseif state == Enum.HumanoidStateType.Seated then
						play("sit")
					elseif speed > 0.75 then
						play("walk", math.floor(math.clamp(speed / 14.5, 0.4, 3) * 20) / 20)
					else
						play("idle")
					end
				end
			end
		end)

		return count
	end

	local function model_build_body(def)
		local c = lp.Character
		if not c then
			notification:Notify({ Title = "SHITARO", Content = "Model Changer: no character", Duration = 4, Icon = "person" })
			return
		end
		if type(makefolder) == "function" and type(isfolder) == "function" then
			local has = false
			pcall(function() has = isfolder(BODY_CACHE) end)
			if not has then pcall(makefolder, BODY_CACHE) end
		end
		local hum = c:FindFirstChildOfClass("Humanoid")
		local r15 = c:FindFirstChild("UpperTorso") ~= nil
			or (hum and hum.RigType == Enum.HumanoidRigType.R15)
		local applied
		if r15 then
			applied = model_build_fake_r6(def, c, hum)
		else
			applied = model_build_r6(def, c)
			if applied > 0 then model_watch_meshes(c) end
		end
		if applied == 0 then
			notification:Notify({
				Title = "SHITARO",
				Content = "Model Changer: " .. (r15 and "R15" or "R6") .. ", 0 meshes loaded",
				Duration = 4,
				Icon = "person"
			})
		end
	end

	local function model_template(def)
		local cached = model_cache[def.Name]
		if cached then return cached end
		local id = def.Id
		if not id then return nil end
		local ok, objs = pcall(game.GetObjects, game, "rbxassetid://" .. id)
		if not ok or type(objs) ~= "table" then return nil end
		local root = objs[1]
		if not root then return nil end
		if not root:IsA("Model") then
			local holder = Instance.new("Model")
			root.Parent = holder
			root = holder
		end
		for _, d in ipairs(root:GetDescendants()) do
			if d:IsA("LuaSourceContainer") or d:IsA("Humanoid") or d:IsA("JointInstance")
				or d:IsA("Constraint") or d:IsA("BodyMover") then
				pcall(function() d:Destroy() end)
			end
		end
		local has_part = false
		for _, d in ipairs(root:GetDescendants()) do
			if d:IsA("BasePart") then
				has_part = true
				d.Anchored = true
				d.CanCollide = false
				d.CanQuery = false
				d.CanTouch = false
				d.Massless = true
				d.CastShadow = false
				d.Locked = true
			end
		end
		if not has_part then
			pcall(function() root:Destroy() end)
			return nil
		end
		model_cache[def.Name] = root
		return root
	end

	local function model_build_asset(def, gen)
		local tpl = model_template(def)
		if not tpl or gen ~= model_gen or not model_on then return end
		local c = lp.Character
		local hrp = c and c:FindFirstChild("HumanoidRootPart")
		if not hrp then return end
		local hum = c:FindFirstChildOfClass("Humanoid")
		local clone = tpl:Clone()
		local _, char_size = c:GetBoundingBox()
		local _, raw_size = clone:GetBoundingBox()
		if raw_size.Y > 0.05 and char_size.Y > 0.05 then
			local scale = char_size.Y / raw_size.Y
			if math.abs(scale - 1) > 0.02 then
				pcall(function() clone:ScaleTo(scale) end)
			end
		end
		local box, size = clone:GetBoundingBox()
		local pivot_fix = (clone:GetPivot():Inverse() * box):Inverse()
		local y_offset = size.Y * 0.5 - hrp.Size.Y * 0.5 - (hum and hum.HipHeight or 0)
		clone.Name = "SHITARO_FAKE_MODEL"
		clone.Parent = workspace
		model_inst = clone
		_G.FAKE_MODEL_RIG = clone
		model_hide_body(c)
		model_veil_watch(c)
		model_tools_track(c, nil, nil)
		model_displays_track(c, nil, nil)
		model_guard(c, hum)
		local last = nil
		local display_stamp = 0
		model_conn = run.RenderStepped:Connect(function()
			if not model_on or clone.Parent == nil then return end
			local char = lp.Character
			local root = char and char:FindFirstChild("HumanoidRootPart")
			if not root then return end
			if os.clock() - display_stamp > 0.5 then
				display_stamp = os.clock()
				model_displays_sync(char, nil, nil)
			end
			local cf = root.CFrame
			if last == cf then return end
			last = cf
			local look, pos = cf.LookVector, cf.Position
			clone:PivotTo(CFrame.new(pos.X, pos.Y + y_offset, pos.Z)
				* CFrame.fromEulerAnglesYXZ(0, math.atan2(-look.X, -look.Z), 0)
				* pivot_fix)
		end)
	end

	local function model_build(gen)
		local def = model_defs[model_pick]
		if not def then return end
		if def.Kind == "body" then
			model_build_body(def)
		else
			model_build_asset(def, gen)
		end
	end

	function model_apply()
		model_gen = model_gen + 1
		model_clear()
		if not model_on then return end
		local gen = model_gen
		task.spawn(function()
			pcall(model_build, gen)
			if gen == model_gen and not model_on then
				model_clear()
			end
		end)
	end

	function model_choose(name)
		if type(name) ~= "string" or not model_defs[name] or name == model_pick then return end
		model_pick = name
		if model_drop then pcall(function() model_drop:SetValue(name) end) end
		if model_grid then pcall(function() model_grid:SetValue(name) end) end
		if model_on then model_apply() end
	end

	local function apply_all()
		if korblox_on then apply_korblox() end
		if headless_on then apply_headless() end
		if model_on then model_apply() end
	end

	local function connect_char()
		if char_conn then
			pcall(function() char_conn:Disconnect() end)
			char_conn = nil
		end
		char_conn = lp.CharacterAdded:Connect(function()
			task.wait(1)
			apply_all()
		end)
	end

	getgenv().__PLR_QUEUE("char", "fake korblox", function(target)
		target:AddToggle({
			Name = "fake korblox",
			Default = false,
			Flag = "Fake krb",
			Callback = function(v)
				korblox_on = v
				if v then
					if not char_conn then connect_char() end
					apply_korblox()
				else
					restore_korblox()
				end
			end
		})
	end)

	getgenv().__PLR_QUEUE("char", "fake headless", function(target)
		target:AddToggle({
			Name = "fake headless",
			Default = false,
			Flag = "Fake hd",
			Callback = function(v)
				headless_on = v
				if v then
					if not char_conn then connect_char() end
					apply_headless()
				else
					restore_headless()
				end
			end
		})
	end)

	getgenv().__PLR_QUEUE("char", "model changer", function(target)
		local model_tgl = target:AddToggle({
			Name = "model changer",
			Default = false,
			Flag = "Fake model",
			Option = true,
			Callback = function(v)
				model_on = v
				if v then
					if not char_conn then connect_char() end
					model_apply()
				else
					model_gen = model_gen + 1
					model_clear()
				end
			end
		})

		model_drop = model_tgl.Option:AddDropdown({
			Name = "Model",
			Default = model_pick,
			Values = model_names,
			AutoUpdate = true,
			Flag = "Fake model type",
			Callback = function(v)
				model_choose(type(v) == "table" and v[1] or v)
			end
		})

		pcall(function() model_drop:SetValues(model_names) end)

		if type(player_tab.AddSub) ~= "function" then return end

		local model_page = player_tab:AddSub({
			Name = "models",
			Icon = "shirt",
			Tip = "model library"
		})

		local function model_menu(name, _, x, y, cell)
			local def = model_defs[name]
			if not def then return end

			local rows = {
				{
					icon = "check",
					name = model_pick == name and "in use" or "use",
					callback = function() model_choose(name) end
				}
			}

			if def.Id then
				rows[#rows + 1] = {
					icon = "copy",
					name = "copy id",
					callback = function()
						if type(setclipboard) == "function" then pcall(setclipboard, def.Id) end
					end
				}
			end

			if def.User then
				rows[#rows + 1] = {
					icon = "trash-2",
					name = "remove",
					callback = function() model_forget(def) end
				}
			end

			popmenu({ title = name, icon = "shirt", x = x, y = y, follow = cell, items = rows })
		end

		model_grid = model_page:AddImageList({
			Name = "models",
			Icon = "shirt",
			Position = 'full',
			Thumb = "Asset",
			Height = 300,
			Cell = 78,
			Tools = false,
			Blank = "person-standing",
			Empty = "nothing here, hit add below",
			Values = model_rows(),
			Default = model_pick,
			Flag = "Fake model library",
			Context = model_menu,
			Buttons = {
				{
					icon = "plus",
					tip = "add ur own model by id or link",
					callback = function()
						askinput({
							title = "add model",
							icon = "plus",
							hint = "model id or link",
							accept = "add",
							deny = "cancel",
							callback = model_add
						})
					end
				}
			},
			Callback = function(v)
				model_choose(type(v) == "table" and v[1] or v)
			end
		})
	end)

	local char_sec = getgenv().__PLAYER_CHAR_SEC

	getgenv().__PLR_FLUSH("misc", getgenv().__PLAYER_MISC_SEC)
	getgenv().__PLR_FLUSH("char", char_sec)

	if char_sec then
		char_sec:AddButton({
			Name = "reset",
			Callback = function()
				local c = lp.Character
				local hum = c and c:FindFirstChildWhichIsA("Humanoid")
				if hum then
					hum:ChangeState(Enum.HumanoidStateType.Dead)
				elseif c then
					pcall(function() c:BreakJoints() end)
				end
			end
		})
	end

	getgenv().FAKE_UNLOAD = function()
		korblox_on, headless_on, model_on = false, false, false
		model_scan_alive = false
		model_gen = model_gen + 1
		if char_conn then
			pcall(function() char_conn:Disconnect() end)
			char_conn = nil
		end
		restore_korblox()
		restore_headless()
		model_clear()
		for name, tpl in pairs(model_cache) do
			pcall(function() tpl:Destroy() end)
			model_cache[name] = nil
		end
		table.clear(model_assets)
	end
end
do
	local player_tab = anim_tab
	local emote_page = (type(anim_tab.AddSub) == "function") and anim_tab:AddSub({
		Name = "emotes",
		Icon = "video",
		Tip = "emote library"
	}) or anim_tab
	do
	
	local players, http = game:GetService("Players"), game:GetService("HttpService")
	local lp = players.LocalPlayer
	local cats = {
		{"Idle", "idle"},
		{"Walk", "walk"},
		{"Run", "run"},
		{"Jump", "jump"},
		{"Fall", "fall"},
		{"Climb", "climb"},
		{"Swim", "swim"},
		{"Swim Idle", "swimidle"}
	}
	local cat_names, cat_map = {}, {}
	for _, c in ipairs(cats) do
		cat_names[#cat_names+1] = c[1]
		cat_map[c[1]] = c[2]
	end
	local animItems, byName, mapCache, sel, origMap = {}, {}, {}, {}, {}
	local enabled, animConn, active = false, nil, "idle"
	local fetched, pendingApply, selLockUntil, applyToken = false, false, 0, 0

	local function getParts()
		local char = lp.Character
		if not char then return end
		return char, char:FindFirstChildOfClass("Humanoid"), char:FindFirstChild("Animate")
	end

	local function refreshAnimate(animate, hum)
		if animate and hum and hum.MoveDirection.Magnitude == 0 then
			animate.Disabled = true
			animate.Disabled = false
		end
	end

	local function stopTracks(hum)
		if not hum then return end
		for _, track in pairs(hum:GetPlayingAnimationTracks()) do
			pcall(function() track:Stop() end)
		end
	end

	local function resolveMappings(data)
		local key = tostring(data.id)
		if mapCache[key] then return mapCache[key] end
		local bundled = data.bundledItems
		if type(bundled) ~= "table" then return nil end
		local mappings = {}
		for _, ids in pairs(bundled) do
			if type(ids) == "table" then
				for _, assetId in pairs(ids) do
					local ok, objs = pcall(game.GetObjects, game, "rbxassetid://"..assetId)
					if ok and objs then
						local function scan(parent, path)
							for _, child in ipairs(parent:GetChildren()) do
								if child:IsA("Animation") then
									local parts = (path.."."..child.Name):split(".")
									mappings[#mappings+1] = {category = parts[#parts-1], name = parts[#parts], id = child.AnimationId}
								elseif #child:GetChildren() > 0 then
									scan(child, path.."."..child.Name)
								end
							end
						end
						for _, o in ipairs(objs) do scan(o, o.Name) pcall(function() o:Destroy() end) end
					end
				end
			end
		end
		mapCache[key] = mappings
		return mappings
	end

	local function catItems(data, folderName)
		local mappings = resolveMappings(data)
		if not mappings then return nil end
		local items = {}
		for _, m in ipairs(mappings) do
			if m.category and m.category:lower() == folderName then
				items[m.name:lower()] = m.id
			end
		end
		return items
	end

	local function applyCat(animate, folderName, data)
		if not (animate and data) then return end
		local items = catItems(data, folderName)
		if not (items and next(items)) then return end
		local folder = animate:FindFirstChild(folderName)
		if not folder then return end
		local _, first = next(items)
		for _, a in ipairs(folder:GetChildren()) do
			if a:IsA("Animation") then
				local id = items[a.Name:lower()] or first
				if id then
					if origMap[a] == nil then origMap[a] = a.AnimationId end
					a.AnimationId = id
					a.Parent = nil
					a.Parent = folder
				end
			end
		end
	end

	local function applyAll(animate)
		for _, c in ipairs(cats) do
			local name = sel[c[2]]
			if name and name ~= "none" and byName[name] then
				applyCat(animate, c[2], byName[name])
			end
		end
	end

	local function restore()
		for a, id in pairs(origMap) do
			if a and a.Parent then
				pcall(function()
					local folder = a.Parent
					a.AnimationId = id
					a.Parent = nil
					a.Parent = folder
				end)
			end
		end
		origMap = {}
	end

	local function doApply()
		applyToken += 1
		local token = applyToken
		task.spawn(function()
			local _, hum, animate = getParts()
			if not animate or token ~= applyToken then return end
			stopTracks(hum)
			restore()
			applyAll(animate)
			if token == applyToken then
				refreshAnimate(animate, hum)
			end
		end)
	end

	local function requestApply()
		if not enabled then return end
		if not fetched then
			pendingApply = true
			return
		end
		doApply()
	end

	local function fetchAll()
		local urls = {
			"https://raw.githubusercontent.com/7yd7/sniper-Emote/refs/heads/test/AnimationSniper.json",
			"https://raw.githubusercontent.com/7yd7/sniper-Emote/refs/heads/test/AnimationSniperoffsale.json"
		}
		local seen = {}
		for _, url in ipairs(urls) do
			local ok, res = pcall(function()
				local c = game:HttpGet(url)
				return c ~= "" and http:JSONDecode(c) or nil
			end)
			if ok and type(res) == "table" then
				local list = res.data or res
				for _, item in pairs(list) do
					local id = tonumber(item.id)
					if id and id > 0 and item.bundledItems and not seen[id] then
						seen[id] = true
						local nm = tostring(item.name or ("Animation_"..id))
						if byName[nm] then nm = nm.." ["..id.."]" end
						byName[nm] = {id = id, bundledItems = item.bundledItems}
						animItems[#animItems+1] = {name = nm, id = id}
					end
				end
			end
		end
	end

	local al
	local busy = false

	local function used()
		local s = {}
		for _, c in ipairs(cats) do
			local nm = sel[c[2]]
			if type(nm) == "string" and nm ~= "" and nm ~= "none" then s[nm] = true end
		end
		return s
	end

	local function bind_respawn()
		if animConn then return end
		animConn = lp.CharacterAdded:Connect(function(c)
			c:WaitForChild("Humanoid")
			local animate = c:WaitForChild("Animate", 5)
			task.wait(0.3)
			if enabled and animate then
				origMap = {}
				requestApply()
			end
		end)
	end

	local function drop_respawn()
		if animConn then pcall(function() animConn:Disconnect() end) animConn = nil end
	end

	local function wipe_anims()
		local _, hum, animate = getParts()
		stopTracks(hum)
		restore()
		refreshAnimate(animate, hum)
	end

	local function push_sel()
		if not al then return end
		local names = {}
		for nm in pairs(used()) do names[#names + 1] = nm end
		busy = true
		pcall(function() al:SetValue(names) end)
		busy = false
	end

	local function settle()
		if next(used()) ~= nil then
			enabled = true
			bind_respawn()
			requestApply()
		else
			enabled = false
			pendingApply = false
			applyToken += 1
			drop_respawn()
			wipe_anims()
		end
	end

	local function has_all(name)
		for _, c in ipairs(cats) do
			if sel[c[2]] ~= name then return false end
		end
		return true
	end

	local function assign(name, key, want)
		if key == "all" then
			for _, c in ipairs(cats) do
				if want then
					sel[c[2]] = name
				elseif sel[c[2]] == name then
					sel[c[2]] = nil
				end
			end
		else
			if want then
				sel[key] = name
			elseif sel[key] == name then
				sel[key] = nil
			end
		end
		push_sel()
		settle()
	end

	local function open_cats(name, x, y, cell)
		if not byName[name] then return end

		local rows = {
			{
				icon = "layers",
				name = "All",
				on = has_all(name),
				callback = function()
					assign(name, "all", not has_all(name))
					return has_all(name)
				end
			}
		}

		for _, c in ipairs(cats) do
			local key = c[2]
			rows[#rows + 1] = {
				icon = "circle-dot",
				name = c[1],
				on = sel[key] == name,
				callback = function()
					assign(name, key, sel[key] ~= name)
					return sel[key] == name
				end
			}
		end

		popmenu({ title = name, icon = "footprints", x = x, y = y, follow = cell, items = rows })
	end

	al = player_tab:AddImageList({
		Name = "animations",
		Icon = "footprints",
		Position = 'full',
		Multi = true,
		Thumb = "BundleThumbnail",
		Height = 300,
		Cell = 74,
		Tools = false,
		Empty = "loading bundles",
		Values = animItems,
		Flag = "player_anim_bundle",
		Action = {
			icon = "sliders-horizontal",
			callback = function(name, _, x, y, cell)
				open_cats(name, x, y, cell)
			end
		},
		Context = function(name, _, x, y, cell)
			open_cats(name, x, y, cell)
		end,
		Callback = function(v)
			if busy or os.clock() < selLockUntil then return end

			local names = {}
			if type(v) == "table" then
				for _, nm in ipairs(v) do
					if type(nm) == "string" and nm ~= "" then names[#names + 1] = nm end
				end
			elseif type(v) == "string" and v ~= "" then
				names[1] = v
			end

			local map = {}
			for i = 1, #names do map[names[i]] = true end

			local prev = used()

			for nm in next, map do
				if not prev[nm] then
					for _, c in ipairs(cats) do
						sel[c[2]] = nm
					end
				end
			end

			for nm in next, prev do
				if not map[nm] then
					for _, c in ipairs(cats) do
						if sel[c[2]] == nm then sel[c[2]] = nil end
					end
				end
			end

			push_sel()
			settle()
		end
	})

	lib:hook("player_anim_sel", "string", function()
		local ok, encoded = pcall(function() return http:JSONEncode(sel) end)
		return (ok and encoded) or "{}"
	end, function(v)
		local map = {}

		if type(v) == "table" then
			for k, name in pairs(v) do
				if type(k) == "string" and type(name) == "string" then map[k] = name end
			end
		elseif type(v) == "string" and v ~= "" then
			pcall(function()
				local decoded = http:JSONDecode(v)
				if type(decoded) == "table" then
					for k, name in pairs(decoded) do
						if type(k) == "string" and type(name) == "string" then map[k] = name end
					end
				end
			end)
		end

		selLockUntil = os.clock() + 0.35

		task.defer(function()
			sel = map
			push_sel()
			settle()
		end)
	end)

	task.spawn(function()
		fetchAll()
		fetched = true
		pcall(function() al:SetData(animItems) end)
		push_sel()
		if pendingApply then
			pendingApply = false
			requestApply()
		end
	end)

	getgenv().ANIM_UNLOAD = function()
		enabled = false
		pendingApply = false
		applyToken += 1
		pcall(function() lib:unhook("player_anim_sel") end)
		if animConn then pcall(function() animConn:Disconnect() end) animConn = nil end
		local _, hum, animate = getParts()
		stopTracks(hum)
		restore()
		if animate then
			pcall(function()
				animate.Disabled = true
				animate.Disabled = false
			end)
		end
	end
end
do

	local players, http = game:GetService("Players"), game:GetService("HttpService")
	local lp = players.LocalPlayer
	local emoteFile = "emotes.json"
	local statEmotes = {
		{"Griddy", "129149402922241"}
	}
	local custEmotes, emoteMap, emoteList, animCache = {}, {}, {}, {}
	local allList, allMap = {}, {}
	local curTrack, selId, custRaw, alive = nil, nil, nil, true

	local function parseCustom()
		if not (isfile and isfile(emoteFile)) then
			if custRaw ~= nil then custRaw, custEmotes = nil, {} return true end
			return false
		end
		local ok, raw = pcall(readfile, emoteFile)
		if not ok or raw == custRaw then return false end
		custRaw, custEmotes = raw, {}
		local dok, data = pcall(function() return http:JSONDecode(raw) end)
		if dok and type(data) == "table" then
			for k, v in pairs(data) do
				local name, id
				if type(v) == "table" then
					name, id = tostring(v.name or v[1] or k), tostring(v.id or v[2] or "")
				else
					name, id = tostring(k), tostring(v)
				end
				if name ~= "" and id ~= "" then
					custEmotes[#custEmotes+1] = {name, id}
				end
			end
		end
		return true
	end

	local function buildList()
		emoteMap, emoteList = {}, {}
		local function add(name, id)
			name = tostring(name)
			if emoteMap[name] then name = name.." ["..tostring(id).."]" end
			emoteMap[name] = tostring(id)
			emoteList[#emoteList+1] = {name = name, id = tonumber((tostring(id):gsub("%D", ""))) or id}
		end
		for _, e in ipairs(statEmotes) do
			add(e[1], e[2])
		end
		for _, e in ipairs(custEmotes) do
			add(e[1], e[2])
		end
		for _, e in ipairs(allList) do
			add(e.name, e.id)
		end
	end

	parseCustom()
	buildList()

	local function getHum()
		local char = lp.Character
		return char and char:FindFirstChildOfClass("Humanoid")
	end

	local function stopEmote()
		if curTrack then
			pcall(function() curTrack:Stop() end)
			curTrack = nil
		end
	end

	local function resolveId(id)
		if animCache[id] then return animCache[id] end
		if id:find("://") then animCache[id] = id return id end
		local raw = id:gsub("%D", "")
		local ok, objs = pcall(game.GetObjects, game, "rbxassetid://"..raw)
		if ok and type(objs) == "table" then
			local found
			local function scan(inst)
				if found then return end
				if inst:IsA("Animation") and inst.AnimationId ~= "" then
					found = inst.AnimationId
					return
				end
				for _, c in ipairs(inst:GetChildren()) do scan(c) end
			end
			for _, o in ipairs(objs) do scan(o) pcall(function() o:Destroy() end) end
			if found then animCache[id] = found return found end
		end
		local url = "rbxassetid://"..raw
		animCache[id] = url
		return url
	end

	local function playEmote()
		local hum = getHum()
		if not hum or not selId then return end
		stopEmote()
		local anim = Instance.new("Animation")
		anim.AnimationId = resolveId(selId)
		local ok, track = pcall(function() return hum:LoadAnimation(anim) end)
		anim:Destroy()
		if ok and track then
			track.Priority = Enum.AnimationPriority.Action
			track.Looped = true
			track:Play()
			curTrack = track
		end
	end

	local el

	el = emote_page:AddImageList({
		Name = "emotes",
		Icon = "video",
		Position = 'full',
		Thumb = "Asset",
		Height = 300,
		Cell = 74,
		Reset = true,
		Tools = false,
		Empty = "loading emotes",
		Values = emoteList,
		Flag = "player_emote_library",
		Callback = function(v)
			local name = type(v) == "table" and v.name or v

			if type(name) ~= "string" or name == "" then
				selId = nil
				stopEmote()

				return
			end

			selId = emoteMap[name]

			if selId then
				playEmote()
			else
				stopEmote()
			end
		end
	})

	local function refresh()
		if parseCustom() then
			buildList()
			pcall(function() el:SetData(emoteList) end)
		end
	end

	local function fetchEmotes()
		local ok, res = pcall(function()
			local c = game:HttpGet("https://raw.githubusercontent.com/7yd7/sniper-Emote/refs/heads/test/EmoteSniper.json")
			return c ~= "" and http:JSONDecode(c) or nil
		end)
		if ok and type(res) == "table" then
			local list = res.data or res
			local seen = {}
			for _, item in pairs(list) do
				local id = tonumber(item.id)
				if id and id > 0 and not seen[id] then
					seen[id] = true
					local nm = tostring(item.name or ("Emote_"..id))
					if allMap[nm] then nm = nm.." ["..id.."]" end
					allMap[nm] = tostring(id)
					allList[#allList+1] = {name = nm, id = id}
				end
			end
		end
	end

	task.spawn(function()
		fetchEmotes()
		buildList()
		pcall(function() el:SetData(emoteList) end)
	end)

	local char_conn = lp.CharacterAdded:Connect(function()
		task.wait(1)
		if selId then playEmote() end
	end)

	task.spawn(function()
		while alive and task.wait(3) do
			refresh()
		end
	end)

	getgenv().EMOTE_UNLOAD = function()
		alive, selId = false, nil
		stopEmote()
		if char_conn then pcall(function() char_conn:Disconnect() end) char_conn = nil end
	end
end
end

do
	local players = game:GetService("Players")
	local run = game:GetService("RunService")
	local ws = workspace
	local lp = players.LocalPlayer

	local sel_map, sel_order = {}, {}
	local busy = false
	local primary = nil
	local plist, info = nil, nil
	local fling_on, spectate_on, looptp_on = false, false, false
	local headsit_on, bang_on = false, false
	local bang_speed = 3
	local fling_bypass_velocity = false
	local bang_track, bang_anim, bang_hum = nil, nil, nil
	local tpx, tpy, tpz = 0, 0, 0

	local function my_hrp()
		local c = lp.Character
		return c and c:FindFirstChild("HumanoidRootPart")
	end
	local function tgt_hrp(plr)
		local c = plr and plr.Character
		return c and (c:FindFirstChild("HumanoidRootPart") or c:FindFirstChild("Head"))
	end
	local function tp_root(cf)
		if getgenv().SHITARO_TELEPORT and getgenv().SHITARO_TELEPORT(cf) then return end
		local hrp = my_hrp()
		if hrp then hrp.CFrame = cf end
	end
	local function player_list(excl)
		local t = {}
		for _, p in ipairs(players:GetPlayers()) do
			if p ~= lp and p ~= excl then
				t[#t + 1] = { name = p.Name, display = p.DisplayName, id = p.UserId }
			end
		end
		return t
	end

	local function label_for(name)
		if not name then return "none" end
		local p = players:FindFirstChild(name)
		return (p and p.DisplayName) or name
	end

	local function modes()
		local t = {}
		if spectate_on then t[#t + 1] = "spec" end
		if headsit_on then t[#t + 1] = "sit" end
		if bang_on then t[#t + 1] = "bang" end
		if looptp_on then t[#t + 1] = "tp" end
		if #t == 0 then return "" end
		return " [" .. table.concat(t, " ") .. "]"
	end

	local function sync_info()
		if not info then return end
		local n = #sel_order
		if n == 0 then
			info:SetValue("target: none")
		elseif n == 1 then
			info:SetValue("target: " .. label_for(primary) .. modes())
		else
			info:SetValue("target: " .. label_for(primary) .. " (+" .. (n - 1) .. ")" .. modes())
		end
	end

	local function push(names)
		busy = true
		pcall(function() plist:SetValue(names) end)
		busy = false
	end

	local function commit(names)
		local map = {}
		for i = 1, #names do map[names[i]] = true end

		for i = #sel_order, 1, -1 do
			if not map[sel_order[i]] then table.remove(sel_order, i) end
		end

		for i = 1, #names do
			if not sel_map[names[i]] then sel_order[#sel_order + 1] = names[i] end
		end

		sel_map = map

		if not primary or not players:FindFirstChild(primary) then
			primary = sel_order[#sel_order]
		end

		sync_info()
	end

	local function on_pick(v)
		if busy then return end

		local names = {}
		if type(v) == "table" then
			for _, nm in ipairs(v) do
				if type(nm) == "string" and nm ~= "" then names[#names + 1] = nm end
			end
		elseif type(v) == "string" and v ~= "" then
			names[1] = v
		end

		commit(names)
	end

	local open_ctx = nil

	plist = target_tab:AddImageList({
		Name = "players",
		Icon = "users",
		Position = 'left',
		Multi = true,
		Thumb = "AvatarHeadShot",
		Height = 262,
		Cell = 62,
		Empty = "nobody around",
		Default = {},
		Values = {},
		Tools = false,
		Flag = "target_players",
		Action = {
			icon = "ellipsis",
			callback = function(name, _, x, y, cell)
				if open_ctx then open_ctx(name, x, y, cell) end
			end
		},
		Context = function(name, _, x, y, cell)
			if open_ctx then open_ctx(name, x, y, cell) end
		end,
		Callback = on_pick
	})

	local ss = target_tab:AddSection({
		Name = "actions",
		Position = 'right'
	})

	local ts = ss

	info = ss:AddLabel("target: none", false)

	local function refresh_lists(excl)
		local plrs = player_list(excl)
		local keep = {}
		for i = 1, #plrs do keep[plrs[i].name] = true end
		for i = #sel_order, 1, -1 do
			if not keep[sel_order[i]] then
				sel_map[sel_order[i]] = nil
				table.remove(sel_order, i)
			end
		end
		if primary and not players:FindFirstChild(primary) then
			primary = nil
		end
		if not primary then
			primary = sel_order[#sel_order]
		end
		pcall(function() plist:SetData(plrs) end)
		sync_info()
	end

	local add_conn = players.PlayerAdded:Connect(function() refresh_lists() end)
	local rem_conn = players.PlayerRemoving:Connect(function(p) refresh_lists(p) end)
	refresh_lists()

	local function do_fling(tp)
		if not tp or not tp.Character then return end
		local hrp = my_hrp()
		local hum = lp.Character and lp.Character:FindFirstChildOfClass("Humanoid")
		if not hrp then return end
		local tc = tp.Character
		local thrp = tc:FindFirstChild("HumanoidRootPart") or tc:FindFirstChild("Head")
		local th = tc:FindFirstChildOfClass("Humanoid")
		if not thrp then return end
		getgenv().FLING_ACTIVE = (getgenv().FLING_ACTIVE or 0) + 1
		if hrp.Velocity.Magnitude < 50 then
			getgenv().OldPos = hrp.CFrame
		end
		if th and th.Sit then
			getgenv().FLING_ACTIVE = math.max(0, (getgenv().FLING_ACTIVE or 1) - 1)
			return
		end
		local camera = ws.CurrentCamera
		local old_fdh = ws.FallenPartsDestroyHeight
		if thrp then
			camera.CameraSubject = thrp
		elseif th then
			camera.CameraSubject = th
		end
		pcall(function() ws.FallenPartsDestroyHeight = 0/0 end)
		local bv = Instance.new("BodyVelocity")
		bv.Parent = hrp
		bv.Velocity = Vector3.new(0, 0, 0)
		bv.MaxForce = Vector3.new(9e9, 9e9, 9e9)
		local se = hum and hum:GetStateEnabled(Enum.HumanoidStateType.Seated)
		if hum then hum:SetStateEnabled(Enum.HumanoidStateType.Seated, false) end
		local tw = 2
		local tm = tick()
		local ang = 0
		repeat
			if hrp and th then
				local tv
				if fling_bypass_velocity then
					tv = th.MoveDirection * th.WalkSpeed
				else
					tv = thrp.Velocity
				end
				if tv.Magnitude < 50 then
					ang = ang + 100
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, 1.5, 0) + th.MoveDirection * tv.Magnitude / 1.25
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(ang), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, -1.5, 0) + th.MoveDirection * tv.Magnitude / 1.25
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(ang), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, 1.5, 0) + th.MoveDirection * tv.Magnitude / 1.25
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(ang), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, -1.5, 0) + th.MoveDirection * tv.Magnitude / 1.25
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(ang), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, 1.5, 0) + th.MoveDirection
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(ang), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, -1.5, 0) + th.MoveDirection
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(ang), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
				else
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, 1.5, th.WalkSpeed)
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(90), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, -1.5, -th.WalkSpeed)
					hrp.CFrame = hrp.CFrame * CFrame.Angles(0, 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, 1.5, th.WalkSpeed)
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(90), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, -1.5, 0)
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(90), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, -1.5, 0)
					hrp.CFrame = hrp.CFrame * CFrame.Angles(0, 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, -1.5, 0)
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(90), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, -1.5, 0)
					hrp.CFrame = hrp.CFrame * CFrame.Angles(0, 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
				end
			end
		until tm + tw < tick() or not fling_on
		if bv then bv:Destroy() end
		if hum and se ~= nil then hum:SetStateEnabled(Enum.HumanoidStateType.Seated, se) end
		camera.CameraSubject = hum
		if getgenv().OldPos and hrp then
			hrp.CFrame = getgenv().OldPos * CFrame.new(0, 0.5, 0)
			lp.Character:SetPrimaryPartCFrame(getgenv().OldPos * CFrame.new(0, 0.5, 0))
			if hum then hum:ChangeState("GettingUp") end
			for _, part in pairs(lp.Character:GetChildren()) do
				if part:IsA("BasePart") then
					part.Velocity = Vector3.new()
					part.RotVelocity = Vector3.new()
				end
			end
			pcall(function() ws.FallenPartsDestroyHeight = old_fdh end)
		end
		getgenv().FLING_ACTIVE = math.max(0, (getgenv().FLING_ACTIVE or 1) - 1)
	end

	local function selected_present()
		local list, seen = {}, {}
		for i = 1, #sel_order do
			local name = sel_order[i]
			if not seen[name] then
				local p = players:FindFirstChild(name)
				if p and p ~= lp then
					seen[name] = true
					list[#list + 1] = p
				end
			end
		end
		return list
	end

	local fling_thread = nil
	local function start_fling()
		if fling_thread then return end
		fling_thread = task.spawn(function()
			while fling_on do
				local list = selected_present()
				if #list == 0 then
					task.wait(0.3)
				else
					for i = 1, #list do
						if not fling_on then break end
						local tp = list[i]
						if tp and tp.Parent and tp.Character then
							if my_hrp() then
								do_fling(tp)
							else
								task.wait(0.2)
							end
						end
					end
					task.wait()
				end
			end
			fling_thread = nil
		end)
	end

	local tsssss = ts:AddToggle({
		Name = "fling",
		Default = false,
		Option = true,
		Flag = "Fling Targets",
		Callback = function(v)
			fling_on = v
			if v then start_fling() end
		end
	})

	tsssss.Option:AddToggle({
		Name = "velocity check",
		Default = false,
		Flag = "Fling Bypass(targets)",
		Callback = function(v)
			fling_bypass_velocity = v
		end
	})

	local rs = game:GetService("ReplicatedStorage")

	local kill_round_mod = nil

	local function kill_require_round()
		return require(rs:WaitForChild("Modules"):WaitForChild("CurrentRoundClient"))
	end

	local function kill_data()
		if not kill_round_mod then
			local ok, m = pcall(kill_require_round)
			if not ok or type(m) ~= "table" then return nil end
			kill_round_mod = m
		end
		return kill_round_mod.PlayerData
	end

	local function target_killable(data, plr)
		local info = data and data[plr.Name]
		if type(info) ~= "table" then return false end
		if info.Dead then return false end
		return info.Role == "Innocent" or info.Role == "Sheriff" or info.Role == "Hero"
	end

	local function get_kill_knife()
		local char = lp.Character
		if char then
			local equipped = char:FindFirstChild("Knife")
			if equipped then return equipped, true end
		end
		local bp = lp:FindFirstChildOfClass("Backpack")
		if bp then
			local stored = bp:FindFirstChild("Knife")
			if stored then return stored, false end
		end
		return nil, false
	end

	local function ensure_kill_knife()
		local knife, equipped = get_kill_knife()
		if not knife then return nil end
		if not equipped then
			local hum = lp.Character and lp.Character:FindFirstChildOfClass("Humanoid")
			if hum then pcall(function() hum:EquipTool(knife) end) end
			return nil
		end
		return knife
	end

	local function kill_stab(knife)
		local events = knife:FindFirstChild("Events")
		local stabbed = events and events:FindFirstChild("KnifeStabbed")
		if stabbed then pcall(function() stabbed:FireServer() end) end
	end

	local function kill_touch(knife, part)
		local events = knife:FindFirstChild("Events")
		local touched = events and events:FindFirstChild("HandleTouched")
		if touched then pcall(function() touched:FireServer(part) end) end
	end

	local kill_on = false
	local last_target_kill = 0
	local kill_thread = nil
	local function start_kill()
		if kill_thread then return end
		kill_thread = task.spawn(function()
			while kill_on do
				local data = kill_data()
				local me = data and data[lp.Name]
				if not (me ~= nil and me.Role == "Murderer" and not me.Dead) then
					task.wait(0.3)
					continue
				end
				if getgenv().AUTOFARM_HOLD then
					task.wait()
					continue
				end
				local knife = ensure_kill_knife()
				if not knife then
					task.wait(0.1)
					continue
				end
				if os.clock() - last_target_kill < 0.05 then
					task.wait()
					continue
				end
				local list = selected_present()
				local victims = {}
				for i = 1, #list do
					local plr = list[i]
					if target_killable(data, plr) then
						local tc = plr.Character
						local hum = tc and tc:FindFirstChildOfClass("Humanoid")
						local part = tc and (tc:FindFirstChild("HumanoidRootPart") or tc:FindFirstChild("Head"))
						if hum and hum.Health > 0 and part then
							victims[#victims + 1] = part
						end
					end
				end
				if #victims > 0 then
					kill_stab(knife)
					for _, part in ipairs(victims) do
						kill_touch(knife, part)
					end
					last_target_kill = os.clock()
				end
				task.wait()
			end
			kill_thread = nil
		end)
	end

	ts:AddToggle({
		Name = "kill",
		Default = false,
		Flag = "Kill Targets",
		Callback = function(v)
			kill_on = v
			if v then start_kill() end
		end
	})

	local function cur_target()
		local name = primary or sel_order[#sel_order]
		if not name or name == "" then return nil end
		local p = players:FindFirstChild(name)
		if p and p ~= lp then return p end
	end

	local spec_conn = run.RenderStepped:Connect(function()
		if not spectate_on then return end
		local tp = cur_target()
		local thrp = tgt_hrp(tp)
		local th = tp and tp.Character and tp.Character:FindFirstChildOfClass("Humanoid")
		if thrp then
			ws.CurrentCamera.CameraSubject = th or thrp
		end
	end)

	local looptp_conn = run.Heartbeat:Connect(function()
		if not looptp_on then return end
		local thrp = tgt_hrp(cur_target())
		local hrp = my_hrp()
		if thrp and hrp then
			tp_root(thrp.CFrame + Vector3.new(tpx, tpy, tpz))
		end
	end)

	local function my_hum()
		local c = lp.Character
		return c and c:FindFirstChildOfClass("Humanoid")
	end

	local function is_r15(char)
		local h = char and char:FindFirstChildOfClass("Humanoid")
		return h ~= nil and h.RigType == Enum.HumanoidRigType.R15
	end

	local headsit_conn = run.Heartbeat:Connect(function()
		if not headsit_on then return end
		local thrp = tgt_hrp(cur_target())
		local hrp = my_hrp()
		local hum = my_hum()
		if thrp and hrp and hum then
			hum.Sit = true
			hrp.CFrame = thrp.CFrame * CFrame.new(0, 1.6, 0.4)
		end
	end)

	local function ensure_bang_anim()
		local hum = my_hum()
		if not hum then return end
		if bang_hum == hum and bang_track then return end
		if bang_track then pcall(function() bang_track:Stop() end) bang_track = nil end
		if bang_anim then pcall(function() bang_anim:Destroy() end) bang_anim = nil end
		bang_anim = Instance.new("Animation")
		bang_anim.AnimationId = is_r15(lp.Character) and "rbxassetid://5918726674" or "rbxassetid://148840371"
		local ok, tr = pcall(function() return hum:LoadAnimation(bang_anim) end)
		if ok and tr then
			bang_track = tr
			bang_track.Looped = true
			bang_track:Play(0.1, 1, 1)
			bang_track:AdjustSpeed(bang_speed)
			bang_hum = hum
		end
	end

	local function stop_bang()
		if bang_track then pcall(function() bang_track:Stop() end) bang_track = nil end
		if bang_anim then pcall(function() bang_anim:Destroy() end) bang_anim = nil end
		bang_hum = nil
	end

	local bang_conn = run.Stepped:Connect(function()
		if not bang_on then return end
		ensure_bang_anim()
		local thrp = tgt_hrp(cur_target())
		local hrp = my_hrp()
		if thrp and hrp then
			hrp.CFrame = thrp.CFrame * CFrame.new(0, 0, 1.1)
		end
	end)

	local function stop_spectate()
		local myh = lp.Character and lp.Character:FindFirstChildOfClass("Humanoid")
		if myh then ws.CurrentCamera.CameraSubject = myh end
	end

	local function aim_at(name)
		primary = name
		sync_info()
	end

	local function tune(name, key, want)
		aim_at(name)

		if key == "spectate" then
			spectate_on = want
			if not want then stop_spectate() end
		elseif key == "headsit" then
			headsit_on = want
			if not want then
				local hum = my_hum()
				if hum then hum.Sit = false end
			end
		elseif key == "bang" then
			bang_on = want
			if want then ensure_bang_anim() else stop_bang() end
		elseif key == "looptp" then
			looptp_on = want
		end

		sync_info()

		return want
	end

	open_ctx = function(name, x, y, cell)
		local plr = players:FindFirstChild(name)
		if not plr or plr == lp then return end

		local live = primary == name

		popmenu({
			title = plr.DisplayName,
			icon = "user",
			x = x,
			y = y,
			follow = cell,
			items = {
				{
					icon = "map-pin",
					name = "teleport",
					callback = function()
						aim_at(name)
						local thrp = tgt_hrp(plr)
						local hrp = my_hrp()
						if thrp and hrp then
							tp_root(thrp.CFrame + Vector3.new(tpx, tpy, tpz))
						end
					end
				},
				{
					icon = "crosshair",
					name = "set",
					callback = function()
						aim_at(name)
					end
				},
				{
					icon = "video",
					name = "spectate",
					on = live and spectate_on,
					callback = function()
						return tune(name, "spectate", not (primary == name and spectate_on))
					end
				},
				{
					icon = "person-standing",
					name = "headsit",
					on = live and headsit_on,
					callback = function()
						return tune(name, "headsit", not (primary == name and headsit_on))
					end
				},
				{
					icon = "heart",
					name = "bang",
					on = live and bang_on,
					callback = function()
						return tune(name, "bang", not (primary == name and bang_on))
					end
				},
				{
					icon = "move",
					name = "loop tp",
					on = live and looptp_on,
					callback = function()
						return tune(name, "looptp", not (primary == name and looptp_on))
					end
				},
			}
		})
	end

	ss:AddSlider({
		Name = "bang speed",
		Default = 3,
		Min = 1,
		Max = 10,
		Round = 1,
		Flag = "target_bang_speed",
		Callback = function(v)
			bang_speed = v
			if bang_track then pcall(function() bang_track:AdjustSpeed(bang_speed) end) end
		end
	})

	ss:AddSlider({ Name = "x", Default = 0, Min = 0, Max = 5, Round = 1, Flag = "target_tp_x", Callback = function(v) tpx = v end })
	ss:AddSlider({ Name = "y", Default = 0, Min = 0, Max = 5, Round = 1, Flag = "target_tp_y", Callback = function(v) tpy = v end })
	ss:AddSlider({ Name = "z", Default = 0, Min = 0, Max = 5, Round = 1, Flag = "target_tp_z", Callback = function(v) tpz = v end })

	

	getgenv().TARGET_UNLOAD = function()
		fling_on, spectate_on, looptp_on = false, false, false
		headsit_on, bang_on = false, false
		kill_on = false
		if add_conn then pcall(function() add_conn:Disconnect() end) add_conn = nil end
		if rem_conn then pcall(function() rem_conn:Disconnect() end) rem_conn = nil end
		if spec_conn then pcall(function() spec_conn:Disconnect() end) spec_conn = nil end
		if looptp_conn then pcall(function() looptp_conn:Disconnect() end) looptp_conn = nil end
		if headsit_conn then pcall(function() headsit_conn:Disconnect() end) headsit_conn = nil end
		if bang_conn then pcall(function() bang_conn:Disconnect() end) bang_conn = nil end
		pcall(stop_bang)
		local myh = lp.Character and lp.Character:FindFirstChildOfClass("Humanoid")
		if myh then pcall(function() myh.Sit = false end) end
		pcall(function() ws.FallenPartsDestroyHeight = -500 end)
		if myh then pcall(function() ws.CurrentCamera.CameraSubject = myh end) end
	end
end

do
	local players = game:GetService("Players")
	local run = game:GetService("RunService")
	local ws = workspace
	local lp = players.LocalPlayer

	local function my_hrp()
		local c = lp.Character
		return c and c:FindFirstChild("HumanoidRootPart")
	end

	local function break_velocity()
		local hrp = my_hrp()
		if hrp then
			hrp.AssemblyLinearVelocity = Vector3.zero
			hrp.AssemblyAngularVelocity = Vector3.zero
		end
	end

	local function tp_root(cf)
		if getgenv().SHITARO_TELEPORT and getgenv().SHITARO_TELEPORT(cf) then return end
		local hrp = my_hrp()
		if hrp then hrp.CFrame = cf end
	end

	local function do_fling(tp)
		if not tp or not tp.Character then return end
		local hrp = my_hrp()
		local hum = lp.Character and lp.Character:FindFirstChildOfClass("Humanoid")
		if not hrp then return end
		local tc = tp.Character
		local thrp = tc:FindFirstChild("HumanoidRootPart") or tc:FindFirstChild("Head")
		local th = tc:FindFirstChildOfClass("Humanoid")
		if not thrp then return end
		getgenv().FLING_ACTIVE = (getgenv().FLING_ACTIVE or 0) + 1
		if hrp.Velocity.Magnitude < 50 then
			getgenv().OldPos = hrp.CFrame
		end
		if th and th.Sit then
			getgenv().FLING_ACTIVE = math.max(0, (getgenv().FLING_ACTIVE or 1) - 1)
			return
		end
		local camera = ws.CurrentCamera
		local old_fdh = ws.FallenPartsDestroyHeight
		if thrp then
			camera.CameraSubject = thrp
		elseif th then
			camera.CameraSubject = th
		end
		pcall(function() ws.FallenPartsDestroyHeight = 0/0 end)
		local bv = Instance.new("BodyVelocity")
		bv.Parent = hrp
		bv.Velocity = Vector3.new(0, 0, 0)
		bv.MaxForce = Vector3.new(9e9, 9e9, 9e9)
		local se = hum and hum:GetStateEnabled(Enum.HumanoidStateType.Seated)
		if hum then hum:SetStateEnabled(Enum.HumanoidStateType.Seated, false) end
		local tw = 2
		local tm = tick()
		local ang = 0
		local active = true
		repeat
			if hrp and th then
				local tv
				if fling_tool_bypass_velocity then
					tv = th.MoveDirection * th.WalkSpeed
				else
					tv = thrp.Velocity
				end
				if tv.Magnitude < 50 then
					ang = ang + 100
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, 1.5, 0) + th.MoveDirection * tv.Magnitude / 1.25
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(ang), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, -1.5, 0) + th.MoveDirection * tv.Magnitude / 1.25
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(ang), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, 1.5, 0) + th.MoveDirection * tv.Magnitude / 1.25
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(ang), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, -1.5, 0) + th.MoveDirection * tv.Magnitude / 1.25
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(ang), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, 1.5, 0) + th.MoveDirection
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(ang), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, -1.5, 0) + th.MoveDirection
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(ang), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
				else
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, 1.5, th.WalkSpeed)
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(90), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, -1.5, -th.WalkSpeed)
					hrp.CFrame = hrp.CFrame * CFrame.Angles(0, 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, 1.5, th.WalkSpeed)
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(90), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, -1.5, 0)
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(90), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, -1.5, 0)
					hrp.CFrame = hrp.CFrame * CFrame.Angles(0, 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, -1.5, 0)
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(90), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, -1.5, 0)
					hrp.CFrame = hrp.CFrame * CFrame.Angles(0, 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
				end
			end
		until tm + tw < tick() or not active
		if bv then bv:Destroy() end
		if hum and se ~= nil then hum:SetStateEnabled(Enum.HumanoidStateType.Seated, se) end
		camera.CameraSubject = hum
		if getgenv().OldPos and hrp then
			hrp.CFrame = getgenv().OldPos * CFrame.new(0, 0.5, 0)
			lp.Character:SetPrimaryPartCFrame(getgenv().OldPos * CFrame.new(0, 0.5, 0))
			if hum then hum:ChangeState("GettingUp") end
			for _, part in pairs(lp.Character:GetChildren()) do
				if part:IsA("BasePart") then
					part.Velocity = Vector3.new()
					part.RotVelocity = Vector3.new()
				end
			end
			pcall(function() ws.FallenPartsDestroyHeight = old_fdh end)
		end
		getgenv().FLING_ACTIVE = math.max(0, (getgenv().FLING_ACTIVE or 1) - 1)
	end

	local tp_on = false
	local tp_tool = nil
	local tp_act_conn = nil
	local tp_add_conn = nil

	local function give_tp_tool()
		if not tp_on then return end
		local bp = lp:FindFirstChildOfClass("Backpack")
		if not bp then return end
		local existing = bp:FindFirstChild("tp")
		if not existing and lp.Character then existing = lp.Character:FindFirstChild("tp") end
		if existing then
			tp_tool = existing
			return
		end
		if tp_act_conn then pcall(function() tp_act_conn:Disconnect() end) tp_act_conn = nil end
		tp_tool = Instance.new("Tool")
		tp_tool.Name = "tp"
		tp_tool.RequiresHandle = false
		tp_tool.CanBeDropped = false
		tp_tool.Parent = bp
		tp_act_conn = tp_tool.Activated:Connect(function()
			local root = my_hrp()
			local m = lp:GetMouse()
			local pos = m.Hit
			if not root or not pos then return end
			tp_root(CFrame.new(pos.X, pos.Y + 3, pos.Z, select(4, root.CFrame:components())))
			break_velocity()
		end)
	end

	local function remove_tp_tool()
		if tp_act_conn then pcall(function() tp_act_conn:Disconnect() end) tp_act_conn = nil end
		if tp_tool then pcall(function() tp_tool:Destroy() end) tp_tool = nil end
		local bp = lp:FindFirstChildOfClass("Backpack")
		if bp then local t = bp:FindFirstChild("tp") if t then pcall(function() t:Destroy() end) end end
		local c = lp.Character
		if c then local t = c:FindFirstChild("tp") if t then pcall(function() t:Destroy() end) end end
	end

	getgenv().__PLR_QUEUE("tools", "tp tool", function(target)
		target:AddToggle({
			Name = "tp tool",
			Default = false,
			Flag = "Tp Tool",
			Callback = function(v)
				tp_on = v
				if v then
					give_tp_tool()
					if not tp_add_conn then
						tp_add_conn = lp.CharacterAdded:Connect(function()
							task.wait(0.5)
							if tp_on then give_tp_tool() end
						end)
					end
				else
					if tp_add_conn then pcall(function() tp_add_conn:Disconnect() end) tp_add_conn = nil end
					remove_tp_tool()
				end
			end
		})
	end)

	local fling_on = false
	local fling_tool = nil
	local fling_act_conn = nil
	local fling_add_conn = nil
	local fling_tool_bypass_velocity = false

	local function clicked_player()
		local m = lp:GetMouse()
		local target = m.Target
		if target then
			local node = target
			while node and node ~= ws do
				local p = players:GetPlayerFromCharacter(node)
				if p and p ~= lp then return p end
				node = node.Parent
			end
		end
		local cam = ws.CurrentCamera
		local mp = Vector2.new(m.X, m.Y)
		local best, bestd = nil, 110
		for _, p in ipairs(players:GetPlayers()) do
			if p ~= lp and p.Character then
				local hrp = p.Character:FindFirstChild("HumanoidRootPart") or p.Character:FindFirstChild("Head")
				if hrp then
					local sp, on = cam:WorldToViewportPoint(hrp.Position)
					if on then
						local d = (Vector2.new(sp.X, sp.Y) - mp).Magnitude
						if d < bestd then bestd = d best = p end
					end
				end
			end
		end
		return best
	end

	local function give_fling_tool()
		if not fling_on then return end
		local bp = lp:FindFirstChildOfClass("Backpack")
		if not bp then return end
		local existing = bp:FindFirstChild("fling")
		if not existing and lp.Character then existing = lp.Character:FindFirstChild("fling") end
		if existing then
			fling_tool = existing
			return
		end
		if fling_act_conn then pcall(function() fling_act_conn:Disconnect() end) fling_act_conn = nil end
		fling_tool = Instance.new("Tool")
		fling_tool.Name = "fling"
		fling_tool.RequiresHandle = false
		fling_tool.CanBeDropped = false
		fling_tool.Parent = bp
		fling_act_conn = fling_tool.Activated:Connect(function()
			local tp = clicked_player()
			if tp and my_hrp() then
				do_fling(tp)
			end
		end)
	end

	local function remove_fling_tool()
		if fling_act_conn then pcall(function() fling_act_conn:Disconnect() end) fling_act_conn = nil end
		if fling_tool then pcall(function() fling_tool:Destroy() end) fling_tool = nil end
		local bp = lp:FindFirstChildOfClass("Backpack")
		if bp then local t = bp:FindFirstChild("fling") if t then pcall(function() t:Destroy() end) end end
		local c = lp.Character
		if c then local t = c:FindFirstChild("fling") if t then pcall(function() t:Destroy() end) end end
	end

	getgenv().__PLR_QUEUE("tools", "fling tool", function(target)
		local ttlttltl = target:AddToggle({
			Name = "fling tool",
			Default = false,
			Option = true,
			Flag = "Fling Tool",
			Callback = function(v)
				fling_on = v
				if v then
					give_fling_tool()
					if not fling_add_conn then
						fling_add_conn = lp.CharacterAdded:Connect(function()
							task.wait(0.5)
							if fling_on then give_fling_tool() end
						end)
					end
				else
					if fling_add_conn then pcall(function() fling_add_conn:Disconnect() end) fling_add_conn = nil end
					remove_fling_tool()
				end
			end
		})

		ttlttltl.Option:AddToggle({
			Name = "bypass velocity",
			Default = false,
			Flag = "Fling Bypass(tool)",
			Callback = function(v)
				fling_tool_bypass_velocity = v
			end
		})
	end)

	local function in_lobby(obj)
		local p = obj.Parent
		while p and p ~= ws do
			if p.Name == "RegularLobby" or p.Name == "Lobby" then return true end
			p = p.Parent
		end
		return false
	end

	local function stable_tp(cf)
		tp_root(cf)
		if getgenv().FAKE_POS_ACTIVE then return end
		task.spawn(function()
			local hrp = my_hrp()
			if not hrp then return end
			local t = os.clock()
			while os.clock() - t < 0.25 and hrp.Parent do
				pcall(function()
					hrp.AssemblyLinearVelocity = Vector3.zero
					hrp.AssemblyAngularVelocity = Vector3.zero
				end)
				task.wait()
			end
		end)
	end

	local function teleport_to_map()
		local root = my_hrp()
		if not root then return end
		local spawnParts = {}
		for _, obj in ipairs(ws:GetDescendants()) do
			if (obj:IsA("SpawnLocation") or (obj:IsA("BasePart") and obj.Name == "Spawn")) and not in_lobby(obj) then
				spawnParts[#spawnParts + 1] = obj
			end
		end
		if #spawnParts > 0 then
			local rspawn = spawnParts[math.random(1, #spawnParts)]
			stable_tp(rspawn.CFrame + Vector3.new(0, 5, 0))
		end
	end

	local function teleport_to_lobby()
		local root = my_hrp()
		if not root then return end
		local lobby = ws:FindFirstChild("RegularLobby") or ws:FindFirstChild("Lobby")
		if not lobby then return end
		local locs = {}
		for _, obj in ipairs(lobby:GetDescendants()) do
			if obj:IsA("SpawnLocation") or (obj:IsA("BasePart") and obj.Name == "Spawn") then
				locs[#locs + 1] = obj
			end
		end
		if #locs > 0 then
			local rspawn = locs[math.random(1, #locs)]
			stable_tp(rspawn.CFrame + Vector3.new(0, 3, 0))
		else
			local ok, pivot = pcall(function() return lobby:GetPivot() end)
			if ok then stable_tp(pivot + Vector3.new(0, 5, 0)) end
		end
	end

	getgenv().__PLR_QUEUE("tools", "teleport to map", function(target)
		target:AddButton({
			Name = "lobby",
			Callback = teleport_to_lobby
		})

		target:AddButton({
			Name = "teleport to map",
			Callback = teleport_to_map
		})
	end)

	getgenv().MISC_TOOLS_UNLOAD = function()
		tp_on, fling_on = false, false
		if tp_add_conn then pcall(function() tp_add_conn:Disconnect() end) tp_add_conn = nil end
		if fling_add_conn then pcall(function() fling_add_conn:Disconnect() end) fling_add_conn = nil end
		remove_tp_tool()
		remove_fling_tool()
	end
end

do
	local players = game:GetService("Players")
	local rs = game:GetService("ReplicatedStorage")
	local lp = players.LocalPlayer

	local notify_on = false
	local miss_on, kill_on, roles_on = false, false, false

	local ICON_MISS = "rbxassetid://74115333842618"
	local ICON_KILL = "rbxassetid://86817768619372"
	local ICON_ROLE = "rbxassetid://84691420588185"

	local last_role = nil
	local gun_conn = nil
	local hooked_gun = nil
	local cur_murderer_name = nil
	local killed_flag = false
	local last_miss = 0

	local notify_round_mod = nil

	local function notify_require_round()
		return require(rs:WaitForChild("Modules"):WaitForChild("CurrentRoundClient"))
	end

	local function get_data()
		if not notify_round_mod then
			local ok, m = pcall(notify_require_round)
			if not ok or type(m) ~= "table" then return nil end
			notify_round_mod = m
		end
		return notify_round_mod.PlayerData
	end

	local function lp_has_gun()
		local char = lp.Character
		if char and char:FindFirstChild("Gun") then return true end
		local bp = lp:FindFirstChildOfClass("Backpack")
		if bp and bp:FindFirstChild("Gun") then return true end
		return false
	end

	local function my_role()
		local d = get_data()
		local me = d and d[lp.Name]
		local role = me and me.Role
		if role == "Sheriff" or role == "Hero" then return role end
		if lp_has_gun() then return "Hero" end
		return role
	end

	local function murderer_player()
		local d = get_data()
		if type(d) ~= "table" then return nil end
		for name, info in pairs(d) do
			if type(info) == "table" and info.Role == "Murderer" then
				return players:FindFirstChild(name)
			end
		end
		return nil
	end

	local function push(text, icon)
		if event_notify then
			pcall(function()
				event_notify:Notify({ Title = text, Icon = icon, Duration = 4 })
			end)
		end
	end

	task.spawn(function()
		while task.wait(0.4) do
			if not (notify_on and roles_on) then
				continue
			end
			local r = my_role()
			if r and r ~= last_role then
				last_role = r
				push("You are now "..tostring(r), ICON_ROLE)
			elseif not r then
				last_role = nil
			end
		end
	end)

	task.spawn(function()
		while task.wait(0.5) do
			if not notify_on then
				continue
			end
			local mp = murderer_player()
			local name = mp and mp.Name
			if name ~= cur_murderer_name then
				cur_murderer_name = name
				killed_flag = false
			end
		end
	end)

	local function on_shot()
		if not (notify_on and (miss_on or kill_on)) then return end
		local role = my_role()
		if role ~= "Sheriff" and role ~= "Hero" then return end
		local mp = murderer_player()
		if not mp then return end
		local mname = mp.Name
		task.delay(0.7, function()
			if not notify_on then return end
			local d = get_data()
			local info = d and d[mname]
			local target = players:FindFirstChild(mname)
			local hum = target and target.Character and target.Character:FindFirstChildOfClass("Humanoid")
			local killed = (info and info.Dead == true) or (hum ~= nil and hum.Health <= 0)
			local alive = (info and info.Dead == false) or (hum ~= nil and hum.Health > 0)
			if killed then
				if kill_on and not killed_flag then
					killed_flag = true
					push("Killed @"..mname, ICON_KILL)
				end
			elseif alive then
				if miss_on and getgenv().SILENT_AIM_ACTIVE and os.clock() - last_miss > 1.5 then
					last_miss = os.clock()
					push("Missed shot due to @"..mname, ICON_MISS)
				end
			end
		end)
	end

	local function ensure_gun_hook()
		if gun_conn and hooked_gun then return end
		local ok, remote = pcall(function()
			return rs:WaitForChild("ClientServices"):WaitForChild("WeaponService"):WaitForChild("GunFired")
		end)
		if not ok or not remote then return end
		if gun_conn then pcall(function() gun_conn:Disconnect() end) gun_conn = nil end
		hooked_gun = remote
		gun_conn = remote.OnClientEvent:Connect(function(gun)
			local char = lp.Character
			if typeof(gun) == "Instance" and char and gun:IsDescendantOf(char) then
				on_shot()
			end
		end)
	end

	task.spawn(function()
		while true do
			if notify_on and (miss_on or kill_on) then
				ensure_gun_hook()
			end
			task.wait(0.4)
		end
	end)

	getgenv().__PLR_QUEUE("alerts", "notify", function(target)
		local ntgl = target:AddToggle({
			Name = "notify",
			Default = false,
			Flag = "Notify",
			Option = true,
			Callback = function(v)
				notify_on = v
				if v and (miss_on or kill_on) then task.spawn(ensure_gun_hook) end
			end
		})

		ntgl.Option:AddToggle({
			Name = "miss",
			Default = false,
			Flag = "Misses",
			Callback = function(v)
				miss_on = v
				if v and notify_on then task.spawn(ensure_gun_hook) end
			end
		})

		ntgl.Option:AddToggle({
			Name = "kill murder",
			Default = false,
			Flag = "KillM",
			Callback = function(v)
				kill_on = v
				if v and notify_on then task.spawn(ensure_gun_hook) end
			end
		})

		ntgl.Option:AddToggle({
			Name = "roles",
			Default = false,
			Flag = "Roles",
			Callback = function(v)
				roles_on = v
			end
		})
	end)

	getgenv().NOTIFY_UNLOAD = function()
		notify_on, miss_on, kill_on, roles_on = false, false, false, false
		if gun_conn then pcall(function() gun_conn:Disconnect() end) gun_conn = nil end
		hooked_gun = nil
	end
end

do
	local players = game:GetService("Players")
	local sound_service = game:GetService("SoundService")
	local lp = players.LocalPlayer

	local snd_cfg = {
		sheriff = { on = false, name = "mc bow", volume = 1 },
		murder = { on = false, name = "skeet", volume = 1 }
	}

	local SND_REMOTE_LIST = { "primordial", "neverlose", "sparkle", "mc bow", "skeet", "break", "rust" }
	local SND_LOCAL_LIST = { "applepay", "bubble", "combobreak", "killcard", "xp", "na naxuy", "stony", "hentai" }
	local SND_FILES = { hentai = "hentai1" }
	local SND_CACHE_DIR = "shitaro_sounds/"
	local SND_USER_DIR = "sounds/"
	local SND_USER_EXTS = { [".ogg"] = true, [".mp3"] = true, [".wav"] = true }
	local SND_DIRS = { "shitaroebet/", "assets/", "khen_juju/assets/", "khen_juju/custom/", SND_USER_DIR, "", SND_CACHE_DIR }
	local SND_EXTS = { ".ogg", ".mp3", ".wav", "" }
	local SND_BASE_URL = "https://github.com/khenn791/lmao/raw/refs/heads/main/"

	local SND_LIST = {}
	local snd_remote = {}

	for _, snd_name in ipairs(SND_REMOTE_LIST) do
		SND_LIST[#SND_LIST + 1] = snd_name
		snd_remote[snd_name] = true
	end

	for _, snd_name in ipairs(SND_LOCAL_LIST) do
		SND_LIST[#SND_LIST + 1] = snd_name
	end

	local SND_BASE_COUNT = #SND_LIST

	local snd_user = {}
	local snd_user_sig = nil
	local snd_drops = {}

	local snd_cache = {}
	local snd_source = {}
	local snd_fetched = {}
	local snd_warned = {}
	local snd_hooked = {}
	local snd_pool = {}
	local snd_tmp = {}
	local snd_alive = true
	local snd_last = { sheriff = 0, murder = 0 }

	local function snd_fs_ready()
		return type(isfile) == "function" and type(readfile) == "function"
			and type(writefile) == "function" and type(getcustomasset) == "function"
	end

	local function snd_load_path(path)
		local ok_is, has = pcall(isfile, path)
		if not (ok_is and has) then return nil end

		local ok_rd, data = pcall(readfile, path)
		if not (ok_rd and type(data) == "string" and #data > 0) then return nil end

		local ext = string.match(path, "(%.[^%./\\]+)$")
		local suffix = ext and string.lower(ext) or ".ogg"
		if not SND_USER_EXTS[suffix] then suffix = ".ogg" end

		local tmp = "shitaro_snd_" .. tostring(math.random(100000, 999999)) .. suffix
		if not pcall(writefile, tmp, data) then return nil end

		local ok_as, asset = pcall(getcustomasset, tmp)
		if not (ok_as and type(asset) == "string" and asset ~= "") then
			pcall(function() if type(delfile) == "function" then delfile(tmp) end end)
			return nil
		end

		local settle = getgenv().shitaro_volatile
		if type(settle) == "function" then
			local ok_v, res = pcall(settle, tmp, asset, "sound")
			if ok_v and type(res) == "string" and res ~= "" then
				asset = res
			end
		else
			snd_tmp[#snd_tmp + 1] = tmp
		end

		return asset
	end

	local function snd_scan(name)
		local direct = snd_user[name]
		if direct then
			local asset = snd_load_path(direct)
			if asset then return asset, direct end
		end

		local file = SND_FILES[name] or name
		for _, dir in ipairs(SND_DIRS) do
			for _, ext in ipairs(SND_EXTS) do
				local path = dir .. file .. ext
				local asset = snd_load_path(path)
				if asset then return asset, path end
			end
		end

		return nil, nil
	end

	local function snd_user_dir_ready()
		if type(isfolder) ~= "function" or type(makefolder) ~= "function" then return false end

		local ok, has = pcall(isfolder, SND_USER_DIR)
		if not ok then return false end
		if has then return true end

		return pcall(makefolder, SND_USER_DIR) == true
	end

	local function snd_user_collect()
		local out = {}
		if type(listfiles) ~= "function" then return out end
		if not snd_user_dir_ready() then return out end

		local ok, rows = pcall(listfiles, SND_USER_DIR)
		if not ok or type(rows) ~= "table" then return out end

		local seen = {}
		for _, entry in ipairs(rows) do
			if type(entry) == "string" then
				local path = string.gsub(entry, "\\", "/")
				local stem, ext = string.match(path, "([^/]+)(%.[^%./]+)$")
				if stem and ext and SND_USER_EXTS[string.lower(ext)] and not seen[stem] then
					seen[stem] = true
					out[#out + 1] = { name = stem, path = path }
				end
			end
		end

		table.sort(out, function(a, b) return string.lower(a.name) < string.lower(b.name) end)
		return out
	end

	local function snd_drop_sync(drop)
		if not drop then return end
		pcall(function()
			local cur = drop:GetValue()
			drop:SetValues(SND_LIST)
			drop:Generate()
			if type(cur) == "table" then cur = cur[1] end
			if type(cur) == "string" and cur ~= "" and drop:GetValue() ~= cur then
				for i = 1, #SND_LIST do
					if SND_LIST[i] == cur then
						drop:SetValue(cur)
						break
					end
				end
			end
		end)
	end

	local function snd_user_publish()
		local rows = snd_user_collect()
		local names = {}
		for i = 1, #rows do names[i] = rows[i].name end

		local sig = table.concat(names, "|")
		if sig == snd_user_sig then return end
		snd_user_sig = sig

		for old in pairs(snd_user) do
			snd_cache[old] = nil
			snd_warned[old] = nil
		end

		table.clear(snd_user)
		for i = 1, #rows do
			snd_user[rows[i].name] = rows[i].path
			snd_cache[rows[i].name] = nil
			snd_warned[rows[i].name] = nil
		end

		for i = #SND_LIST, SND_BASE_COUNT + 1, -1 do
			SND_LIST[i] = nil
		end

		local taken = {}
		for i = 1, SND_BASE_COUNT do taken[SND_LIST[i]] = true end
		for i = 1, #names do
			if not taken[names[i]] then
				taken[names[i]] = true
				SND_LIST[#SND_LIST + 1] = names[i]
			end
		end

		snd_drop_sync(snd_drops.sheriff)
		snd_drop_sync(snd_drops.murder)
	end

	local function snd_pull(name)
		local grab = getgenv().shitaro_asset

		if type(grab) ~= "function" then
			return nil
		end

		local file = SND_FILES[name] or name
		local names = getgenv().shitaro_assetlist

		if type(names) == "function" then
			local ok, rows = pcall(names, "")

			if ok and type(rows) == "table" then
				for _, entry in ipairs(rows) do
					local stem, ext = string.match(entry, "^([^/]+)(%.[^%.]+)$")

					if stem == file and (ext == ".mp3" or ext == ".wav" or ext == ".ogg") then
						local id = grab(entry)

						if id then
							return id
						end
					end
				end
			end

			return nil
		end

		for _, ext in ipairs({ ".mp3", ".wav", ".ogg" }) do
			local id = grab(file .. ext)

			if id then
				return id
			end
		end

		return nil
	end

	local function snd_download(name)
		if snd_fetched[name] ~= nil then
			return snd_fetched[name]
		end
		if not snd_remote[name] then
			snd_fetched[name] = false
			return false
		end
		local path = SND_CACHE_DIR .. name .. ".ogg"
		local ok_is, has = pcall(isfile, path)
		if ok_is and has then
			snd_fetched[name] = true
			return true
		end
		if type(isfolder) ~= "function" or type(makefolder) ~= "function" then
			snd_fetched[name] = false
			return false
		end
		local ok_dir = pcall(function()
			if not isfolder(SND_CACHE_DIR) then
				makefolder(SND_CACHE_DIR)
			end
		end)
		if not ok_dir then
			snd_fetched[name] = false
			return false
		end
		local url = SND_BASE_URL .. (string.gsub(name, " ", "%%20")) .. ".ogg"
		local ok_dl, data = pcall(function()
			return game:HttpGet(url)
		end)
		if not ok_dl or type(data) ~= "string" or #data < 1024 then
			snd_fetched[name] = false
			return false
		end
		local ok_wr = pcall(writefile, path, data)
		snd_fetched[name] = ok_wr == true
		return snd_fetched[name]
	end

	local function snd_resolve(name)
		local cached = snd_cache[name]
		if cached ~= nil then
			if cached == false then return nil end
			return cached
		end
		if not snd_fs_ready() then
			snd_cache[name] = false
			return nil
		end
		local found, found_path = snd_scan(name)
		if not found then
			found = snd_pull(name)
			if found then
				found_path = name
			end
		end
		if not found and snd_download(name) then
			found, found_path = snd_scan(name)
		end
		snd_cache[name] = found or false
		snd_source[name] = found_path
		if not found and not snd_warned[name] then
			snd_warned[name] = true
			if event_notify then
				pcall(function()
					event_notify:Notify({ Title = "Sound file '" .. name .. "' not found", Icon = "clipboard", Duration = 5 })
				end)
			end
		end
		return found
	end

	local function snd_template(kind)
		local cfg = snd_cfg[kind]
		if not cfg then return nil end
		local id = snd_resolve(cfg.name)
		if not id then
			local old = snd_pool[kind]
			if old then
				pcall(function() old:Destroy() end)
				snd_pool[kind] = nil
			end
			return nil
		end
		local cur = snd_pool[kind]
		if cur and cur.Parent and cur.SoundId == id then
			pcall(function() cur.Volume = cfg.volume end)
			return cur
		end
		if cur then pcall(function() cur:Destroy() end) end
		local ok, s = pcall(function()
			local snd = Instance.new("Sound")
			snd.Name = "\0"
			snd.SoundId = id
			snd.Volume = cfg.volume
			snd.Looped = false
			snd.Parent = sound_service
			return snd
		end)
		if not ok or not s then
			snd_pool[kind] = nil
			return nil
		end
		snd_pool[kind] = s
		task.spawn(function()
			pcall(function() game:GetService("ContentProvider"):PreloadAsync({ s }) end)
		end)
		return s
	end

	local function snd_play(kind)
		local template = snd_pool[kind] or snd_template(kind)
		if not template then return false end
		local ok = pcall(function()
			local c = template:Clone()
			c.Volume = snd_cfg[kind].volume
			c.Looped = false
			c.PlayOnRemove = false
			c.TimePosition = 0
			c.Parent = sound_service
			c:Play()
			task.delay(0.3, function()
				if not c.Parent then return end
				if c.IsPlaying or c.TimePosition > 0 then return end
				pcall(function()
					c.PlayOnRemove = true
					c:Destroy()
				end)
			end)
			task.delay(8, function() pcall(function() c:Destroy() end) end)
		end)
		return ok
	end

	local function snd_kind_active(kind)
		local cfg = snd_cfg[kind]
		return cfg ~= nil and cfg.on
	end

	local function snd_any_active()
		return snd_cfg.sheriff.on or snd_cfg.murder.on
	end

	local function snd_should_mute(kind)
		local cfg = snd_cfg[kind]
		if not cfg or not cfg.on then return false end
		return snd_template(kind) ~= nil
	end

	local function snd_refresh()
		local mute = { sheriff = snd_should_mute("sheriff"), murder = snd_should_mute("murder") }
		for inst, entry in pairs(snd_hooked) do
			if inst.Parent then
				pcall(function()
					inst.Volume = mute[entry.kind] and 0 or entry.vol
				end)
			end
		end
	end

	local function snd_hook(inst, kind)
		if snd_hooked[inst] then return end
		local entry = { kind = kind, vol = inst.Volume, conns = {} }
		snd_hooked[inst] = entry

		local function fire()
			if not snd_kind_active(kind) then return end
			if not snd_pool[kind] and not snd_template(kind) then return end
			if os.clock() - snd_last[kind] < 0.15 then return end
			snd_last[kind] = os.clock()
			pcall(function() inst:Stop() end)
			snd_play(kind)
		end

		entry.conns[#entry.conns + 1] = inst.Played:Connect(fire)
		entry.conns[#entry.conns + 1] = inst:GetPropertyChangedSignal("Playing"):Connect(function()
			if inst.Playing then fire() end
		end)
		entry.conns[#entry.conns + 1] = inst.Destroying:Connect(function()
			snd_hooked[inst] = nil
		end)

		pcall(function()
			inst.Volume = snd_should_mute(kind) and 0 or entry.vol
		end)

		if inst.Playing or inst.IsPlaying then
			fire()
		end
	end

	local function snd_tool_kind(tool)
		if tool:FindFirstChild("GunClient") or tool:FindFirstChild("Shoot") or tool.Name == "Gun" then
			return "sheriff"
		end
		if tool:FindFirstChild("KnifeClient") or tool:FindFirstChild("Events") or tool.Name == "Knife" then
			return "murder"
		end
		return nil
	end

	local snd_watch_conns = {}
	local snd_watched_char = nil
	local snd_watched_bp = nil

	local function snd_consider(inst)
		if not inst:IsA("Sound") then return end
		if inst.Name ~= "GunKill" and inst.Name ~= "Kill" then return end
		local handle = inst.Parent
		if not handle or handle.Name ~= "Handle" then return end
		local tool = handle.Parent
		if not tool or not tool:IsA("Tool") then return end
		local kind = snd_tool_kind(tool)
		if kind then snd_hook(inst, kind) end
	end

	local function snd_clear_watch()
		for i = #snd_watch_conns, 1, -1 do
			pcall(function() snd_watch_conns[i]:Disconnect() end)
			snd_watch_conns[i] = nil
		end
		snd_watched_char, snd_watched_bp = nil, nil
	end

	local function snd_watch()
		local char = lp.Character
		local bp = lp:FindFirstChildOfClass("Backpack")
		if char == snd_watched_char and bp == snd_watched_bp then return end
		snd_clear_watch()
		snd_watched_char, snd_watched_bp = char, bp
		if char then
			snd_watch_conns[#snd_watch_conns + 1] = char.DescendantAdded:Connect(snd_consider)
		end
		if bp then
			snd_watch_conns[#snd_watch_conns + 1] = bp.DescendantAdded:Connect(snd_consider)
		end
	end

	local function snd_scan()
		snd_watch()
		local function scan(container)
			if not container then return end
			for _, tool in ipairs(container:GetChildren()) do
				if tool:IsA("Tool") then
					local kind = snd_tool_kind(tool)
					local handle = tool:FindFirstChild("Handle")
					if kind and handle then
						for _, child in ipairs(handle:GetChildren()) do
							if child:IsA("Sound") and (child.Name == "GunKill" or child.Name == "Kill") then
								snd_hook(child, kind)
							end
						end
					end
				end
			end
		end
		scan(lp.Character)
		scan(lp:FindFirstChildOfClass("Backpack"))
	end

	local function snd_unhook_all()
		for inst, entry in pairs(snd_hooked) do
			for i = 1, #entry.conns do
				pcall(function() entry.conns[i]:Disconnect() end)
			end
			if inst.Parent then
				pcall(function() inst.Volume = entry.vol end)
			end
		end
		table.clear(snd_hooked)
		for kind, s in pairs(snd_pool) do
			pcall(function() s:Destroy() end)
			snd_pool[kind] = nil
		end
		snd_clear_watch()
	end

	task.spawn(function()
		while snd_alive do
			task.wait(0.4)
			if snd_alive and snd_any_active() then
				pcall(snd_scan)
				pcall(snd_refresh)
			end
		end
	end)

	task.spawn(function()
		while snd_alive do
			if snd_user_dir_ready() then
				pcall(snd_user_publish)
			end
			task.wait(2)
		end
	end)

	local function snd_apply(kind, v)
		snd_cfg[kind].on = v
		if snd_any_active() then
			if v then pcall(snd_template, kind) end
			pcall(snd_scan)
			pcall(snd_refresh)
		else
			pcall(snd_unhook_all)
		end
	end

	local function snd_preview(name, volume)
		local id = snd_resolve(name)
		if not id then return end
		pcall(function()
			local snd = Instance.new("Sound")
			snd.SoundId = id
			snd.Volume = volume
			snd.Looped = false
			snd.Parent = sound_service
			snd:Play()
			task.delay(8, function() pcall(function() snd:Destroy() end) end)
		end)
	end

	local function snd_bulk_change()
		local sync = getgenv().UI_SYNC
		if not sync then return false end
		if os.clock() - sync.start < 3 then return true end
		return os.clock() - sync.stamp < 0.7 and sync.count >= 3
	end

	local snd_preview_token = 0

	local function snd_request_preview(name, volume)
		snd_preview_token = snd_preview_token + 1
		local token = snd_preview_token
		task.delay(0.3, function()
			if token ~= snd_preview_token then return end
			if not snd_alive then return end
			if snd_bulk_change() then return end
			snd_preview(name, volume)
		end)
	end

	local function snd_set_name(kind, v)
		if type(v) == "table" then v = v[1] end
		if type(v) ~= "string" or v == "" then return end
		snd_cfg[kind].name = v
		if snd_cfg[kind].on then pcall(snd_template, kind) end
		if snd_any_active() then pcall(snd_refresh) end
		snd_request_preview(v, snd_cfg[kind].volume)
	end

	local function snd_set_volume(kind, v)
		snd_cfg[kind].volume = v
		local s = snd_pool[kind]
		if s then pcall(function() s.Volume = v end) end
	end

	getgenv().__PLR_QUEUE("alerts", "sheriff kill", function(target)
		local sheriff_tgl = target:AddToggle({
			Name = "sheriff kill",
			ToolTip = "Plays when you kill the murderer as sheriff/hero",
			Default = false,
			Flag = "SoundsSheriffKill",
			Option = true,
			Callback = function(v)
				snd_apply("sheriff", v)
			end
		})

		snd_drops.sheriff = sheriff_tgl.Option:AddDropdown({
			Name = "sound",
			Default = "mc bow",
			Values = SND_LIST,
			Flag = "SoundsSheriffValue",
			Callback = function(v)
				snd_set_name("sheriff", v)
			end
		})

		sheriff_tgl.Option:AddSlider({
			Name = "volume",
			Default = 1,
			Min = 0.1,
			Max = 5,
			Round = 1,
			Flag = "SoundsSheriffVolume",
			Callback = function(v)
				snd_set_volume("sheriff", v)
			end
		})
	end)

	getgenv().__PLR_QUEUE("alerts", "murder kill", function(target)
		local murder_tgl = target:AddToggle({
			Name = "murder kill",
			ToolTip = "Plays when you kill someone as murderer",
			Default = false,
			Flag = "SoundsMurderKill",
			Option = true,
			Callback = function(v)
				snd_apply("murder", v)
			end
		})

		snd_drops.murder = murder_tgl.Option:AddDropdown({
			Name = "sound",
			Default = "skeet",
			Values = SND_LIST,
			Flag = "SoundsMurderValue",
			Callback = function(v)
				snd_set_name("murder", v)
			end
		})

		murder_tgl.Option:AddSlider({
			Name = "volume",
			Default = 1,
			Min = 0.1,
			Max = 5,
			Round = 1,
			Flag = "SoundsMurderVolume",
			Callback = function(v)
				snd_set_volume("murder", v)
			end
		})
	end)

	getgenv().SOUNDS_UNLOAD = function()
		snd_alive = false
		snd_cfg.sheriff.on = false
		snd_cfg.murder.on = false
		pcall(snd_unhook_all)
		if type(delfile) == "function" then
			for i = 1, #snd_tmp do
				pcall(delfile, snd_tmp[i])
			end
		end
		table.clear(snd_tmp)
		table.clear(snd_cache)
		table.clear(snd_warned)
		table.clear(snd_user)
		table.clear(snd_drops)
		snd_user_sig = nil
	end
end

do
	local players = game:GetService("Players")
	local rs = game:GetService("ReplicatedStorage")
	local ws = workspace
	local lp = players.LocalPlayer

	local fling_murder_on = false
	local fling_sheriff_on = false
	local fling_thread = nil
	local round_mod = nil
	local fling_roles_bypass_velocity = false

	local function my_hrp()
		local c = lp.Character
		return c and c:FindFirstChild("HumanoidRootPart")
	end

	local function get_data()
		if not round_mod then
			local ok, m = pcall(function()
				return require(rs:WaitForChild("Modules"):WaitForChild("CurrentRoundClient"))
			end)
			if ok and type(m) == "table" then round_mod = m end
		end
		return round_mod and round_mod.PlayerData
	end

	local function role_player(role)
		local d = get_data()
		if type(d) ~= "table" then return nil end
		for name, info in pairs(d) do
			if type(info) == "table" and not info.Dead and (info.Role == role or (role == "Sheriff" and info.Role == "Hero")) then
				local p = players:FindFirstChild(name)
				if p and p ~= lp then return p end
			end
		end
		return nil
	end

	local function do_fling(tp)
		if not tp or not tp.Character then return end
		local hrp = my_hrp()
		local hum = lp.Character and lp.Character:FindFirstChildOfClass("Humanoid")
		if not hrp then return end
		local tc = tp.Character
		local thrp = tc:FindFirstChild("HumanoidRootPart") or tc:FindFirstChild("Head")
		local th = tc:FindFirstChildOfClass("Humanoid")
		if not thrp then return end
		getgenv().FLING_ACTIVE = (getgenv().FLING_ACTIVE or 0) + 1
		if hrp.Velocity.Magnitude < 50 then
			getgenv().OldPos = hrp.CFrame
		end
		if th and th.Sit then
			getgenv().FLING_ACTIVE = math.max(0, (getgenv().FLING_ACTIVE or 1) - 1)
			return
		end
		local camera = ws.CurrentCamera
		local old_fdh = ws.FallenPartsDestroyHeight
		if thrp then
			camera.CameraSubject = thrp
		elseif th then
			camera.CameraSubject = th
		end
		pcall(function() ws.FallenPartsDestroyHeight = 0/0 end)
		local bv = Instance.new("BodyVelocity")
		bv.Parent = hrp
		bv.Velocity = Vector3.new(0, 0, 0)
		bv.MaxForce = Vector3.new(9e9, 9e9, 9e9)
		local se = hum and hum:GetStateEnabled(Enum.HumanoidStateType.Seated)
		if hum then hum:SetStateEnabled(Enum.HumanoidStateType.Seated, false) end
		local tw = 2
		local tm = tick()
		local ang = 0
		repeat
			if hrp and th then
				local tv
				if fling_roles_bypass_velocity then
					tv = th.MoveDirection * th.WalkSpeed
				else
					tv = thrp.Velocity
				end
				if tv.Magnitude < 50 then
					ang = ang + 100
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, 1.5, 0) + th.MoveDirection * tv.Magnitude / 1.25
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(ang), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, -1.5, 0) + th.MoveDirection * tv.Magnitude / 1.25
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(ang), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, 1.5, 0) + th.MoveDirection * tv.Magnitude / 1.25
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(ang), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, -1.5, 0) + th.MoveDirection * tv.Magnitude / 1.25
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(ang), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, 1.5, 0) + th.MoveDirection
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(ang), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, -1.5, 0) + th.MoveDirection
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(ang), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
				else
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, 1.5, th.WalkSpeed)
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(90), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, -1.5, -th.WalkSpeed)
					hrp.CFrame = hrp.CFrame * CFrame.Angles(0, 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, 1.5, th.WalkSpeed)
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(90), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, -1.5, 0)
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(90), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, -1.5, 0)
					hrp.CFrame = hrp.CFrame * CFrame.Angles(0, 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, -1.5, 0)
					hrp.CFrame = hrp.CFrame * CFrame.Angles(math.rad(90), 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
					hrp.CFrame = CFrame.new(thrp.Position) * CFrame.new(0, -1.5, 0)
					hrp.CFrame = hrp.CFrame * CFrame.Angles(0, 0, 0)
					lp.Character:SetPrimaryPartCFrame(hrp.CFrame)
					hrp.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
					hrp.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
					task.wait()
				end
			end
		until tm + tw < tick() or not (fling_murder_on or fling_sheriff_on)
		if bv then bv:Destroy() end
		if hum and se ~= nil then hum:SetStateEnabled(Enum.HumanoidStateType.Seated, se) end
		camera.CameraSubject = hum
		if getgenv().OldPos then
			repeat
				hrp.CFrame = getgenv().OldPos * CFrame.new(0, 0.5, 0)
				lp.Character:SetPrimaryPartCFrame(getgenv().OldPos * CFrame.new(0, 0.5, 0))
				if hum then hum:ChangeState("GettingUp") end
				for _, part in pairs(lp.Character:GetChildren()) do
					if part:IsA("BasePart") then
						part.Velocity = Vector3.new()
						part.RotVelocity = Vector3.new()
					end
				end
				task.wait()
			until (hrp.Position - getgenv().OldPos.p).Magnitude < 25
			pcall(function() ws.FallenPartsDestroyHeight = old_fdh end)
		end
		getgenv().FLING_ACTIVE = math.max(0, (getgenv().FLING_ACTIVE or 1) - 1)
	end

	local function start_loop()
		if fling_thread then return end
		fling_thread = task.spawn(function()
			while fling_murder_on or fling_sheriff_on do
				local target = nil
				if fling_murder_on then target = role_player("Murderer") end
				if not target and fling_sheriff_on then target = role_player("Sheriff") end
				if target and target.Character and my_hrp() then
					do_fling(target)
				else
					task.wait(0.3)
				end
				task.wait()
			end
			fling_thread = nil
		end)
	end

	getgenv().__PLR_QUEUE("tools", "fling murder", function(target)
		target:AddToggle({
			Name = "fling murder",
			Default = false,
			Flag = "Fling Murder",
			Callback = function(v)
				fling_murder_on = v
				if v then start_loop() end
			end
		})
	end)

	getgenv().__PLR_QUEUE("tools", "fling sheriff", function(target)
		target:AddToggle({
			Name = "fling sheriff",
			Default = false,
			Flag = "Fling Sheriff",
			Callback = function(v)
				fling_sheriff_on = v
				if v then start_loop() end
			end
		})
	end)

	getgenv().__PLR_QUEUE("tools", "bypass velocity", function(target)
		target:AddToggle({
			Name = "bypass velocity",
			Default = false,
			Flag = "Fling Bypass(roles)",
			Callback = function(v)
				fling_roles_bypass_velocity = v
			end
		})
	end)

	getgenv().__PLR_FLUSH("tools", getgenv().__MISC_TOOLS_SEC)
	getgenv().__PLR_FLUSH("alerts", getgenv().__MISC_ALERTS_SEC)

	getgenv().FLINGROLES_UNLOAD = function()
		fling_murder_on = false
		fling_sheriff_on = false
	end
end

do
	local tracer_section = getgenv().__SHITARO_EFFECTS_SEC or visuals:AddSection({
		Name = "EFFECTS",
		Position = 'right'
	})

	local rs = game:GetService("ReplicatedStorage")
	local tween_service = game:GetService("TweenService")
	local debris = game:GetService("Debris")
	local lp = game.Players.LocalPlayer

	getgenv().SHERIFF_TRACER_ENABLED = false
	getgenv().SHERIFF_TRACER_COLOR = Color3.fromRGB(133, 220, 255)
	getgenv().SHERIFF_TRACER_DURATION = 1

	local tracer_on = false
	local gun_fired_conn = nil
	local gun_fired_remote = nil
	local round_client = nil

	local fade_tween = TweenInfo.new(0.2, Enum.EasingStyle.Linear, Enum.EasingDirection.Out)

	local function get_round_client()
		local ok, module = pcall(function()
			return require(rs:WaitForChild("Modules"):WaitForChild("CurrentRoundClient"))
		end)
		if ok then round_client = module end
		return round_client
	end

	local function is_local_sheriff()
		local char = lp.Character
		if char and char:FindFirstChild("Gun") then return true end
		local bp = lp:FindFirstChildOfClass("Backpack")
		if bp and bp:FindFirstChild("Gun") then return true end
		local round = get_round_client()
		if not round then return false end
		local data = round.PlayerData
		local d = data and data[lp.Name]
		return d ~= nil and (d.Role == "Sheriff" or d.Role == "Hero")
	end

	local function make_point(position, lifetime)
		local part = Instance.new("Part")
		part.Transparency = 1
		part.Anchored = true
		part.CanCollide = false
		part.CanQuery = false
		part.Size = Vector3.new(1, 1, 1)
		part.CFrame = CFrame.new(position)
		Instance.new("Attachment", part)
		debris:AddItem(part, lifetime)
		part.Parent = workspace
		return part
	end

	local function to_position(value)
		if typeof(value) == "Vector3" then
			return value
		elseif typeof(value) == "CFrame" then
			return value.Position
		elseif typeof(value) == "Instance" then
			if value:IsA("Attachment") then
				return value.WorldPosition
			elseif value:IsA("BasePart") then
				return value.Position
			end
		end
	end

	local function create_tracer(start_value, end_value)
		local start_position = to_position(start_value)
		local end_position = to_position(end_value)
		if not start_position or not end_position then return end

		local duration = getgenv().SHERIFF_TRACER_DURATION or 1
		local start_part = make_point(start_position, duration + 0.5)
		local end_part = make_point(end_position, duration + 0.5)

		local beam = Instance.new("Beam")
		beam.FaceCamera = true
		beam.TextureSpeed = 1.5
		beam.TextureLength = 2
		beam.Width0 = 0.25
		beam.Width1 = 0.25
		beam.LightEmission = 3
		beam.LightInfluence = 0
		beam.Brightness = 2.5
		beam.Texture = "rbxassetid://12781800668"
		beam.Color = ColorSequence.new(getgenv().SHERIFF_TRACER_COLOR)
		beam.Transparency = NumberSequence.new({ NumberSequenceKeypoint.new(0, 0.1), NumberSequenceKeypoint.new(1, 0.1) })
		beam.Attachment0 = start_part.Attachment
		beam.Attachment1 = end_part.Attachment
		beam.Parent = start_part

		task.delay(duration, function()
			if beam.Parent then
				tween_service:Create(beam, fade_tween, { Width0 = 0, Width1 = 0 }):Play()
			end
		end)
	end

	local function on_gun_fired(gun, start_value, end_value)
		if not tracer_on then return end
		local char = lp.Character
		if not char then return end
		if not (typeof(gun) == "Instance" and gun:IsDescendantOf(char)) then return end
		if not is_local_sheriff() then return end
		create_tracer(start_value, end_value)
	end

	local function connect_gun_fired()
		local ok, remote = pcall(function()
			return rs:WaitForChild("ClientServices"):WaitForChild("WeaponService"):WaitForChild("GunFired")
		end)
		if not ok or not remote then return end
		if gun_fired_conn and gun_fired_remote == remote and gun_fired_conn.Connected then return end
		if gun_fired_conn then pcall(function() gun_fired_conn:Disconnect() end) gun_fired_conn = nil end
		gun_fired_remote = remote
		gun_fired_conn = remote.OnClientEvent:Connect(function(gun, start_value, end_value)
			task.spawn(on_gun_fired, gun, start_value, end_value)
		end)
	end

	task.spawn(function()
		while true do
			if tracer_on then
				pcall(connect_gun_fired)
			end
			task.wait(1)
		end
	end)

	local tracer = tracer_section:AddToggle({
		Name = "bullet tracer",
		ToolTip = "Create a tracer line when you shoot",
		Default = false,
		Flag = "Sheriff Tracer",
		Option = true,
		Callback = function(v)
			tracer_on = v
			getgenv().SHERIFF_TRACER_ENABLED = v
			if v then connect_gun_fired() end
		end
	})

	tracer.Option:AddColorPicker({
		Name = "color",
		Default = Color3.fromRGB(133, 220, 255),
		Flag = "sheriff_tracer_color",
		Callback = function(c)
			getgenv().SHERIFF_TRACER_COLOR = c
		end
	})

	tracer.Option:AddSlider({
		Name = "duration",
		Default = 1,
		Min = 0.1,
		Max = 5,
		Round = 1,
		Flag = "sheriff_tracer_duration",
		Callback = function(v)
			getgenv().SHERIFF_TRACER_DURATION = v
		end
	})

	getgenv().TRACER_UNLOAD = function()
		tracer_on = false
		getgenv().SHERIFF_TRACER_ENABLED = false
		if gun_fired_conn then pcall(function() gun_fired_conn:Disconnect() end) gun_fired_conn = nil end
	end
end


do
	window:AddColors()

	local _, pref = window:AddConfig()

	

	if #lib.cursorlist > 0 then
		pref:toggle({
			name = "custom cursor",
			default = false,
			flag = "MenuCursor",
			callback = function(v)
				lib:setcursor(v)
			end,
		})

		pref:dropdown({
			name = "preset",
			list = lib.cursorlist,
			default = lib.cursorlist[1],
			flag = "MenuCursorStyle",
			callback = function(v)
				lib:setstyle(v)
			end,
		})
	end

	pref:toggle({
		name = "menu sounds",
		default = false,
		flag = "MenuSounds",
		callback = function(v)
			lib:setsound(v)
		end,
	})

	pref:dropdown({
		name = "sound",
		list = lib.tonelist,
		default = "Click",
		flag = "MenuTone",
		callback = function(v)
			lib:settone(v)
		end,
	})
	pref:toggle({
		name = "furry",
		default = true,
		flag = "MenuFurry",
		callback = function(v)
			if window.__win and type(window.__win.setfury) == "function" then
				window.__win:setfury(v)
			end
		end,
	})
	pref:toggle({
		name = "hotkeys",
		default = true,
		flag = "MenuHotkeys",
		callback = function(v)
			lib:sethotkeys(v)
		end,
	})

	pref:toggle({
		name = "watermark",
		default = true,
		flag = "Watermark",
		callback = function(v)
			lib:setwatermark(v)
		end,
	})

	pref:keybind({
		name = "menu key",
		default = "Insert",
		flag = "MenuKeybind",
		callback = function(v)
			window:SetBind(v)
		end,
	})
	pref:button({
		name = "telegram",
		icon = "send",
		callback = function()
			pcall(function()
				setclipboard("https://t.me/shitarouse")
				__Logging.new("107339085791087", 'copied invite to gay party', 5)
			end)
		end,
	})

	local function tdown()
		shkey.stop()

		pcall(function()
			local unloads = {
				"FAKE_POS_UNLOAD","LOCAL_VIS_UNLOAD","AURA_UNLOAD","WORLD_EXTRA_UNLOAD",
				"WORLD_FX_UNLOAD","TRACER_UNLOAD","SHADER_UNLOAD","SILENT_UNLOAD","KNIFE_UNLOAD",
				"CROSSHAIR_UNLOAD","HITBOX_UNLOAD","KILL_UNLOAD","KILLAURA_UNLOAD","GUN_ESP_UNLOAD","PLAYERS_DEATH_UNLOAD","AUTOFARM_UNLOAD","MISC_UNLOAD",
				"CHARACTER_UNLOAD","FAKE_UNLOAD","TARGET_UNLOAD","MISC_TOOLS_UNLOAD",
				"NOTIFY_UNLOAD","SOUNDS_UNLOAD","FLINGROLES_UNLOAD","EMOTE_UNLOAD","ANIM_UNLOAD","PIXEL_SURF_UNLOAD","SHOWVALUES_UNLOAD",
				"ESP_PREVIEW_UNLOAD","SKIN_UNLOAD","MAPVOTE_UNLOAD"
			}
			for _, key in ipairs(unloads) do
				local fn = getgenv()[key]
				if fn then
					pcall(fn)
					getgenv()[key] = nil
				end
			end

			if tabUpdateThread then task.cancel(tabUpdateThread) tabUpdateThread = nil end
			if roleThread then task.cancel(roleThread) roleThread = nil end
			for i = 1, #roleThreadConns do
				local c = roleThreadConns[i]
				pcall(function() c:Disconnect() end)
			end
			table.clear(roleThreadConns)

			pcall(function()
				local lighting = game:GetService("Lighting")
				if getgenv().WORLD_FOG_ENABLED then
					lighting.FogColor = Color3.fromRGB(192, 192, 192)
					lighting.FogStart = 0
					lighting.FogEnd = 100000
					getgenv().WORLD_FOG_ENABLED = false
				end
				if getgenv().WORLD_FULLBRIGHT_ENABLED then
					lighting.Brightness = 1
					lighting.ClockTime = 14
					lighting.FogEnd = 100000
					lighting.GlobalShadows = true
					lighting.OutdoorAmbient = Color3.fromRGB(128, 128, 128)
					getgenv().WORLD_FULLBRIGHT_ENABLED = false
				end
				if getgenv().WORLD_AMBIENT_ENABLED then
					lighting.Ambient = Color3.fromRGB(0, 0, 0)
					lighting.OutdoorAmbient = Color3.fromRGB(128, 128, 128)
					getgenv().WORLD_AMBIENT_ENABLED = false
				end
				if getgenv().WORLD_SKYBOX_ENABLED then
					for _, sky in pairs(lighting:GetChildren()) do
						if sky:IsA("Sky") and sky.Name == "CustomSky" then
							sky:Destroy()
						end
					end
					getgenv().WORLD_SKYBOX_ENABLED = false
				end
				for _, gui in pairs(game:GetService("CoreGui"):GetChildren()) do
					if gui.Name == "SkyboxInput" then gui:Destroy() end
				end
				for _, effect in pairs(lighting:GetChildren()) do
					if effect:IsA("BlurEffect") then effect:Destroy() end
				end
			end)

			if esp and esp._loaded then
				pcall(function() esp.Unload() end)
			end
		end)

		pcall(function() lib:unload() end)

		getgenv().shitaroebet = nil
		getgenv().SHKEY = nil
	end

	shkey.bind(tdown)

	pref:button({
		name = "Unload",
		icon = "log-out",
		callback = tdown,
	})
end



do
	local plrs = game:GetService("Players")
	local rstor = game:GetService("ReplicatedStorage")
	local assets = game:GetService("AssetService")
	local jsn = game:GetService("HttpService")
	local cs = game:GetService("CollectionService")
	local lp = plrs.LocalPlayer

	local dbfile = "mm2_weapons.json"
	local harvestfile = "mm2_harvest.json"
	local harvestname = string.char(104, 97, 114, 118, 101, 115, 116, 46, 106, 115, 111, 110)
	local flagfile = "mm2_flags.json"
	local assetfile = "mm2_assets.json"
	local skdb, schema = nil, nil
	local skflags, skassets = nil, nil
	local dbfx, sharedfx = {}, {}
	local rows, byname = {}, {}
	local rarities = {}
	local fkind, frar, fstate = "all", "all", "working"
	local mcache, made, snaps = {}, {}, {}
	local gunconns = {}
	local picks = { Knife = nil, Gun = nil }
	local muted = { Knife = {}, Gun = {} }
	local touched = { Knife = {}, Gun = {} }
	local slotsounds = { Knife = nil, Gun = nil }
	local holdtracks = {}
	local alive, watch = true, true
	local slist, rardrop, seltext, syncsel = nil, nil, nil, nil

	local skip = {
		Anchored = true, Massless = true, CanCollide = true, CanQuery = true, CanTouch = true,
		MeshId = true, MeshSize = true, Size = true, Part0 = true, Part1 = true,
		Attachment0 = true, Attachment1 = true, Locked = true,
		TimeLength = true, Playing = true, IsLoaded = true, IsPlaying = true,
	}

	local fxclass = {
		Beam = true, Trail = true, ParticleEmitter = true, Decal = true, Texture = true,
		Fire = true, Smoke = true, Sparkles = true, PointLight = true, SpotLight = true,
		SurfaceLight = true,
	}

	local mutenames = { Gunshot = true }

	local fxshare = {
		ParticleEmitter = true, Beam = true, Trail = true, Fire = true, Smoke = true,
		Sparkles = true, PointLight = true, SpotLight = true, SurfaceLight = true,
	}

	local SHAREMIN = 3

	local order = {
		"BasePart", "MeshPart", "SpecialMesh", "Decal", "Texture", "ParticleEmitter", "Beam",
		"Trail", "Sound", "Attachment", "Highlight",
	}

	local function assid(v)
		return tonumber(tostring(v):match("(%d+)"))
	end

	local function strid(v)
		if type(v) ~= "string" or v == "" then return nil end
		return tostring(v):match("(%d+)")
	end

	local function iconid(v)
		if type(v) ~= "string" or v == "" then return nil end
		local id = v:match("assetId=(%d+)") or v:match("[%?&]id=(%d+)") or v:match("^rbxassetid://(%d+)")
		if id then return tonumber(id) end
		local last
		for n in v:gmatch("(%d+)") do last = n end
		return last and tonumber(last) or nil
	end

	local function assetok(bucket, raw)
		local id = strid(raw)
		if not id then return true end
		if not skassets or not skassets[bucket] then return true end
		local state = skassets[bucket][id]
		if state == nil then return true end
		return state
	end

	local function meshok(raw)
		return assetok("mesh", raw) and assetok("meshpart", raw)
	end

	local function fxkey(n)
		if not n or not fxshare[n.class] then return nil end
		local props = n.props or {}
		local tex = strid(props.Texture) or strid(props.Texture1) or ""
		return n.class .. "\1" .. tostring(n.name) .. "\1" .. tex
	end

	local function collectdbfx(items)
		table.clear(dbfx)
		if type(items) ~= "table" then return end
		for _, rec in pairs(items) do
			for _, field in ipairs({ "display", "tool" }) do
				local tree = rec[field]
				for _, n in ipairs(tree and tree.nodes or {}) do
					local k = fxkey(n)
					if k then dbfx[k] = true end
				end
			end
		end
	end

	local function prunefx()
		if not skdb or type(skdb.items) ~= "table" then return end

		local hits = {}
		for _, rec in pairs(skdb.items) do
			if rec.fromharvest then
				local own = {}
				for _, field in ipairs({ "display", "tool" }) do
					local tree = rec[field]
					for _, n in ipairs(tree and tree.nodes or {}) do
						local k = fxkey(n)
						if k and not dbfx[k] and not own[k] then
							own[k] = true
							hits[k] = (hits[k] or 0) + 1
						end
					end
				end
			end
		end

		table.clear(sharedfx)
		for k, c in pairs(hits) do
			if c >= SHAREMIN then sharedfx[k] = true end
		end
		if not next(sharedfx) then return end

		for _, rec in pairs(skdb.items) do
			if rec.fromharvest then
				for _, field in ipairs({ "display", "tool" }) do
					local tree = rec[field]
					local nodes = tree and tree.nodes
					if nodes then
						local dead = {}
						for i = #nodes, 1, -1 do
							local n = nodes[i]
							local k = fxkey(n)
							if k and sharedfx[k] then
								if n.path then dead[n.path] = true end
								table.remove(nodes, i)
							end
						end
						if next(dead) then
							for i = #nodes, 1, -1 do
								local p = nodes[i].parent
								if p and dead[p] then table.remove(nodes, i) end
							end
						end
					end
				end
			end
		end
	end

	local function recstate(id)
		if not skflags or not skflags.status then return "ok" end
		return skflags.status[id] or "ok"
	end

	local function tov3(t)
		return t and Vector3.new(t[1], t[2], t[3]) or nil
	end

	local function toc3(t)
		return t and Color3.new(t[1], t[2], t[3]) or nil
	end

	local function toenum(s, e)
		local n = tostring(s):match("([%w_]+)$")
		if not n then return nil end
		local ok, r = pcall(function() return e[n] end)
		return ok and r or nil
	end

	local function tonseq(t)
		local k = {}
		for _, p in ipairs(t) do k[#k + 1] = NumberSequenceKeypoint.new(p.t, p.v, p.e or 0) end
		if #k >= 2 then return NumberSequence.new(k) end
		return NumberSequence.new(k[1] and k[1].Value or 0)
	end

	local function tocseq(t)
		local k = {}
		for _, p in ipairs(t) do k[#k + 1] = ColorSequenceKeypoint.new(p.t, Color3.new(p.c[1], p.c[2], p.c[3])) end
		if #k >= 2 then return ColorSequence.new(k) end
		return ColorSequence.new(k[1] and k[1].Value or Color3.new(1, 1, 1))
	end

	local function decode(v, kind)
		if v == nil then return nil end
		if kind == "num" or kind == "bool" or kind == "str" then return v end
		if kind == "v3" then return tov3(v) end
		if kind == "v2" then return Vector2.new(v[1], v[2]) end
		if kind == "c3" then return toc3(v) end
		if kind == "cf" then return CFrame.new(table.unpack(v)) end
		if kind == "enum" then return nil end
		if kind == "nrange" then return NumberRange.new(v[1], v[2]) end
		if kind == "nseq" then return tonseq(v) end
		if kind == "cseq" then return tocseq(v) end
		return nil
	end

	local function schemaof(inst)
		local out = {}
		if not schema then return out end
		for _, cls in ipairs(order) do
			local ok, isa = pcall(function() return inst:IsA(cls) end)
			if ok and isa and schema[cls] then
				for k, v in pairs(schema[cls]) do out[k] = v end
			end
		end
		return out
	end

	local function enumfull(s)
		local a, b = tostring(s):match("^Enum%.([%w_]+)%.([%w_]+)$")
		if not a then return nil end
		local ok, e = pcall(function() return Enum[a][b] end)
		return ok and e or nil
	end

	local function fitvalue(current, raw)
		local t = typeof(current)
		if type(raw) == "string" then
			if t == "EnumItem" then return enumfull(raw) end
			return raw
		end
		if type(raw) == "number" or type(raw) == "boolean" then return raw end
		if type(raw) ~= "table" then return nil end
		local n = #raw
		if t == "Color3" and n == 3 then return toc3(raw) end
		if t == "Vector3" and n == 3 then return tov3(raw) end
		if t == "Vector2" and n == 2 then return Vector2.new(raw[1], raw[2]) end
		if t == "NumberRange" and n == 2 then return NumberRange.new(raw[1], raw[2]) end
		if t == "CFrame" and (n == 12 or n == 7) then return CFrame.new(table.unpack(raw)) end
		if t == "NumberSequence" and type(raw[1]) == "table" then return tonseq(raw) end
		if t == "ColorSequence" and type(raw[1]) == "table" then return tocseq(raw) end
		return nil
	end

	local function setprops(inst, props)
		if not props then return end
		for prop, raw in pairs(props) do
			if not skip[prop] then
				local ok, current = pcall(function() return inst[prop] end)
				if ok then
					local val = fitvalue(current, raw)
					if val ~= nil then pcall(function() inst[prop] = val end) end
				end
			end
		end
	end

	local function mkpart(props)
		local id = assid(props.MeshId)
		if not id then return nil end
		if not meshok(props.MeshId) then return nil end
		local base = mcache[id]
		if not base then
			local ok, mp = pcall(function()
				return assets:CreateMeshPartAsync(Content.fromAssetId(id))
			end)
			if not ok or not mp then return nil end
			mp.Parent = nil
			mcache[id] = mp
			base = mp
		end
		local part = base:Clone()
		if props.Size then part.Size = tov3(props.Size) end
		if props.TextureID and props.TextureID ~= "" and assetok("image", props.TextureID) then
			pcall(function() part.TextureID = props.TextureID end)
		end
		if props.Color then part.Color = toc3(props.Color) end
		if props.Transparency then part.Transparency = props.Transparency end
		if props.Reflectance then part.Reflectance = props.Reflectance end
		local mat = toenum(props.Material, Enum.Material)
		if mat then pcall(function() part.Material = mat end) end
		part.Anchored = false
		part.Massless = true
		part.CanCollide = false
		part.CanQuery = false
		part.CanTouch = false
		part.Locked = true
		return part
	end

	local function softpart(part)
		part.Anchored = false
		part.Massless = true
		part.CanCollide = false
		part.CanQuery = false
		part.CanTouch = false
		part.Locked = true
		return part
	end

	local function rootmeshnode(entry)
		for _, n in ipairs(entry.display and entry.display.nodes or {}) do
			if n.class == "SpecialMesh" and not n.parent and n.props and n.props.MeshId then
				return n
			end
		end
		return nil
	end

	local function mkspecial(props, node)
		if not meshok(node.props.MeshId) then return nil end
		local part = Instance.new("Part")
		if props then
			setprops(part, props)
			if props.Size then part.Size = tov3(props.Size) end
			if props.Color then part.Color = toc3(props.Color) end
			local mat = props.Material and toenum(props.Material, Enum.Material)
			if mat then pcall(function() part.Material = mat end) end
			if props.Transparency then part.Transparency = props.Transparency end
			if props.Reflectance then part.Reflectance = props.Reflectance end
		end
		softpart(part)
		local mesh = Instance.new("SpecialMesh")
		mesh.MeshType = Enum.MeshType.FileMesh
		mesh.Name = node.name or "Mesh"
		setprops(mesh, node.props)
		pcall(function() mesh.MeshId = node.props.MeshId end)
		if node.props.TextureId and node.props.TextureId ~= "" and assetok("image", node.props.TextureId) then
			pcall(function() mesh.TextureId = node.props.TextureId end)
		else
			pcall(function() mesh.TextureId = "" end)
		end
		mesh.Parent = part
		return part
	end

	local function mkroot(entry)
		local props = entry.display and entry.display.root and entry.display.root.props
		if not props then return nil end
		if props.MeshId then
			local part = mkpart(props)
			if part then return part end
		end
		local node = rootmeshnode(entry)
		if node then return mkspecial(props, node) end
		return nil
	end

	local function keep(owner, inst)
		made[#made + 1] = { owner = owner, inst = inst }
	end

	local function wipe(owner)
		for i = #made, 1, -1 do
			local rec = made[i]
			if not owner or rec.owner == owner then
				if rec.inst then pcall(function() rec.inst:Destroy() end) end
				table.remove(made, i)
			end
		end
	end

	local function longaxis(v)
		if v.X >= v.Y and v.X >= v.Z then return Vector3.xAxis end
		if v.Y >= v.Z then return Vector3.yAxis end
		return Vector3.zAxis
	end

	local function alignrot(from, to)
		local d = math.clamp(from:Dot(to), -1, 1)
		if d > 0.9999 then return CFrame.identity end
		if d < -0.9999 then
			local perp = math.abs(from.X) < 0.9 and Vector3.xAxis or Vector3.yAxis
			return CFrame.fromAxisAngle(from:Cross(perp).Unit, math.pi)
		end
		return CFrame.fromAxisAngle(from:Cross(to).Unit, math.acos(d))
	end

	local canongrip = {
		Knife = Vector3.new(0, -1, -0.1),
		Gun = Vector3.new(0, -0.355, 0.7),
	}

	local function axisrot(kind, size)
		if not size then return CFrame.identity end
		local ax = longaxis(size)
		if kind == "Gun" then
			if ax == Vector3.zAxis then return CFrame.identity end
			if ax == Vector3.yAxis then return CFrame.fromAxisAngle(Vector3.xAxis, math.pi / 2) end
			return CFrame.fromAxisAngle(Vector3.yAxis, math.pi / 2)
		end
		if ax == Vector3.zAxis then return CFrame.fromAxisAngle(Vector3.xAxis, -math.pi / 2) end
		return CFrame.identity
	end

	local function topnodes(entry)
		local out = {}
		for _, n in ipairs(entry.display and entry.display.nodes or {}) do
			if not n.parent then out[#out + 1] = n end
		end
		return out
	end

	local function rootprops(entry)
		return entry.display and entry.display.root and entry.display.root.props or nil
	end

	local gripidx = {}

	local function meshkeyof(entry)
		local props = entry.display and entry.display.root and entry.display.root.props
		if props and props.MeshId then return strid(props.MeshId) end
		for _, n in ipairs(entry.display and entry.display.nodes or {}) do
			if n.class == "SpecialMesh" and not n.parent and n.props and n.props.MeshId then
				return strid(n.props.MeshId)
			end
		end
		return nil
	end

	local function toolmeshof(entry)
		local nodes = entry.tool and entry.tool.nodes
		if not nodes then return nil end
		for _, n in ipairs(nodes) do
			if n.name == "Handle" and n.props and n.props.MeshId then
				return strid(n.props.MeshId)
			end
		end
		for _, n in ipairs(nodes) do
			if n.class == "SpecialMesh" and n.parent == "Handle" and n.props and n.props.MeshId then
				return strid(n.props.MeshId)
			end
		end
		return nil
	end

	local function owngrip(entry)
		local raw = entry.tool and entry.tool.root and entry.tool.root.props and entry.tool.root.props.Grip
		if not raw then return nil end
		local disp, tmesh = meshkeyof(entry), toolmeshof(entry)
		if not disp or not tmesh or disp ~= tmesh then return nil end
		return raw
	end

	local function buildgripidx()
		table.clear(gripidx)
		if not skdb then return end
		for key, rec in pairs(skdb.harvest or {}) do
			if rec.grip then gripidx[tostring(key)] = rec.grip end
		end
		for _, rec in pairs(skdb.items) do
			local own = owngrip(rec)
			local key = own and meshkeyof(rec)
			if key and not gripidx[key] then gripidx[key] = own end
		end
		for _, rec in pairs(skdb.items) do
			local live = rec.live and rec.live.grip
			local key = live and meshkeyof(rec)
			if key and not gripidx[key] then gripidx[key] = live end
		end
	end

	local function gripfor(entry)
		local own = owngrip(entry)
		if own then return own end
		if entry.live and entry.live.grip then return entry.live.grip end
		local key = meshkeyof(entry)
		return key and gripidx[key] or nil
	end

	local origins = setmetatable({}, { __mode = "k" })

	local function originof(tool, hnd)
		local rec = origins[tool]
		if not rec or rec.handle ~= hnd or not rec.handle.Parent then
			rec = {
				grip = tool.Grip,
				size = hnd.Size,
				htrans = hnd.Transparency,
				ltm = hnd.LocalTransparencyModifier,
				handle = hnd,
			}
			origins[tool] = rec
		end
		return rec
	end

	local function dispref(kind)
		local ch = lp.Character
		if not ch then return nil end
		local ref = ch:FindFirstChild("DisplayRef" .. kind)
		local val = ref and ref.Value
		return (val and val.Parent) and val or nil
	end

	local function toolof(kind)
		for _, root in ipairs({ lp.Character, lp:FindFirstChildOfClass("Backpack") }) do
			if root then
				local t = root:FindFirstChild(kind)
				if t and t:IsA("Tool") then return t end
			end
		end
		return nil
	end

	local function childmeshnode(entry, path)
		if not path then return nil end
		for _, n in ipairs(entry.display and entry.display.nodes or {}) do
			if n.class == "SpecialMesh" and n.parent == path and n.props and n.props.MeshId then
				return n
			end
		end
		return nil
	end

	local function buildkids(entry, owner, body, parent)
		for _, n in ipairs(topnodes(entry)) do
			if (n.class == "MeshPart" or n.class == "Part") and n.roff and n.props then
				local p
				if n.class == "MeshPart" then
					p = mkpart(n.props)
				else
					local mesh = childmeshnode(entry, n.path)
					if mesh then p = mkspecial(n.props, mesh) end
				end
				if p then
					p.Name = n.name
					p.Parent = parent
					p.CFrame = body.CFrame * CFrame.new(table.unpack(n.roff))
					local wc = Instance.new("WeldConstraint")
					wc.Part0 = body
					wc.Part1 = p
					wc.Parent = p
					keep(owner, p)
				end
			end
		end
	end

	local function tagmeta(inst, n)
		for _, tag in ipairs(n.tags or {}) do
			if tag ~= "WeaponDisplay" then pcall(function() cs:AddTag(inst, tag) end) end
		end
		for k, v in pairs(n.attrs or {}) do
			local tv = type(v)
			if tv == "string" or tv == "number" or tv == "boolean" then
				pcall(function() inst:SetAttribute(k, v) end)
			end
		end
	end

	local function mark(kind, inst)
		local list = touched[kind]
		if not list or not inst then return end
		if not table.find(list, inst) then list[#list + 1] = inst end
	end

	local function buildfx(entry, owner, body, host)
		local map = {}
		local sounds = {}
		local slot = entry.kind
		for _, n in ipairs(entry.display and entry.display.nodes or {}) do
			local cls = n.class
			local tex = n.props and n.props.Texture
			local texdead = tex and tex ~= "" and not assetok("image", tex)
			local parent = (n.parent and map[n.parent])
				or ((cls == "Attachment" or cls == "Sound" or cls == "Beam") and host or body)

			if texdead then
				continue
			end

			if cls == "Sound" then
				local id = n.props and n.props.SoundId
				if id and id ~= "" and assetok("sound", id) then
					local existing = parent:FindFirstChild(n.name)
					if existing and existing:IsA("Sound") then
						if not snaps[existing] then
							snaps[existing] = { sndid = existing.SoundId, vol = existing.Volume, speed = existing.PlaybackSpeed }
						end
						mark(slot, existing)
						setprops(existing, n.props)
						sounds[n.name] = existing
						if n.path then map[n.path] = existing end
					else
						local s = Instance.new("Sound")
						s.Name = n.name
						setprops(s, n.props)
						s.Parent = parent
						sounds[n.name] = s
						if n.path then map[n.path] = s end
						keep(owner, s)
					end
				end
			elseif cls == "Attachment" then
				local existing = parent:FindFirstChild(n.name)
				if existing and existing:IsA("Attachment") then
					if not snaps[existing] then snaps[existing] = { atcf = existing.CFrame } end
					mark(slot, existing)
					setprops(existing, n.props)
					if n.path then map[n.path] = existing end
				else
					local at = Instance.new("Attachment")
					at.Name = n.name
					setprops(at, n.props)
					at.Parent = parent
					if n.path then map[n.path] = at end
					keep(owner, at)
				end
			elseif fxclass[cls] then
				local old = parent:FindFirstChild(n.name)
				if old and old.ClassName == cls then pcall(function() old:Destroy() end) end
				local inst = Instance.new(cls)
				inst.Name = n.name
				setprops(inst, n.props)
				if tex then pcall(function() inst.Texture = tex end) end
				inst.Parent = parent
				tagmeta(inst, n)
				if n.path then map[n.path] = inst end
				keep(owner, inst)
			end
		end
		return sounds
	end

	local function dressdisp(entry)
		local disp = dispref(entry.kind)
		if not disp then return false end
		if not snaps[disp] then
			snaps[disp] = { ltm = disp.LocalTransparencyModifier, size = disp.Size, trans = disp.Transparency }
		end
		wipe(disp)
		for _, ch in ipairs(disp:GetChildren()) do
			if ch.Name == "SkinBody" then ch:Destroy() end
		end
		disp.LocalTransparencyModifier = 1
		pcall(function() disp.Transparency = 1 end)

		local props = rootprops(entry)
		if not props then return false end
		local body = mkroot(entry)
		if not body then return false end
		body.Name = "SkinBody"
		body.Parent = disp
		keep(disp, body)
		body.CFrame = disp.CFrame
		local wc = Instance.new("WeldConstraint")
		wc.Part0 = disp
		wc.Part1 = body
		wc.Parent = body

		buildkids(entry, disp, body, disp)
		buildfx(entry, disp, body, body)
		return true
	end

	local function dresstool(entry)
		local tool = toolof(entry.kind)
		if not tool then return false end
		local hnd = tool:FindFirstChild("Handle") or tool:FindFirstChildWhichIsA("BasePart")
		if not hnd then return false end

		local base = originof(tool, hnd)

		if not snaps[tool] then
			snaps[tool] = {
				grip = base.grip, size = base.size, htrans = base.htrans,
				ltm = base.ltm, handle = hnd,
			}
		end
		wipe(tool)
		for _, ch in ipairs(tool:GetChildren()) do
			if ch.Name == "SkinBody" then ch:Destroy() end
		end

		local props = rootprops(entry)
		if not props then return false end

		hnd.LocalTransparencyModifier = 1
		pcall(function() hnd.Transparency = 1 end)
		local want = tov3(props.Size)
		if want then hnd.Size = want end

		local grip = gripfor(entry)
		if grip then
			pcall(function() tool.Grip = CFrame.new(table.unpack(grip)) end)
		else
			pcall(function()
				local off = canongrip[entry.kind] or base.grip.Position
				tool.Grip = axisrot(entry.kind, want) * CFrame.new(off)
			end)
		end

		local body = mkroot(entry)
		if not body then return false end
		body.Name = "SkinBody"
		body.Parent = tool
		keep(tool, body)
		body.CFrame = hnd.CFrame
		local wc = Instance.new("WeldConstraint")
		wc.Part0 = hnd
		wc.Part1 = body
		wc.Parent = body

		buildkids(entry, tool, body, tool)
		local sounds = buildfx(entry, tool, body, hnd)

		table.clear(muted[entry.kind])
		local custom = false
		for _ in pairs(sounds) do
			custom = true
			break
		end
		if custom then
			for _, d in ipairs(tool:GetDescendants()) do
				if d:IsA("Sound") and mutenames[d.Name] and not sounds[d.Name] then
					if not snaps[d] then snaps[d] = { mutedvol = d.Volume } end
					pcall(function() d.Volume = 0 end)
					table.insert(muted[entry.kind], d)
				end
			end
		end
		slotsounds[entry.kind] = sounds

		local prev = holdtracks[tool]
		if prev then pcall(function() prev:Stop() end) pcall(function() prev:Destroy() end) holdtracks[tool] = nil end

		local holdid
		for _, n in ipairs(entry.tool and entry.tool.nodes or {}) do
			if n.class == "Animation" and n.name == "CustomHold" and n.props and n.props.AnimationId then
				holdid = n.props.AnimationId
				break
			end
		end

		if holdid and holdid ~= "" then
			local hum = lp.Character and lp.Character:FindFirstChildOfClass("Humanoid")
			local anmt = hum and hum:FindFirstChildOfClass("Animator")
			if anmt then
				local anim = Instance.new("Animation")
				anim.AnimationId = holdid
				anim.Parent = tool
				keep(tool, anim)
				local ok, tr = pcall(function() return anmt:LoadAnimation(anim) end)
				if ok and tr then
					tr.Priority = Enum.AnimationPriority.Action
					tr.Looped = true
					holdtracks[tool] = tr
					if tool.Parent == lp.Character then pcall(function() tr:Play() end) end
					gunconns[#gunconns + 1] = tool.Equipped:Connect(function()
						local t = holdtracks[tool]
						if t then pcall(function() t:Play() end) end
					end)
					gunconns[#gunconns + 1] = tool.Unequipped:Connect(function()
						local t = holdtracks[tool]
						if t then pcall(function() t:Stop() end) end
					end)
				end
			end
		end

		return true
	end

	local function equip(entry)
		local ok, pd = pcall(function() return require(rstor.Modules.ProfileData) end)
		if ok and pd and pd.Weapons and pd.Weapons.Equipped then
			pd.Weapons.Equipped[entry.kind] = entry.id
		end
		pcall(function()
			rstor.Remotes.Inventory.Equip:FireServer(entry.id, "Weapons")
		end)
	end

	local function applysnap(inst, snap)
		if not inst.Parent then return end
		if snap.grip then pcall(function() inst.Grip = snap.grip end) end
		if snap.sndid then
			pcall(function()
				inst.SoundId = snap.sndid
				inst.Volume = snap.vol
				inst.PlaybackSpeed = snap.speed
			end)
		end
		if snap.mutedvol then pcall(function() inst.Volume = snap.mutedvol end) end
		if snap.atcf then pcall(function() inst.CFrame = snap.atcf end) end
		if snap.trans ~= nil then pcall(function() inst.Transparency = snap.trans end) end
		if snap.handle and snap.handle.Parent then
			pcall(function()
				snap.handle.Size = snap.size
				snap.handle.Transparency = snap.htrans or 0
				snap.handle.LocalTransparencyModifier = snap.ltm
			end)
		elseif snap.ltm then
			pcall(function()
				inst.Size = snap.size
				inst.LocalTransparencyModifier = snap.ltm
			end)
		end
	end

	local function unsnap(inst)
		local snap = snaps[inst]
		if not snap then return end
		applysnap(inst, snap)
		snaps[inst] = nil
	end

	local function restoreslot(kind)
		picks[kind] = nil
		slotsounds[kind] = nil
		for _, snd in ipairs(muted[kind]) do
			unsnap(snd)
		end
		table.clear(muted[kind])

		local objs = {}
		local disp = dispref(kind)
		if disp then objs[#objs + 1] = disp end
		local tool = toolof(kind)
		if tool then
			objs[#objs + 1] = tool
			local tr = holdtracks[tool]
			if tr then pcall(function() tr:Stop() end) pcall(function() tr:Destroy() end) holdtracks[tool] = nil end
		end

		for _, obj in ipairs(objs) do
			local hnd = obj:IsA("Tool") and obj:FindFirstChild("Handle") or nil
			wipe(obj)
			unsnap(obj)
			if hnd then unsnap(hnd) end
		end

		for _, inst in ipairs(touched[kind]) do
			unsnap(inst)
		end
		table.clear(touched[kind])
	end

	local function restore()
		wipe()
		for inst, snap in pairs(snaps) do
			applysnap(inst, snap)
		end
		table.clear(snaps)
		table.clear(touched.Knife)
		table.clear(touched.Gun)
		picks.Knife, picks.Gun = nil, nil
	end

	local function apply(entry)
		if not entry then return end
		equip(entry)
		task.wait(0.35)
		dressdisp(entry)
		dresstool(entry)
	end

	local function applyall()
		for _, kind in ipairs({ "Knife", "Gun" }) do
			local entry = picks[kind]
			if entry then pcall(apply, entry) end
		end
	end

	local function dressed(owner)
		for _, rec in ipairs(made) do
			if rec.owner == owner and rec.inst and rec.inst.Parent then return true end
		end
		return false
	end

	local function rarname(entry)
		local m = entry.meta or {}
		return tostring(m.Rarity or "unknown"):lower()
	end

	local function loaddb()
		if type(isfile) ~= "function" or not isfile(dbfile) then return false end
		local ok, raw = pcall(readfile, dbfile)
		if not ok or type(raw) ~= "string" or #raw < 32 then return false end
		local dok, data = pcall(function() return jsn:JSONDecode(raw) end)
		if not dok or type(data) ~= "table" or type(data.items) ~= "table" then return false end
		skdb, schema = data, data.schema
		collectdbfx(data.items)
		buildgripidx()
		return true
	end

	local function harvestraw()
		local pull = getgenv().shitaro_data

		if type(pull) == "function" then
			local ok, body = pcall(pull, harvestname)

			if ok and type(body) == "string" and #body >= 8 then
				return body
			end
		end

		if type(isfile) ~= "function" or not isfile(harvestfile) then return nil end
		local ok, raw = pcall(readfile, harvestfile)
		if not ok or type(raw) ~= "string" or #raw < 8 then return nil end
		return raw
	end

	local function loadharvest()
		local raw = harvestraw()
		if type(raw) ~= "string" then return 0 end
		local dok, data = pcall(function() return jsn:JSONDecode(raw) end)
		if not dok or type(data) ~= "table" or type(data.entries) ~= "table" then return 0 end

		if not skdb then
			skdb = { items = {}, harvest = {}, templates = {} }
		end
		skdb.items = skdb.items or {}

		local n = 0
		for _, rec in pairs(data.entries) do
			local id = rec.name
			if id and rec.display then
				local state = skflags and skflags.status and skflags.status[id] or nil
				local prev = skdb.items[id]
				if not prev or not prev.display or state == "collide" or state == "empty" then
					skdb.items[id] = {
						id = id,
						kind = rec.kind or (rec.meta and rec.meta.ItemType),
						meta = rec.meta or (prev and prev.meta),
						display = rec.display,
						tool = rec.tool or (prev and prev.tool),
						fx = rec.fx or (prev and prev.fx),
						live = prev and prev.live,
						fromharvest = true,
					}
					if skflags and skflags.status then skflags.status[id] = "ok" end
					n += 1
				end
			end
		end
		buildgripidx()
		return n
	end

	local function loadside()
		local function grab(path)
			if type(isfile) ~= "function" or not isfile(path) then return nil end
			local ok, raw = pcall(readfile, path)
			if not ok or type(raw) ~= "string" or #raw < 8 then return nil end
			local dok, data = pcall(function() return jsn:JSONDecode(raw) end)
			return dok and type(data) == "table" and data or nil
		end
		skflags = grab(flagfile)
		skassets = grab(assetfile)
	end

	local function build()
		rows, byname = {}, {}
		local seen = {}
		if not skdb then return end
		local ids = {}
		for id in pairs(skdb.items) do ids[#ids + 1] = id end
		table.sort(ids)
		for _, id in ipairs(ids) do
			local entry = skdb.items[id]
			local meta = entry.meta or {}
			local kind = entry.kind or meta.ItemType
			local rar = rarname(entry)
			seen[rar] = true
			local pass = (fkind == "all")
				or (fkind == "knives" and kind == "Knife")
				or (fkind == "guns" and kind == "Gun")
			local state = recstate(id)
			local statepass = (fstate == "all")
				or (fstate == "working" and state == "ok")
				or (fstate == "broken" and state ~= "ok")
			if pass and statepass and (frar == "all" or frar == rar) then
				local label = tostring(meta.ItemName or id)
				local key = id
				byname[key] = entry
				rows[#rows + 1] = {
					name = key,
					display = label .. "  ·  " .. rar .. (state == "ok" and "" or ("  ·  " .. state)),
					id = iconid(meta.Image) or iconid(meta.ItemID),
				}
			end
		end
		rarities = { "all" }
		local rl = {}
		for r in pairs(seen) do rl[#rl + 1] = r end
		table.sort(rl)
		for _, r in ipairs(rl) do rarities[#rarities + 1] = r end
	end

	local function push()
		build()
		if slist then pcall(function() slist:SetData(rows) end) end
		if rardrop then pcall(function() rardrop:SetValues(rarities) end) end
	end

	local filt = skin_tab:AddSection({
		Name = "filter",
		Position = 'left'
	})

	filt:AddDropdown({
		Name = "slot",
		Default = "all",
		Values = { "all", "knives", "guns" },
		Flag = "skin_slot",
		Callback = function(v)
			fkind = tostring(v or "all")
			push()
		end
	})

	rardrop = filt:AddDropdown({
		Name = "rarity",
		Default = "all",
		Values = { "all" },
		Flag = "skin_rarity",
		Callback = function(v)
			frar = tostring(v or "all")
			push()
		end
	})

	filt:AddDropdown({
		Name = "records",
		ToolTip = "working = clean dump entries, broken = collided or empty, needs redump",
		Default = "working",
		Values = { "working", "all", "broken" },
		Flag = "skin_records",
		Callback = function(v)
			fstate = tostring(v or "working")
			push()
		end
	})

	filt:AddToggle({
		Name = "keep applied",
		ToolTip = "Redress on respawn and when the tool is handed out",
		Default = true,
		Flag = "skin_keep",
		Callback = function(v)
			watch = v and true or false
		end
	})

	filt:AddButton({
		Name = "restore knife",
		Icon = "rotate-ccw",
		Callback = function()
			restoreslot("Knife")
			if syncsel then syncsel() end
		end
	})

	filt:AddButton({
		Name = "restore gun",
		Icon = "rotate-ccw",
		Callback = function()
			restoreslot("Gun")
			if syncsel then syncsel() end
		end
	})

	filt:AddButton({
		Name = "restore all",
		Icon = "rotate-ccw",
		Callback = function()
			restore()
			if slist then pcall(function() slist:Clear() end) end
			if syncsel then syncsel() end
		end
	})

	local pushing = false

	local function selection()
		local out = {}
		for _, kind in ipairs({ "Knife", "Gun" }) do
			local entry = picks[kind]
			if entry and entry.id then out[#out + 1] = entry.id end
		end
		return out
	end

	syncsel = function()
		if not slist then return end
		pushing = true
		pcall(function() slist:SetValue(selection()) end)
		pushing = false
		if seltext then
			local k = picks.Knife and (picks.Knife.meta and picks.Knife.meta.ItemName or picks.Knife.id) or "none"
			local g = picks.Gun and (picks.Gun.meta and picks.Gun.meta.ItemName or picks.Gun.id) or "none"
			seltext:SetValue("knife: " .. k .. "  |  gun: " .. g)
		end
	end

	local function onpick(v)
		if pushing then return end

		local keys = {}
		if type(v) == "table" then
			for _, item in ipairs(v) do
				local key = type(item) == "table" and (item.name or item[1]) or item
				if type(key) == "string" and key ~= "" then keys[#keys + 1] = key end
			end
		elseif type(v) == "string" and v ~= "" then
			keys[1] = v
		end

		local found = { Knife = {}, Gun = {} }
		for _, key in ipairs(keys) do
			local entry = byname[key]
			if entry then
				local kind = entry.kind or (entry.meta and entry.meta.ItemType)
				local bucket = found[kind]
				if bucket then bucket[#bucket + 1] = entry end
			end
		end

		local wanted = { Knife = nil, Gun = nil }
		for _, kind in ipairs({ "Knife", "Gun" }) do
			local bucket = found[kind]
			if #bucket > 0 then
				local fresh = nil
				for _, entry in ipairs(bucket) do
					if entry ~= picks[kind] then
						fresh = entry
						break
					end
				end
				wanted[kind] = fresh or bucket[1]
			end
		end

		for _, kind in ipairs({ "Knife", "Gun" }) do
			local entry = wanted[kind]
			local current = picks[kind]
			if entry ~= current then
				restoreslot(kind)
				if entry then
					picks[kind] = entry
					task.spawn(function()
						pcall(apply, entry)
					end)
				end
			end
		end

		syncsel()
	end

	seltext = skin_tab:AddSection({
		Name = "applied",
		Position = 'left'
	}):AddLabel("knife: none  |  gun: none", false)

	slist = skin_tab:AddImageList({
		Name = "skins",
		Icon = "125353572203968",
		Position = 'full',
		Thumb = "Asset",
		Height = 320,
		Cell = 74,
		Multi = true,
		Reset = true,
		Tools = false,
		Empty = "run dump_weapons or mm2_harvest first",
		Default = {},
		Values = rows,
		Flag = "skin_library",
		Callback = onpick
	})

	task.spawn(function()
		loadside()
		local ok = loaddb()
		local extra = loadharvest()
		prunefx()
		if ok or extra > 0 then push() end
	end)

	do
		local ws = rstor:FindFirstChild("ClientServices")
		ws = ws and ws:FindFirstChild("WeaponService")
		local fired = ws and ws:FindFirstChild("GunFired")
		if fired and fired:IsA("RemoteEvent") then
			table.insert(gunconns, fired.OnClientEvent:Connect(function(source)
				local sounds = slotsounds.Gun
				if not sounds then return end
				local tool = toolof("Gun")
				if not tool or tool.Parent ~= lp.Character then return end
				if typeof(source) == "Instance" and not source:IsDescendantOf(tool) then return end
				local alt = sounds.AltSound or sounds.Gunshot
				if alt and alt.Parent then
					pcall(function()
						alt.TimePosition = 0
						alt:Play()
					end)
				end
			end))
		end
	end

	task.spawn(function()
		while alive do
			task.wait(0.6)
			if watch then
				for _, kind in ipairs({ "Knife", "Gun" }) do
					local entry = picks[kind]
					if entry then
						local disp = dispref(kind)
						if disp and not dressed(disp) then
							pcall(dressdisp, entry)
						elseif disp then
							disp.LocalTransparencyModifier = 1
							if disp.Transparency ~= 1 then pcall(function() disp.Transparency = 1 end) end
						end
						local tool = toolof(kind)
						if tool and not dressed(tool) then
							pcall(dresstool, entry)
						elseif tool then
							local hnd = tool:FindFirstChild("Handle")
							if hnd then
								hnd.LocalTransparencyModifier = 1
								if hnd.Transparency ~= 1 then pcall(function() hnd.Transparency = 1 end) end
							end
							for _, snd in ipairs(muted[kind]) do
								if snd.Parent and snd.Volume ~= 0 then
									pcall(function() snd.Volume = 0 end)
								end
							end
						end
					end
				end
			end
		end
	end)

	local bag_conn, char_conn

	char_conn = lp.CharacterAdded:Connect(function()
		table.clear(snaps)
		table.clear(origins)
		table.clear(touched.Knife)
		table.clear(touched.Gun)
		wipe()
		task.wait(1.5)
		if watch then applyall() end
	end)

	local function hookbag(root)
		if not root then return end
		return root.ChildAdded:Connect(function(child)
			if not watch then return end
			if not child:IsA("Tool") then return end
			local entry = picks[child.Name]
			if not entry then return end
			child:WaitForChild("Handle", 3)
			task.wait(0.25)
			pcall(dresstool, entry)
		end)
	end

	bag_conn = hookbag(lp:FindFirstChildOfClass("Backpack"))

	local add_conn = lp.ChildAdded:Connect(function(c)
		if c:IsA("Backpack") then
			if bag_conn then pcall(function() bag_conn:Disconnect() end) end
			bag_conn = hookbag(c)
		end
	end)

	getgenv().SKIN_UNLOAD = function()
		alive = false
		picks.Knife, picks.Gun = nil, nil
		for _, c in ipairs({ bag_conn, char_conn, add_conn }) do
			if c then pcall(function() c:Disconnect() end) end
		end
		for _, c in ipairs(gunconns) do pcall(function() c:Disconnect() end) end
		table.clear(gunconns)
		restore()
		table.clear(origins)
		for _, mp in pairs(mcache) do pcall(function() mp:Destroy() end) end
		table.clear(mcache)
	end
end

do
	local players = game:GetService("Players")
	local run = game:GetService("RunService")
	local lp = players.LocalPlayer

	local function crack(payload)
		local plain = shblob(payload)

		if type(plain) ~= "string" or #plain == 0 then return nil end

		local rows = {}

		for line in string.gmatch(plain, "([^\n]+)") do
			local name, id = string.match(line, "^(.-)\t(%d+)$")
			local num = tonumber(id)

			if name and name ~= "" and num and num > 0 then
				rows[#rows + 1] = { name, num }
			end
		end

		if #rows == 0 then return nil end

		return rows
	end

	local vaultName = string.char(109, 97, 112, 115, 46, 98, 105, 110)

	local map_defs, map_rows, picked = {}, {}, {}
	local pads, pad_conns = {}, {}
	local root, lobby_conn, ws_conn = nil, nil, nil
	local hold_conn, tally_conn, spawn_conn = nil, nil, nil
	local vote_on, dupe_on, alive = false, false, true
	local dupe_cap, dupe_used = 3, 0
	local grid, spot, mark = nil, nil, 0
	local session, running, pending = 0, false, false
	local origin = nil

	local function sort_rows()
		table.sort(map_rows, function(a, b)
			return string.lower(a.name) < string.lower(b.name)
		end)
	end

	local function learn(name, image)
		if type(name) ~= "string" or name == "" or name == "MAP NAME" then return false end
		if type(image) ~= "string" or image == "" then return false end
		if map_defs[name] then return false end
		map_defs[name] = image
		map_rows[#map_rows + 1] = { name = name, label = name, image = image }
		return true
	end

	local function sync_picked()
		if not grid then return end
		local v = grid:GetValue()
		table.clear(picked)
		if type(v) == "table" then
			for _, name in ipairs(v) do
				if type(name) == "string" and name ~= "" then picked[name] = true end
			end
		elseif type(v) == "string" and v ~= "" then
			picked[v] = true
		end
	end

	local function soak()
		local rows = nil

		for _ = 1, 3 do
			rows = crack(shnet.lib(vaultName))

			if rows then break end

			task.wait(0.75)
		end

		if not rows then return end

		local grew = false

		for i = 1, #rows do
			if learn(rows[i][1], "rbxassetid://" .. rows[i][2]) then grew = true end
		end

		if not grew then return end

		sort_rows()

		if grid then pcall(function() grid:SetData(map_rows) end) end
		sync_picked()
	end

	local function tally_of(entry)
		return tonumber(string.match(entry.tally.Text, "%d+")) or 0
	end

	local function ready(entry)
		local name = entry.title.Text
		return entry.info.Enabled and name ~= "" and name ~= "MAP NAME"
	end

	local function window_open()
		for i = 1, #pads do
			if pads[i].info.Enabled then return true end
		end
		return false
	end

	local function drop_conns()
		for _, c in ipairs({ hold_conn, tally_conn, spawn_conn }) do
			if c then pcall(function() c:Disconnect() end) end
		end
		hold_conn, tally_conn, spawn_conn = nil, nil, nil
	end

	local function finish()
		drop_conns()
		running = false
		spot = nil
		dupe_used = 0
		origin = nil
	end

	local function stand_point(pad)
		local params = RaycastParams.new()
		params.FilterType = Enum.RaycastFilterType.Exclude
		params.FilterDescendantsInstances = { lp.Character, root }

		local hit = workspace:Raycast(pad.Position + Vector3.new(0, 8, 0), Vector3.new(0, -40, 0), params)
		local y = hit and (hit.Position.Y + 3.2) or pad.Position.Y

		return Vector3.new(pad.Position.X, y, pad.Position.Z)
	end

	local function plant(point)
		local char = lp.Character
		local hrp = char and char:FindFirstChild("HumanoidRootPart")
		if not hrp then return false end
		hrp.CFrame = CFrame.new(point)
		return true
	end

	local function kill_self()
		local char = lp.Character
		local hum = char and char:FindFirstChildWhichIsA("Humanoid")
		if hum then
			hum:ChangeState(Enum.HumanoidStateType.Dead)
			pcall(function() hum.Health = 0 end)
		elseif char then
			pcall(function() char:BreakJoints() end)
		end
	end

	local function choices()
		local out = {}
		for i = 1, #pads do
			local entry = pads[i]
			if ready(entry) and picked[entry.title.Text] then out[#out + 1] = entry end
		end
		return out
	end

	local function begin(id)
		local list = choices()
		if #list == 0 then
			finish()
			return
		end

		local entry = list[math.random(1, #list)]
		spot = stand_point(entry.pad)
		dupe_used = 0
		mark = tally_of(entry)

		local char = lp.Character
		local hrp = char and char:FindFirstChild("HumanoidRootPart")
		if not hrp then finish() return end

		origin = hrp.CFrame

		if not plant(spot) then
			finish()
			return
		end

		if not dupe_on then
			task.delay(0.15, function()
				if session ~= id then return end
				local c2 = lp.Character
				local h2 = c2 and c2:FindFirstChild("HumanoidRootPart")
				if h2 then
					local hum = c2:FindFirstChildWhichIsA("Humanoid")
					if hum then pcall(function() hum:ChangeState(Enum.HumanoidStateType.Physics) end) end
					h2.CFrame = origin
					task.delay(0.05, function()
						local c3 = lp.Character
						local h3 = c3 and c3:FindFirstChildWhichIsA("Humanoid")
						if h3 then pcall(function() h3:ChangeState(Enum.HumanoidStateType.Running) end) end
					end)
				end
				finish()
			end)
			return
		end

		hold_conn = run.Heartbeat:Connect(function()
			if not alive or session ~= id or not spot then return end
			local c2 = lp.Character
			local h2 = c2 and c2:FindFirstChild("HumanoidRootPart")
			if not h2 then return end
			local flat = Vector3.new(h2.Position.X - spot.X, 0, h2.Position.Z - spot.Z)
			if flat.Magnitude > 2.5 then h2.CFrame = CFrame.new(spot) end
		end)

		tally_conn = entry.tally:GetPropertyChangedSignal("Text"):Connect(function()
			if session ~= id or not dupe_on or not entry.info.Enabled then return end
			local now = tally_of(entry)
			if now <= mark then
				mark = now
				return
			end
			mark = now
			if dupe_used >= dupe_cap then
				drop_conns()
				task.defer(function()
					if session ~= id then return end
					local c2 = lp.Character
					local h2 = c2 and c2:FindFirstChild("HumanoidRootPart")
					if h2 and origin then
						local hum = c2:FindFirstChildWhichIsA("Humanoid")
						if hum then pcall(function() hum:ChangeState(Enum.HumanoidStateType.Physics) end) end
						h2.CFrame = origin
						task.delay(0.05, function()
							local c3 = lp.Character
							local h3 = c3 and c3:FindFirstChildWhichIsA("Humanoid")
							if h3 then pcall(function() h3:ChangeState(Enum.HumanoidStateType.Running) end) end
						end)
					end
					finish()
				end)
				return
			end
			dupe_used = dupe_used + 1
			kill_self()
		end)

		spawn_conn = lp.CharacterAdded:Connect(function(char)
			if session ~= id or not dupe_on then return end
			local h2 = char:WaitForChild("HumanoidRootPart", 6)
			if not h2 or session ~= id or not entry.info.Enabled or not spot then return end
			if dupe_used >= dupe_cap then
				if origin then
					local hum = char:FindFirstChildWhichIsA("Humanoid")
					if hum then pcall(function() hum:ChangeState(Enum.HumanoidStateType.Physics) end) end
					h2.CFrame = origin
					task.delay(0.05, function()
						local c3 = lp.Character
						local h3 = c3 and c3:FindFirstChildWhichIsA("Humanoid")
						if h3 then pcall(function() h3:ChangeState(Enum.HumanoidStateType.Running) end) end
					end)
				end
				return
			end
			h2.CFrame = CFrame.new(spot)
		end)
	end

	local function settle()
		pending = false
		if not alive then return end

		local grew = false
		for i = 1, #pads do
			local entry = pads[i]
			if entry.info.Enabled and learn(entry.title.Text, entry.icon.Image) then grew = true end
		end

		if grew then
			sort_rows()
			if grid then pcall(function() grid:SetData(map_rows) end) end
			sync_picked()
		end

		if not window_open() then
			if running then finish() end
			return
		end

		if not vote_on or running then return end

		running = true
		session = session + 1
		begin(session)
	end

	local function schedule()
		if pending or not alive then return end
		pending = true
		task.delay(0.25, settle)
	end

	local function shape(model)
		local pad = model:FindFirstChild("Pad")
		local info = model:FindFirstChild("MapInfoGui")
		local vote = model:FindFirstChild("VoteInfoGui")
		local icon = info and info:FindFirstChild("MapIcon")
		local box = vote and vote:FindFirstChild("Container")
		local title = box and box:FindFirstChild("MapName")
		local tally = box and box:FindFirstChild("Votes")

		if not (pad and info and icon and title and tally) then return nil end

		return { pad = pad, info = info, icon = icon, title = title, tally = tally }
	end

	local function bind(model_root)
		for _, c in ipairs(pad_conns) do pcall(function() c:Disconnect() end) end
		table.clear(pad_conns)
		table.clear(pads)

		root = model_root
		if not root then return end

		for _, model in ipairs(root:GetChildren()) do
			local entry = shape(model)
			if entry then
				pads[#pads + 1] = entry
				pad_conns[#pad_conns + 1] = entry.info:GetPropertyChangedSignal("Enabled"):Connect(schedule)
				pad_conns[#pad_conns + 1] = entry.title:GetPropertyChangedSignal("Text"):Connect(schedule)
				pad_conns[#pad_conns + 1] = entry.icon:GetPropertyChangedSignal("Image"):Connect(schedule)
			end
		end

		schedule()
	end

	local function watch_lobby(lobby)
		if lobby_conn then
			pcall(function() lobby_conn:Disconnect() end)
			lobby_conn = nil
		end

		if not lobby then
			bind(nil)
			return
		end

		lobby_conn = lobby.ChildAdded:Connect(function(child)
			if child.Name == "VotePads" then
				task.defer(function() bind(child) end)
			end
		end)

		bind(lobby:FindFirstChild("VotePads"))
	end

	local page = (type(misc.AddSub) == "function") and misc:AddSub({
		Name = "maps",
		Icon = "map",
		Tip = "map vote"
	}) or misc

	local sec = page:AddSection({
		Name = "voting",
		Position = 'full'
	})

	local auto = sec:AddToggle({
		Name = "auto vote",
		Default = false,
		Flag = "map_vote_auto",
		Option = true,
		Callback = function(v)
			vote_on = v
			if v then
				schedule()
			else
				finish()
			end
		end
	})

	auto.Option:AddToggle({
		Name = "dupe",
		Default = false,
		Flag = "map_vote_dupe",
		Callback = function(v)
			dupe_on = v
			if not v then
				for _, c in ipairs({ tally_conn, spawn_conn }) do
					if c then pcall(function() c:Disconnect() end) end
				end
				tally_conn, spawn_conn = nil, nil
			end
		end
	})

	auto.Option:AddSlider({
		Name = "count",
		Default = 3,
		Min = 1,
		Max = 11,
		Flag = "map_vote_dupe_cap",
		Callback = function(v)
			dupe_cap = math.clamp(math.floor(tonumber(v) or 3), 1, 10)
		end
	})

	grid = page:AddImageList({
		Name = "maps",
		Icon = "map",
		Position = 'full',
		Multi = true,
		Thumb = "Asset",
		Height = 300,
		Cell = 78,
		Tools = false,
		Blank = "map",
		Empty = "no maps seen yet",
		Values = map_rows,
		Default = {},
		Flag = "map_vote_priority",
		Callback = function(v)
			table.clear(picked)

			if type(v) == "table" then
				for _, name in ipairs(v) do
					if type(name) == "string" and name ~= "" then picked[name] = true end
				end
			elseif type(v) == "string" and v ~= "" then
				picked[v] = true
			end
		end
	})

	watch_lobby(workspace:FindFirstChild("SummerLobby"))

	ws_conn = workspace.ChildAdded:Connect(function(child)
		if child.Name == "Lobby" then
			task.defer(function() watch_lobby(child) end)
		end
	end)

	task.spawn(soak)

	getgenv().MAPVOTE_UNLOAD = function()
		alive = false
		vote_on, dupe_on = false, false
		finish()

		for _, c in ipairs(pad_conns) do pcall(function() c:Disconnect() end) end
		table.clear(pad_conns)
		table.clear(pads)

		for _, c in ipairs({ lobby_conn, ws_conn }) do
			if c then pcall(function() c:Disconnect() end) end
		end

		lobby_conn, ws_conn, root = nil, nil, nil
	end
end
