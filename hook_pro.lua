local bit_band = bit32.band
local bit_bxor = bit32.bxor
local bit_rrotate = bit32.rrotate
local bit_lshift = bit32.lshift
local bit_rshift = bit32.rshift
local bit_bor = bit32.bor
local bit_bnot = bit32.bnot
local string_char = string.char
local string_byte = string.byte
local IV = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
}
local SIGMA_FLAT = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
    10, 11, 12, 13, 14, 15, 14, 10, 4, 8,
    9, 15, 13, 6, 1, 12, 0, 2, 11, 7,
    5, 3, 11, 8, 12, 0, 5, 2, 15, 13,
    10, 14, 3, 6, 7, 1, 9, 4, 7, 9,
    3, 1, 13, 12, 11, 14, 2, 6, 5, 10,
    4, 0, 15, 8, 9, 0, 5, 7, 2, 4,
    10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
    2, 12, 6, 10, 0, 11, 8, 3, 4, 13,
    7, 5, 15, 14, 1, 9, 12, 5, 1, 15,
    14, 13, 4, 10, 0, 7, 6, 3, 9, 2,
    8, 11, 13, 11, 7, 14, 12, 1, 3, 9,
    5, 0, 15, 4, 8, 6, 2, 10, 6, 15,
    14, 9, 11, 3, 0, 8, 12, 2, 13, 7,
    1, 4, 10, 5, 10, 2, 8, 4, 7, 6,
    1, 5, 15, 11, 9, 14, 3, 12, 13, 0
}
local function string_rep(s, n)
    if n <= 0 then
        return ""
    end
    local result = ""
    for _ = 1, n do
        result = result .. s
    end
    return result
end
local function table_concat(tbl)
    local result = ""
    for i = 1, #tbl do
        if tbl[i] then
            result = result .. tbl[i]
        end
    end
    return result
end
local function string_sub(s, i, j)
    if type(s) ~= "string" then
        return ""
    end
    local len = #s
    i = i or 1
    j = j or len
    if i < 0 then
        i = len + i + 1
    end
    if j < 0 then
        j = len + j + 1
    end
    if i < 1 then
        i = 1
    end
    if j > len then
        j = len
    end
    if i > j then
        return ""
    end
    local result = {}
    for k = i, j do
        result[#result + 1] = string_char(string_byte(s, k))
    end
    return table_concat(result)
end
local function to_bytes_le(n)
    return string_char(
        bit_band(n, 0xff),
        bit_band(bit_rshift(n, 8), 0xff),
        bit_band(bit_rshift(n, 16), 0xff),
        bit_band(bit_rshift(n, 24), 0xff)
    )
end
local function from_bytes_le(s, i)
    i = i or 1
    local b1, b2, b3, b4 = string_byte(s, i, i + 3)
    return bit_bor(b1 or 0, bit_lshift(b2 or 0, 8), bit_lshift(b3 or 0, 16), bit_lshift(b4 or 0, 24))
end
local function compress(h, t_low, t_high, block, is_last_block)
    local v = {}
    local m = {}
    for i = 1, 8 do
        v[i] = h[i]
    end
    for i = 1, 8 do
        v[i + 8] = IV[i]
    end
    v[13] = bit_bxor(v[13], t_low)
    v[14] = bit_bxor(v[14], t_high)
    if is_last_block then
        v[15] = bit_bnot(v[15])
    end
    for i = 1, 16 do
        m[i] = from_bytes_le(block, (i - 1) * 4 + 1)
    end
    for r = 0, 9 do
        local s_offset = r * 16

        local va, vb, vc, vd = v[1], v[5], v[9], v[13]
        local x, y = m[SIGMA_FLAT[s_offset + 1] + 1], m[SIGMA_FLAT[s_offset + 2] + 1]
        va = bit_band(va + vb + x, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 16)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 12)
        va = bit_band(va + vb + y, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 8)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 7)
        v[1], v[5], v[9], v[13] = va, vb, vc, vd

        local va, vb, vc, vd = v[2], v[6], v[10], v[14]
        local x, y = m[SIGMA_FLAT[s_offset + 3] + 1], m[SIGMA_FLAT[s_offset + 4] + 1]
        va = bit_band(va + vb + x, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 16)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 12)
        va = bit_band(va + vb + y, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 8)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 7)
        v[2], v[6], v[10], v[14] = va, vb, vc, vd

        local va, vb, vc, vd = v[3], v[7], v[11], v[15]
        local x, y = m[SIGMA_FLAT[s_offset + 5] + 1], m[SIGMA_FLAT[s_offset + 6] + 1]
        va = bit_band(va + vb + x, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 16)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 12)
        va = bit_band(va + vb + y, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 8)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 7)
        v[3], v[7], v[11], v[15] = va, vb, vc, vd

        local va, vb, vc, vd = v[4], v[8], v[12], v[16]
        local x, y = m[SIGMA_FLAT[s_offset + 7] + 1], m[SIGMA_FLAT[s_offset + 8] + 1]
        va = bit_band(va + vb + x, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 16)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 12)
        va = bit_band(va + vb + y, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 8)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 7)
        v[4], v[8], v[12], v[16] = va, vb, vc, vd

        local va, vb, vc, vd = v[1], v[6], v[11], v[16]
        local x, y = m[SIGMA_FLAT[s_offset + 9] + 1], m[SIGMA_FLAT[s_offset + 10] + 1]
        va = bit_band(va + vb + x, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 16)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 12)
        va = bit_band(va + vb + y, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 8)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 7)
        v[1], v[6], v[11], v[16] = va, vb, vc, vd

        local va, vb, vc, vd = v[2], v[7], v[12], v[13]
        local x, y = m[SIGMA_FLAT[s_offset + 11] + 1], m[SIGMA_FLAT[s_offset + 12] + 1]
        va = bit_band(va + vb + x, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 16)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 12)
        va = bit_band(va + vb + y, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 8)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 7)
        v[2], v[7], v[12], v[13] = va, vb, vc, vd

        local va, vb, vc, vd = v[3], v[8], v[9], v[14]
        local x, y = m[SIGMA_FLAT[s_offset + 13] + 1], m[SIGMA_FLAT[s_offset + 14] + 1]
        va = bit_band(va + vb + x, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 16)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 12)
        va = bit_band(va + vb + y, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 8)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 7)
        v[3], v[8], v[9], v[14] = va, vb, vc, vd

        local va, vb, vc, vd = v[4], v[5], v[10], v[15]
        local x, y = m[SIGMA_FLAT[s_offset + 15] + 1], m[SIGMA_FLAT[s_offset + 16] + 1]
        va = bit_band(va + vb + x, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 16)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 12)
        va = bit_band(va + vb + y, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 8)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 7)
        v[4], v[5], v[10], v[15] = va, vb, vc, vd
    end
    for i = 1, 8 do
        h[i] = bit_bxor(h[i], v[i], v[i + 8])
    end
end
local function blake2s(message, mode, length, key)
    local block_byte = 64
    local hexchars = "0123456789abcdef"
    mode = mode or "hex"
    length = length or 256
    key = key or ""
    if type(length) ~= "number" or length % 8 ~= 0 then
        return nil
    end
    local length_bytes = length / 8
    if length_bytes <= 0 or length_bytes > 32 then
        return nil
    end
    if #key > 32 then
        return nil
    end
    if type(message) ~= "string" then
        return nil
    end
    local h = {}
    for i = 1, 8 do
        h[i] = IV[i]
    end
    local p0_keylen = bit_lshift(#key, 8)
    local p0 = bit_bor(length_bytes, p0_keylen, 0x01010000)
    h[1] = bit_bxor(h[1], p0)
    local stream = message
    if #key > 0 then
        local key_block = key .. string_rep("\0", block_byte - #key)
        stream = key_block .. message
    end
    local t_low, t_high = 0, 0
    local offset = 1
    local stream_len = #stream
    while offset <= stream_len - block_byte do
        local chunk = string_sub(stream, offset, offset + block_byte - 1)
        t_low = t_low + block_byte
        if t_low > 0xffffffff then
            t_low = bit_band(t_low, 0xffffffff)
            t_high = t_high + 1
        end
        compress(h, t_low, t_high, chunk, false)
        offset = offset + block_byte
    end
    local last_chunk = string_sub(stream, offset)
    local last_len = #last_chunk
    t_low = t_low + last_len
    if t_low > 0xffffffff then
        t_low = bit_band(t_low, 0xffffffff)
        t_high = t_high + 1
    end
    local padded_chunk = last_chunk .. string_rep("\0", block_byte - last_len)
    compress(h, t_low, t_high, padded_chunk, true)
    local raw_digest_parts = {}
    for i = 1, 8 do
        raw_digest_parts[i] = to_bytes_le(h[i])
    end
    local raw_digest = string_sub(table_concat(raw_digest_parts), 1, length_bytes)
    if mode == "byte" or mode == "raw" then
        return raw_digest
    else
        local hex_parts = {}
        for i = 1, length_bytes do
            local b = string_byte(raw_digest, i)
            local high = bit_rshift(b, 4)
            local low = bit_band(b, 0x0F)
            hex_parts[i] =
                string_sub(hexchars, high + 1, high + 1) .. string_sub(hexchars, low + 1, low + 1)
        end
        return table_concat(hex_parts)
    end
end
local function kdf_blake2s_keyed(ikm, salt, info, length)
    local HASH_LEN = 32
    if type(length) ~= "number" or length > 255 * HASH_LEN then
        while task.wait() do end
    end
    if #salt > HASH_LEN then
        salt = blake2s(salt, "raw", 256)
    end
    local prk = blake2s(ikm, "raw", 256, salt)
    local okm, T = "", ""
    local num_blocks = ((length + HASH_LEN - 1) - ((length + HASH_LEN - 1) % HASH_LEN)) / HASH_LEN
    for i = 1, num_blocks do
        T = blake2s(T .. info .. string.char(i), "raw", 256, prk)
        okm = okm .. T
    end
    return okm
end
local function hex_to_binary(hex_str)
    return hex_str:gsub("..", function(hex)
        return string.char(tonumber(hex, 16))
    end)
end
local function binary_to_hex(binary_str)
    return binary_str:gsub(".", function(binary)
        return string.format("%02x", string.byte(binary))
    end)
end
local HttpService = game:GetService("HttpService")
local Keys = HttpService:JSONDecode(readfile("keys.json"))
local Init = HttpService:JSONDecode(readfile("init.json"))
local ClientKey
local Nonce
local Auth
RequestCall = hookfunction(request, function(t)
    local Response = RequestCall(t)
    local Token = t.Url:match("^https://api%.a%-ditto%.xyz/a%-ditto/api/v2/auth/gettoken%?pid="..Keys.pid.."&nonce=(%x+)$")
    local Heartbeat = t.Url:match("^https://api%.a%-ditto%.xyz/a%-ditto/api/v2/auth/luau/heartbeat/pro/"..Init.heartbeattoken:gsub("([^$()%.[]*+-?])", "%%%1").."/(%x+)/.+$")
    if Token then
        Nonce = Token
        Auth = HttpService:JSONDecode(Response.Body)
        ClientKey = kdf_blake2s_keyed(
            hex_to_binary(Keys.secret_key1),
            blake2s(Nonce..hex_to_binary(Keys.pid)..Keys.public_key..hex_to_binary(Keys.main_key), "raw", 256)..
            hex_to_binary(Keys.secret_key2)..blake2s(hex_to_binary(Keys.pid)..base64.encode(getfenv().ADittoKey):gsub("=", ""), "raw", 256),
            hex_to_binary(Keys.pid), 32
        )
    elseif t.Url:match("^https://api%.a%-ditto%.xyz/a%-ditto/api/v2/auth/luau/init/pro/"..Keys.pid.."/.-%.[^%.]+$") then
        Init.sign = binary_to_hex(blake2s(
            Init.nonce..Init.code..(Init.exp or Keys.exp_key)..(Init.premium and Keys.premium_key1 or Keys.premium_key2)..Auth.tid..Keys.pid,
            "raw", 256, ClientKey
        ))
        local Payload = base64.encode(HttpService:JSONEncode(Init))
        Response.Body = Payload.."."..base64.encode(blake2s(Payload, "raw", 256, hex_to_binary(Keys.main_key)))
    elseif t.Url:match("^https://api%.a%-ditto%.xyz/a%-ditto/api/v2/auth/luau/group/pro/"..Init.token:gsub("([^$()%.[]*+-?])", "%%%1").."%?sign=.+$") then
        local Payload = base64.encode(HttpService:JSONEncode(Init))
        Response.Body = Payload.."."..base64.encode(blake2s(Payload..Init.tid..Nonce..Init.dittoid, "raw", 256, ClientKey))
    elseif Heartbeat then
        Init.signature = binary_to_hex(blake2s(
            Keys.pid..Init.dittoid..Init.hbtid..getfenv().ADittoKey..Init.nonce..Auth.nonce..Auth.tid..hex_to_binary(Heartbeat)..hex_to_binary(Nonce)..hex_to_binary(Init.dittononce),
            "raw", 256, ClientKey
        ))
        local Payload = base64.encode(HttpService:JSONEncode(Init))
        Response.Body = Payload.."."..base64.encode(blake2s(Payload, "raw", 256, ClientKey))
    end
    return Response
end)
SubCall = hookfunction(string.sub, function(self, ...)
    if self:match("^%x+$") then
        print(self)
    end
    return SubCall(self, ...)
end)
XPCall = hookfunction(xpcall, function(func, err, ...)
    return XPCall(func, (checkcaller() and function(e)
        print(e)
    end or err), ...)

end)
