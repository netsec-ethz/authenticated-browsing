------------------------------------------------------------------------
--- @file abext.lua
--- @brief (Authenticated Browsing Extension Header) utility.
--- Utility functions for the abext_header structs 
------------------------------------------------------------------------

local ffi = require "ffi"
require "proto.template"
local initHeader = initHeader

---------------------------------------------------------------------------
---- abext constants 
---------------------------------------------------------------------------

--- abext protocol constants
local abext = {}

abext.PROTO_ICMP = 0x01
abext.PROTO_TCP  = 0x06
abext.PROTO_UDP  = 0x11
abext.PROTO_GRE  = 0x2f
abext.PROTO_ESP  = 0x32
abext.PROTO_AH   = 0x33
abext.PROTO_SCTP = 0x84

---------------------------------------------------------------------------
---- abext header
---------------------------------------------------------------------------


abext.headerFormat = [[
    uint8_t  next_hdr;        // Next Hdr (1B)
    uint8_t  hdr_ext_len;     // Hdr. Ext. Len (1B)
    uint8_t  opt_type;        // Opt. Type (1B)
    uint8_t  opt_len;         // Opt. Len (1B)
    uint8_t  idpid;           // IDPID (1B)
    uint16_t timeout;         // Timeout (2B)
    uint8_t  eruid[7];        // ERUID (7B)
    uint8_t  padding[2];      // Padding (2B)
    uint8_t  tag[8];          // Tag (8B)
]]




--- Variable sized member
abext.headerVariableMember = nil

--- Module for abext_address struct
local abextHeader = initHeader()
abextHeader.__index = abextHeader

function abextHeader:getProtocol()
    return self.next_hdr
end

function abextHeader:getString()
	return "AB Extension Header"
end

-- Maps headers to respective protocol value.
-- This list should be extended whenever a new protocol is added to 'IPv4 constants'. 
local mapNameProto = {
	icmp = abext.PROTO_ICMP,
	udp = abext.PROTO_UDP,
	tcp = abext.PROTO_TCP, 
	esp = abext.PROTO_ESP,
	ah = abext.PROTO_AH,
	gre = abext.PROTO_GRE,
}

--- Resolve which header comes after this one (in a packet).
--- For instance: in tcp/udp based on the ports.
--- This function must exist and is only used when get/dump is executed on
--- an unknown (mbuf not yet casted to e.g. tcpv6 packet) packet (mbuf)
--- @return String next header (e.g. 'udp', 'icmp', nil)
function abextHeader:resolveNextHeader()
	local proto = self:getProtocol()
	for name, _proto in pairs(mapNameProto) do
		if proto == _proto then
			return name
		end
	end
	return nil
end

------------------------------------------------------------------------
---- Metatypes
------------------------------------------------------------------------

abext.metatype = abextHeader

return abext