-- Xena Micro Test Payload Dissector v1.0 for Wireshark.
--
-- Apache License
-- Version 2.0, January 2004
-- http://www.apache.org/licenses/

-- TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

-- 1. Definitions.

-- "License" shall mean the terms and conditions for use, reproduction,
-- and distribution as defined by Sections 1 through 9 of this document.

-- "Licensor" shall mean the copyright owner or entity authorized by
-- the copyright owner that is granting the License.

-- "Legal Entity" shall mean the union of the acting entity and all
-- other entities that control, are controlled by, or are under common
-- control with that entity. For the purposes of this definition,
-- "control" means (i) the power, direct or indirect, to cause the
-- direction or management of such entity, whether by contract or
-- otherwise, or (ii) ownership of fifty percent (50%) or more of the
-- outstanding shares, or (iii) beneficial ownership of such entity.

-- "You" (or "Your") shall mean an individual or Legal Entity
-- exercising permissions granted by this License.

-- "Source" form shall mean the preferred form for making modifications,
-- including but not limited to software source code, documentation
-- source, and configuration files.

-- "Object" form shall mean any form resulting from mechanical
-- transformation or translation of a Source form, including but
-- not limited to compiled object code, generated documentation,
-- and conversions to other media types.

-- "Work" shall mean the work of authorship, whether in Source or
-- Object form, made available under the License, as indicated by a
-- copyright notice that is included in or attached to the work
-- (an example is provided in the Appendix below).

-- "Derivative Works" shall mean any work, whether in Source or Object
-- form, that is based on (or derived from) the Work and for which the
-- editorial revisions, annotations, elaborations, or other modifications
-- represent, as a whole, an original work of authorship. For the purposes
-- of this License, Derivative Works shall not include works that remain
-- separable from, or merely link (or bind by name) to the interfaces of,
-- the Work and Derivative Works thereof.

-- "Contribution" shall mean any work of authorship, including
-- the original version of the Work and any modifications or additions
-- to that Work or Derivative Works thereof, that is intentionally
-- submitted to Licensor for inclusion in the Work by the copyright owner
-- or by an individual or Legal Entity authorized to submit on behalf of
-- the copyright owner. For the purposes of this definition, "submitted"
-- means any form of electronic, verbal, or written communication sent
-- to the Licensor or its representatives, including but not limited to
-- communication on electronic mailing lists, source code control systems,
-- and issue tracking systems that are managed by, or on behalf of, the
-- Licensor for the purpose of discussing and improving the Work, but
-- excluding communication that is conspicuously marked or otherwise
-- designated in writing by the copyright owner as "Not a Contribution."

-- "Contributor" shall mean Licensor and any individual or Legal Entity
-- on behalf of whom a Contribution has been received by Licensor and
-- subsequently incorporated within the Work.

-- 2. Grant of Copyright License. Subject to the terms and conditions of
-- this License, each Contributor hereby grants to You a perpetual,
-- worldwide, non-exclusive, no-charge, royalty-free, irrevocable
-- copyright license to reproduce, prepare Derivative Works of,
-- publicly display, publicly perform, sublicense, and distribute the
-- Work and such Derivative Works in Source or Object form.

-- 3. Grant of Patent License. Subject to the terms and conditions of
-- this License, each Contributor hereby grants to You a perpetual,
-- worldwide, non-exclusive, no-charge, royalty-free, irrevocable
-- (except as stated in this section) patent license to make, have made,
-- use, offer to sell, sell, import, and otherwise transfer the Work,
-- where such license applies only to those patent claims licensable
-- by such Contributor that are necessarily infringed by their
-- Contribution(s) alone or by combination of their Contribution(s)
-- with the Work to which such Contribution(s) was submitted. If You
-- institute patent litigation against any entity (including a
-- cross-claim or counterclaim in a lawsuit) alleging that the Work
-- or a Contribution incorporated within the Work constitutes direct
-- or contributory patent infringement, then any patent licenses
-- granted to You under this License for that Work shall terminate
-- as of the date such litigation is filed.

-- 4. Redistribution. You may reproduce and distribute copies of the
-- Work or Derivative Works thereof in any medium, with or without
-- modifications, and in Source or Object form, provided that You
-- meet the following conditions:

-- (a) You must give any other recipients of the Work or
-- Derivative Works a copy of this License; and

-- (b) You must cause any modified files to carry prominent notices
-- stating that You changed the files; and

-- (c) You must retain, in the Source form of any Derivative Works
-- that You distribute, all copyright, patent, trademark, and
-- attribution notices from the Source form of the Work,
-- excluding those notices that do not pertain to any part of
-- the Derivative Works; and

-- (d) If the Work includes a "NOTICE" text file as part of its
-- distribution, then any Derivative Works that You distribute must
-- include a readable copy of the attribution notices contained
-- within such NOTICE file, excluding those notices that do not
-- pertain to any part of the Derivative Works, in at least one
-- of the following places: within a NOTICE text file distributed
-- as part of the Derivative Works; within the Source form or
-- documentation, if provided along with the Derivative Works; or,
-- within a display generated by the Derivative Works, if and
-- wherever such third-party notices normally appear. The contents
-- of the NOTICE file are for informational purposes only and
-- do not modify the License. You may add Your own attribution
-- notices within Derivative Works that You distribute, alongside
-- or as an addendum to the NOTICE text from the Work, provided
-- that such additional attribution notices cannot be construed
-- as modifying the License.

-- You may add Your own copyright statement to Your modifications and
-- may provide additional or different license terms and conditions
-- for use, reproduction, or distribution of Your modifications, or
-- for any such Derivative Works as a whole, provided Your use,
-- reproduction, and distribution of the Work otherwise complies with
-- the conditions stated in this License.

-- 5. Submission of Contributions. Unless You explicitly state otherwise,
-- any Contribution intentionally submitted for inclusion in the Work
-- by You to the Licensor shall be under the terms and conditions of
-- this License, without any additional terms or conditions.
-- Notwithstanding the above, nothing herein shall supersede or modify
-- the terms of any separate license agreement you may have executed
-- with Licensor regarding such Contributions.

-- 6. Trademarks. This License does not grant permission to use the trade
-- names, trademarks, service marks, or product names of the Licensor,
-- except as required for reasonable and customary use in describing the
-- origin of the Work and reproducing the content of the NOTICE file.

-- 7. Disclaimer of Warranty. Unless required by applicable law or
-- agreed to in writing, Licensor provides the Work (and each
-- Contributor provides its Contributions) on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
-- implied, including, without limitation, any warranties or conditions
-- of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
-- PARTICULAR PURPOSE. You are solely responsible for determining the
-- appropriateness of using or redistributing the Work and assume any
-- risks associated with Your exercise of permissions under this License.

-- 8. Limitation of Liability. In no event and under no legal theory,
-- whether in tort (including negligence), contract, or otherwise,
-- unless required by applicable law (such as deliberate and grossly
-- negligent acts) or agreed to in writing, shall any Contributor be
-- liable to You for damages, including any direct, indirect, special,
-- incidental, or consequential damages of any character arising as a
-- result of this License or out of the use or inability to use the
-- Work (including but not limited to damages for loss of goodwill,
-- work stoppage, computer failure or malfunction, or any and all
-- other commercial damages or losses), even if such Contributor
-- has been advised of the possibility of such damages.

-- 9. Accepting Warranty or Additional Liability. While redistributing
-- the Work or Derivative Works thereof, You may choose to offer,
-- and charge a fee for, acceptance of support, warranty, indemnity,
-- or other liability obligations and/or rights consistent with this
-- License. However, in accepting such obligations, You may act only
-- on Your own behalf and on Your sole responsibility, not on behalf
-- of any other Contributor, and only if You agree to indemnify,
-- defend, and hold each Contributor harmless for any liability
-- incurred by, or claims asserted against, such Contributor by reason
-- of your accepting any such warranty or additional liability.

-- END OF TERMS AND CONDITIONS

-- APPENDIX: How to apply the Apache License to your work.

-- To apply the Apache License to your work, attach the following
-- boilerplate notice, with the fields enclosed by brackets "[]"
-- replaced with your own identifying information. (Don't include
-- the brackets!)  The text should be enclosed in the appropriate
-- comment syntax for the file format. We also recommend that a
-- file or class name and description of purpose be included on the
-- same "printed page" as the copyright notice for easier
-- identification within third-party archives.

-- Copyright 2024 Teledyne LeCroy Xena

-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at

-- http://www.apache.org/licenses/LICENSE-2.0

-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- Dissector version
local xutpld_version = "1.0"

--
-- Wireshark version check - require version 2.0 or higher
--
local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
if major and tonumber(major) < 2 then
    error(  "\n\nXena TPLD Dissector: Wireshark version ("..get_version()..") is too old!\n"..
            "This dissector needs Wireshark version 2.0 or higher.\n" )
end

local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

local DEBUG = debug_level.LEVEL_1

local dprint = function() end

--local dprint = function(...)
--    print(table.concat({"Lua:", ...}," "))
--end

dprint("Wireshark version = ", get_version())
dprint("Lua version = ", _VERSION)

-- Function to parse Lua version string
local function parse_lua_version(version)
    local major, minor = version:match("Lua (%d+)%.(%d+)")
    return tonumber(major), tonumber(minor)
end

local lua_major, lua_minor = parse_lua_version(_VERSION)

-- Custom bitwise operations for unsigned integers. 
-- Needed because the bit32 library is not available in Lua 5.4,
-- and the bit library is using signed integers which messes up the crc calculation.
local xbit32 = {}

function xbit32.band(a, b)
    local result = 0
    local bitval = 1
    while a > 0 and b > 0 do
        local abit = a % 2
        local bbit = b % 2
        if abit == 1 and bbit == 1 then
            result = result + bitval
        end
        bitval = bitval * 2
        a = math.floor(a / 2)
        b = math.floor(b / 2)
    end
    return result
end

function xbit32.bor(a, b)
    local result = 0
    local bitval = 1
    while a > 0 or b > 0 do
        local abit = a % 2
        local bbit = b % 2
        if abit == 1 or bbit == 1 then
            result = result + bitval
        end
        bitval = bitval * 2
        a = math.floor(a / 2)
        b = math.floor(b / 2)
    end
    return result
end

function xbit32.bxor(a, b)
    local result = 0
    local bitval = 1
    while a > 0 or b > 0 do
        local abit = a % 2
        local bbit = b % 2
        if abit ~= bbit then
            result = result + bitval
        end
        bitval = bitval * 2
        a = math.floor(a / 2)
        b = math.floor(b / 2)
    end
    return result
end

function xbit32.lshift(a, b)
    return (a * (2 ^ b)) % 2^32
end

function xbit32.rshift(a, b)
    return math.floor(a / (2 ^ b)) % 2^32
end

function xbit32.bnot(a)
    return 2^32 - 1 - a
end

local bit32 = xbit32

-- Various protocol definitions
local MIN_TPLD_LEN      = 6
local ETHER_FCS_LEN     = 4

-- Define the Xena TPLD protocol
xutpld_proto = Proto("xutpld", "Xena Micro Test Payload")

-- Define TPLD fields
local pf_timestamp      = ProtoField.new ("Timestamp", "xutpld.timestamp", ftypes.UINT32)
local pf_timestampns    = ProtoField.new ("Timestamp (nsec)", "xutpld.timestampns", ftypes.STRING)
local pf_tid            = ProtoField.new ("TID", "xutpld.tid", ftypes.UINT16)
local pf_flags          = ProtoField.new ("Flags", "xutpld.flags", ftypes.UINT8, nil, base.HEX)
local pf_flags_fpf      = ProtoField.new ("First Packet", "xutpld.flags.fpf", ftypes.BOOLEAN)
local pf_checksum       = ProtoField.new ("Checksum", "xutpld.flags.chksum", ftypes.UINT8, nil, base.HEX)

-- Register fields
xutpld_proto.fields = { 
    pf_timestamp, pf_timestampns,
    pf_tid, pf_flags, pf_flags_fpf,
    pf_checksum
}

-- Expert fields
local ef_chkvalid       = ProtoExpert.new("xutpld.chkvalid.expert", "Is Valid",
                                expert.group.CHECKSUM, expert.severity.COMMENT)
local ef_chkinvalid     = ProtoExpert.new("xutpld.chkinvalid.expert", "Not Valid",
                                expert.group.CHECKSUM, expert.severity.ERROR)

-- Register expert fields
xutpld_proto.experts = { ef_chkvalid, ef_chkinvalid }
               

-- Preferences

local default_settings =
{
    setprotinheader = false,
    decodebadcrc = false,
}

xutpld_proto.prefs.setprotinheader = Pref.bool("Show Protocol in Header", 
    default_settings.setprotinheader,
    "Show the XMP protocol ID in the column header")

xutpld_proto.prefs.decodebadcrc  = Pref.bool("Decode Packets with Bad CRC", 
    default_settings.decodebadcrc,
    "Decode packets with invalid checksums")

               
-- Register this dissector as a post-dissector so it receives all packets 
-- when all other dissectors have run.
register_postdissector(xutpld_proto)

-- CRC definitions
local CRCTABLE_SIZE         = 256
local WIDTH                 = 32
local TOPBIT                = bit32.lshift(1, WIDTH - 1)
local POLYNOMIAL            = 0x04C11DB7
local INITIAL_REMAINDER	    = 0xFFFFFFFF
local FINAL_XOR_VALUE		= 0x00000000

-- CRC remainder table for fast calculation
local crcTable              = {}
local crc_init_performed    = false;

-- Initialize CRC calculator
function crc_init()
    if crc_init_performed == true then
        -- only do this once
        return
    end

    local remainder = 0;
	local dividend = 0;
	local bit = 0;
    
    -- Compute the remainder of each possible dividend.
    for dividend = 0, 255, 1 do
    
        -- Start with the dividend followed by zeros.
        remainder = bit32.lshift(dividend, WIDTH - 8)

         -- Perform modulo-2 division, a bit at a time.
        for bit = 8, 1, -1 do
            -- Try to divide the current data bit.
            if bit32.band(remainder, TOPBIT) > 0 then
                remainder = bit32.bxor(bit32.lshift(remainder, 1), POLYNOMIAL)
            else
                remainder = bit32.lshift(remainder, 1)
            end
        end

        -- Store the result into the table.
        crcTable[dividend] = remainder
    end
    
    crc_init_performed = true
end 

-- 
-- Compute the CRC of a given message.
--
function crc_fast(bytearray, bytecount)
    local remainder = INITIAL_REMAINDER;
    local data;
	local byteval;

    -- Divide the message by the polynomial, a byte at a time.
    for byteval = 0, bytecount - 1, 1 do
        data = bit32.bxor(bytearray:get_index(byteval), bit32.rshift(remainder, WIDTH - 8))
  		remainder = bit32.bxor(crcTable[data], bit32.lshift(remainder, 8))
    end

    -- The final remainder is the CRC.
    return bit32.bxor(remainder, FINAL_XOR_VALUE)
end

-- Format a number with thousand separators
-- credit http://richard.warburton.it
function comma_value(n) 
	local left,num,right = string.match(tostring(n) ,'^([^%d]*%d)(%d*)(.-)$')
	return left..(num:reverse():gsub('(%d%d%d)','%1,'):reverse())..right
end

-- Dissector initialization routine - called by Wireshark
function xutpld_proto.init()
    crc_init()
end

-- Dissector preferences has changed - called by Wireshark
function xutpld_proto.prefs_changed()
    default_settings.setprotinheader = xutpld_proto.prefs.setprotinheader
    default_settings.decodebadcrc  = xutpld_proto.prefs.decodebadcrc
end

-- Dissector main routine - called by Wireshark
function xutpld_proto.dissector(tvbuf, pktinfo, root)
    -- get the reported remaining length of the buffer
    local pktlen = tvbuf:reported_length_remaining()
    
    if pktlen < (MIN_TPLD_LEN + ETHER_FCS_LEN) then
        -- buffer is too small to contain a Xena TPLD - bail out!
        dprint("packet length", pktlen, "too short")
        return
    end

    local payloadlength = pktlen - (MIN_TPLD_LEN + ETHER_FCS_LEN)
    local tpldbuf = tvbuf:range(payloadlength, MIN_TPLD_LEN)
    
    -- process the TPLD flags first
    local flags = tpldbuf(0,1)
    local flagsvalue = flags:uint()
    
    local firstpacket = bit32.band(bit32.rshift(flagsvalue, 7), 0x01)
    
    -- Calculate expected CRC checksum using Fast CRC algorithm
    local crc_calculated = crc_fast(tpldbuf(1,4):bytes(), 4)
    
    local chksumbuf = tpldbuf:range(5, 1)

    -- check if the calculated checksums match with the values in the packet
    local checksum_valid = true
    -- Take the 8 least significant bits of the calculated CRC
    local crc_8bit = bit32.band(crc_calculated, 0xFF)
    if chksumbuf:uint() ~= crc_8bit then
        checksum_valid = false
        
        if default_settings.decodebadcrc == false then
            return
        end
    end
    
    if default_settings.setprotinheader and checksum_valid then
        pktinfo.cols.protocol:set(xutpld_proto.name)
    end
    
    -- add the results to the tree
    local tree = root:add(xutpld_proto, tpldbuf)

    -- TID only uses 10 bits
    local tid = bit32.band(bit32.rshift(tpldbuf(0, 2):uint(), 4), 0x03FF)
    
    tree:add(pf_tid, tid)
    
    local flags_treeitem = tree:add(pf_flags, flags)
    flags_treeitem:add(pf_flags_fpf, firstpacket)

    local tsbuf = tpldbuf(1, 4)

    local tsvalue = bit32.band(tsbuf:uint(), 0x0FFFFFFF)
    local tsvaluens = 8 * tsvalue
    
    local tssubtree = tree:add(pf_timestampns, comma_value(tsvaluens))
    tssubtree:add(pf_timestamp, tsbuf)
    
    tree:add(pf_checksum, chksumbuf)

    if checksum_valid == true then
        tree:add_proto_expert_info(ef_chkvalid, "Checksum Valid")
    else
        tree:add_proto_expert_info(ef_chkinvalid, "Checksum Invalid")
    end
    
end    
   
