"""
URSP Decoder for SIM Card (EF.URSP)
Decodes URSP rule hex data stored in BER-TLV tag 0x80.

SIM card stores: PLMN(3B) + BER-TLV_Length + URSP_Rules (per TS 31.102 Section 4.4.11.12)
Based on 3GPP TS 24.526 URSP rule encoding.

NOTE: This module is NOT part of the original pySim project.
      Custom implementation for sim-reader tool.
"""

import ipaddress

# ============================================================================
# Spec constants
# ============================================================================

TD_TYPES_BY_ID = {
    0x01: "Match-all",
    0x08: "OS Id + OS App Id",
    0x10: "IPv4 remote address",
    0x21: "IPv6 remote address/prefix length",
    0x30: "Protocol identifier/next header",
    0x50: "Single remote port",
    0x51: "Remote port range",
    0x52: "IP 3 tuple",
    0x60: "Security parameter index",
    0x70: "Type of service/traffic class",
    0x80: "Flow label",
    0x81: "Destination MAC address",
    0x83: "802.1Q C-TAG VID",
    0x84: "802.1Q S-TAG VID",
    0x85: "802.1Q C-TAG PCP/DEI",
    0x86: "802.1Q S-TAG PCP/DEI",
    0x87: "Ethertype",
    0x88: "DNN",
    0x90: "Connection capabilities",
    0x91: "Destination FQDN",
    0x92: "Regular expression",
    0xA0: "OS App Id",
    0xA1: "Destination MAC address range",
    0xA2: "PIN ID",
    0xA3: "Connectivity group ID",
}

RSD_TYPES_BY_ID = {
    0x01: "SSC mode",
    0x02: "S-NSSAI",
    0x04: "DNN",
    0x08: "PDU session type",
    0x10: "Preferred access type",
    0x11: "Multi-access preference",
    0x20: "Non-seamless non-3GPP offload indication",
    0x40: "Location criteria",
    0x80: "Time window",
    0x81: "5G ProSe layer-3 UE-to-network relay offload indication",
    0x82: "PDU session pair ID",
    0x83: "RSN",
    0x84: "5G ProSe multi-path preference",
}

RSD_ZERO = {"Multi-access preference", "Non-seamless non-3GPP offload indication",
            "5G ProSe layer-3 UE-to-network relay offload indication", "5G ProSe multi-path preference"}

PROTOCOL_MAP = {0x01: "ICMP", 0x06: "TCP", 0x11: "UDP", 0x32: "ESP", 0x3A: "ICMPv6"}

CONNECTION_CAPABILITY_MAP = {
    0x01: "IMS", 0x02: "MMS", 0x04: "SUPL", 0x08: "Internet",
    0x10: "LCS user plane positioning", 0x20: "Operator specific",
    0xA1: "IoT delay-tolerant", 0xA2: "IoT non-delay-tolerant",
    0xA3: "Downlink streaming", 0xA4: "Uplink streaming",
    0xA5: "Vehicular communications", 0xA6: "Real time interactive",
    0xA7: "Unified communications", 0xA8: "Background",
    0xA9: "Mission critical communications", 0xAA: "Time critical communications",
}

SSC_MODE_MAP = {0x01: "SSC mode 1", 0x02: "SSC mode 2", 0x03: "SSC mode 3"}
PDU_SESSION_TYPE_MAP = {0x01: "IPv4", 0x02: "IPv6", 0x03: "IPv4v6"}
PREFERRED_ACCESS_TYPE_MAP = {0x01: "3GPP access", 0x02: "Non-3GPP access"}
PDU_SESSION_PAIR_ID_MAP = {i: f"PDU session pair ID {i}" for i in range(7)}
RSN_MAP = {0x00: "v1", 0x01: "v2"}
SST_STANDARD_VALUES = {1: "eMBB", 2: "URLLC", 3: "MIoT", 4: "V2X", 5: "HMTC", 6: "HDLLC", 7: "GBRSS"}
ANDROID_OS_ID = "97A498E3FC925C9489860333D06E4E47"


# ============================================================================
# Helpers
# ============================================================================

def _parse_ber_length(hb, idx):
    if idx >= len(hb):
        return 0, idx
    first = int(hb[idx], 16)
    if first <= 0x7F:
        return first, idx + 1
    elif first == 0x81:
        return int(hb[idx + 1], 16), idx + 2
    elif first == 0x82:
        return (int(hb[idx + 1], 16) << 8) + int(hb[idx + 2], 16), idx + 3
    return 0, idx + 1

def _u16(hb, idx):
    return (int(hb[idx], 16) << 8) + int(hb[idx + 1], 16), idx + 2

def _u8(hb, idx):
    return int(hb[idx], 16), idx + 1

def _read_ascii(hb, idx, length):
    return ''.join(chr(int(hb[idx + i], 16)) for i in range(length) if idx + i < len(hb)), idx + length


# ============================================================================
# Main decoder
# ============================================================================

def decode_ursp_hex(hex_str):
    """Decode URSP hex (tag 0x80 value) → normalized dict for tree rendering."""
    if not hex_str or len(hex_str) < 8:
        return {'success': False, 'error': 'Hex data too short'}
    try:
        hb = [hex_str[i:i+2].upper() for i in range(0, len(hex_str), 2)]
        idx = 0

        # PLMN (3 bytes, nibble-swap BCD)
        n0, idx = _u8(hb, idx)
        n1, idx = _u8(hb, idx)
        n2, idx = _u8(hb, idx)
        mcc = f"{n0 & 0x0F}{(n0 >> 4) & 0x0F}{n1 & 0x0F}"
        mnc3 = (n1 >> 4) & 0x0F
        mnc = f"{n2 & 0x0F}{(n2 >> 4) & 0x0F}"
        if mnc3 != 0xF:
            mnc += str(mnc3)

        # BER-TLV length of URSP rules block
        ursp_block_len, idx = _parse_ber_length(hb, idx)
        ursp_end = idx + ursp_block_len

        # Parse URSP rules
        rules = []
        while idx < ursp_end and idx < len(hb):
            rule, idx = _parse_rule(hb, idx)
            if rule:
                rules.append(rule)

        return {'success': True, 'plmn': mcc + mnc, 'URSP rules': rules}
    except Exception as e:
        return {'success': False, 'error': str(e)}


# ============================================================================
# Rule parser — outputs final normalized form directly
# ============================================================================

def _parse_rule(hb, idx):
    rule_len, idx = _u16(hb, idx)
    rule_end = idx + rule_len

    pv, idx = _u8(hb, idx)

    # Traffic descriptor
    td_len, idx = _u16(hb, idx)
    td_end = idx + td_len
    td_list = []
    if td_len > 0:
        while idx < td_end and idx < len(hb):
            comp, idx = _parse_td(hb, idx, td_end)
            if comp:
                td_list.append(comp)
    else:
        td_list.append({'type': 'Match-all'})

    # Route selection descriptor list
    rsd_len, idx = _u16(hb, idx)
    rsd_end = idx + rsd_len
    rsd_list = []
    while idx < rsd_end and idx < len(hb):
        rsd, idx = _parse_rsd(hb, idx)
        if rsd:
            rsd_list.append(rsd)

    return {
        'Precedence value': pv,
        'Traffic descriptor': td_list,
        'Route selection descriptor list': rsd_list,
    }, rule_end


# ============================================================================
# TD component parser — returns normalized form directly
# ============================================================================

def _parse_td(hb, idx, td_end):
    if idx >= td_end or idx >= len(hb):
        return None, idx

    type_id, idx = _u8(hb, idx)
    type_name = TD_TYPES_BY_ID.get(type_id, f"Unknown(0x{type_id:02X})")

    if type_name == "Match-all":
        return {'type': type_name}, idx

    elif type_name == "OS Id + OS App Id":
        os_id = ''.join(hb[idx:idx + 16]); idx += 16
        app_len, idx = _u8(hb, idx)
        app_id, idx = _read_ascii(hb, idx, app_len)
        if os_id == ANDROID_OS_ID:
            return {'type': type_name, 'value': {'OS Id': 'Android', 'OS App Id': app_id}}, idx
        uid = f"{os_id[0:8]}-{os_id[8:12]}-{os_id[12:16]}-{os_id[16:20]}-{os_id[20:32]}"
        return {'type': type_name, 'value': {'OS Id': uid, 'OS App Id': app_id}}, idx

    elif type_name == "IPv4 remote address":
        addr = '.'.join(str(int(hb[idx + i], 16)) for i in range(4)); idx += 4
        mask = '.'.join(str(int(hb[idx + i], 16)) for i in range(4)); idx += 4
        return {'type': type_name, 'value': {'IPv4 address': addr, 'Subnet mask': mask}}, idx

    elif type_name == "IPv6 remote address/prefix length":
        v6 = int(''.join(hb[idx:idx + 16]), 16); idx += 16
        pfx, idx = _u8(hb, idx)
        return {'type': type_name, 'value': {'IPv6 address': str(ipaddress.IPv6Address(v6)), 'Prefix length': pfx}}, idx

    elif type_name == "Protocol identifier/next header":
        p, idx = _u8(hb, idx)
        return {'type': type_name, 'value': PROTOCOL_MAP.get(p, str(p))}, idx

    elif type_name == "Single remote port":
        port, idx = _u16(hb, idx)
        return {'type': type_name, 'value': port}, idx

    elif type_name == "Remote port range":
        lo, idx = _u16(hb, idx)
        hi, idx = _u16(hb, idx)
        return {'type': type_name, 'value': {'Low limit': lo, 'High limit': hi}}, idx

    elif type_name == "IP 3 tuple":
        bitmap, idx = _u8(hb, idx)
        r = {}
        if bitmap & 0x01:
            r['IPv4 address'] = '.'.join(str(int(hb[idx + i], 16)) for i in range(4)); idx += 4
            r['Subnet mask'] = '.'.join(str(int(hb[idx + i], 16)) for i in range(4)); idx += 4
        if bitmap & 0x02:
            r['IPv6 address'] = str(ipaddress.IPv6Address(int(''.join(hb[idx:idx + 16]), 16))); idx += 16
            pfx, idx = _u8(hb, idx); r['Prefix length'] = pfx
        if bitmap & 0x04:
            pid, idx = _u8(hb, idx)
            key = 'Protocol identifier' if (bitmap & 0x01) else ('Next header' if (bitmap & 0x02) else 'Protocol identifier/Next header')
            r[key] = PROTOCOL_MAP.get(pid, str(pid))
        if bitmap & 0x08:
            port, idx = _u16(hb, idx); r['Port'] = port
        if bitmap & 0x10:
            lo, idx = _u16(hb, idx); hi, idx = _u16(hb, idx)
            r['Port low limit'] = lo; r['Port high limit'] = hi
        return {'type': type_name, 'value': r}, idx

    elif type_name == "Security parameter index":
        spi = 0
        for i in range(4): spi = (spi << 8) + int(hb[idx + i], 16)
        idx += 4
        return {'type': type_name, 'value': f"0x{spi:08X}"}, idx

    elif type_name == "Type of service/traffic class":
        v, idx = _u8(hb, idx)
        return {'type': type_name, 'value': f"0x{v:02X}"}, idx

    elif type_name == "Flow label":
        fl = 0
        for i in range(3): fl = (fl << 8) + int(hb[idx + i], 16)
        idx += 3
        return {'type': type_name, 'value': f"0x{fl:05X}"}, idx

    elif type_name == "Destination MAC address":
        mac = ':'.join(hb[idx + i] for i in range(6)); idx += 6
        return {'type': type_name, 'value': mac}, idx

    elif type_name in ("802.1Q C-TAG VID", "802.1Q S-TAG VID"):
        v, idx = _u16(hb, idx)
        return {'type': type_name, 'value': v}, idx

    elif type_name in ("802.1Q C-TAG PCP/DEI", "802.1Q S-TAG PCP/DEI"):
        v, idx = _u8(hb, idx)
        return {'type': type_name, 'value': f"0x{v:02X}"}, idx

    elif type_name == "Ethertype":
        v, idx = _u16(hb, idx)
        return {'type': type_name, 'value': f"0x{v:04X}"}, idx

    elif type_name == "DNN":
        dnn_len, idx = _u8(hb, idx)
        apn_len, idx = _u8(hb, idx)
        name, idx = _read_ascii(hb, idx, apn_len)
        return {'type': type_name, 'value': name}, idx

    elif type_name == "Connection capabilities":
        n, idx = _u8(hb, idx)
        caps = []
        for _ in range(n):
            cid, idx = _u8(hb, idx)
            caps.append(CONNECTION_CAPABILITY_MAP.get(cid, f"0x{cid:02X}"))
        return {'type': type_name, 'value': caps}, idx

    elif type_name == "Destination FQDN":
        flen, idx = _u8(hb, idx)
        name, idx = _read_ascii(hb, idx, flen)
        return {'type': type_name, 'value': name}, idx

    elif type_name == "Regular expression":
        rlen, idx = _u8(hb, idx)
        expr, idx = _read_ascii(hb, idx, rlen)
        return {'type': type_name, 'value': expr}, idx

    elif type_name == "OS App Id":
        alen, idx = _u8(hb, idx)
        name, idx = _read_ascii(hb, idx, alen)
        return {'type': type_name, 'value': name}, idx

    elif type_name == "Destination MAC address range":
        lo = ':'.join(hb[idx + i] for i in range(6)); idx += 6
        hi = ':'.join(hb[idx + i] for i in range(6)); idx += 6
        return {'type': type_name, 'value': {'Low limit': lo, 'High limit': hi}}, idx

    elif type_name == "PIN ID":
        plen, idx = _u8(hb, idx)
        name, idx = _read_ascii(hb, idx, plen)
        return {'type': type_name, 'value': name}, idx

    elif type_name == "Connectivity group ID":
        glen, idx = _u8(hb, idx)
        name, idx = _read_ascii(hb, idx, glen)
        return {'type': type_name, 'value': name}, idx

    else:
        if idx < len(hb):
            skip, idx = _u8(hb, idx); idx += skip
        return {'type': type_name, 'value': ''}, idx


# ============================================================================
# RSD parser — returns normalized form directly
# ============================================================================

def _parse_rsd(hb, idx):
    rsd_len, idx = _u16(hb, idx)
    rsd_end = idx + rsd_len

    pv, idx = _u8(hb, idx)
    cont_len, idx = _u16(hb, idx)
    cont_end = idx + cont_len

    components = []
    while idx < cont_end and idx < len(hb):
        type_id, idx = _u8(hb, idx)
        type_name = RSD_TYPES_BY_ID.get(type_id, f"Unknown(0x{type_id:02X})")

        if type_name in RSD_ZERO:
            components.append({'type': type_name})

        elif type_name == "SSC mode":
            v, idx = _u8(hb, idx)
            components.append({'type': type_name, 'value': SSC_MODE_MAP.get(v, str(v))})

        elif type_name == "S-NSSAI":
            slen, idx = _u8(hb, idx)
            sst, idx = _u8(hb, idx)
            if slen == 4:
                sd = (int(hb[idx], 16) << 16) | (int(hb[idx + 1], 16) << 8) | int(hb[idx + 2], 16); idx += 3
                components.append({'type': type_name, 'value': {'SST': sst, 'SD': sd}})
            else:
                components.append({'type': type_name, 'value': {'SST': sst}})

        elif type_name == "DNN":
            dlen, idx = _u8(hb, idx)
            alen, idx = _u8(hb, idx)
            name, idx = _read_ascii(hb, idx, alen)
            components.append({'type': type_name, 'value': name})

        elif type_name == "PDU session type":
            v, idx = _u8(hb, idx)
            components.append({'type': type_name, 'value': PDU_SESSION_TYPE_MAP.get(v, str(v))})

        elif type_name == "Preferred access type":
            v, idx = _u8(hb, idx)
            components.append({'type': type_name, 'value': PREFERRED_ACCESS_TYPE_MAP.get(v, str(v))})

        elif type_name == "PDU session pair ID":
            v, idx = _u8(hb, idx)
            components.append({'type': type_name, 'value': PDU_SESSION_PAIR_ID_MAP.get(v, str(v))})

        elif type_name == "RSN":
            v, idx = _u8(hb, idx)
            components.append({'type': type_name, 'value': RSN_MAP.get(v, str(v))})

        else:
            if idx < len(hb):
                skip, idx = _u8(hb, idx); idx += skip
            components.append({'type': type_name, 'value': ''})

    return {
        'Precedence value': pv,
        'Route selection descriptor contents': components,
    }, rsd_end
