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
# Spec constants (from ursp/spec.py - subset needed for SIM decode)
# ============================================================================

# TD Component Types by ID
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

# RSD Component Types by ID
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

# Zero-length RSD types
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

SST_STANDARD_VALUES = {
    1: "eMBB", 2: "URLLC", 3: "MIoT", 4: "V2X",
    5: "HMTC", 6: "HDLLC", 7: "GBRSS",
}

ANDROID_OS_ID = "97A498E3FC925C9489860333D06E4E47"


# ============================================================================
# BER-TLV Length helpers
# ============================================================================

def _parse_ber_length(hb, idx):
    """Parse BER-TLV length field. Returns (length_value, new_idx)."""
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


# ============================================================================
# DECODER - hex string → JSON
# ============================================================================

def decode_ursp_hex(hex_str):
    """
    Decode URSP hex value (from BER-TLV tag 0x80, after stripping tag+length).
    
    Input: hex string = PLMN(3B) + BER-TLV_Length + URSP_Rules
    Output: dict with plmn, ursp_rules[]
    
    Each URSP rule: {precedence_value, td_components[], rsd_list[]}
    Each RSD: {precedence_value, rsd_components[]}
    """
    if not hex_str or len(hex_str) < 8:
        return {'success': False, 'error': 'Hex data too short'}

    try:
        hb = [hex_str[i:i+2].upper() for i in range(0, len(hex_str), 2)]
        idx = 0

        # --- PLMN (3 bytes) ---
        mcc1 = int(hb[0], 16) & 0x0F
        mcc2 = (int(hb[0], 16) >> 4) & 0x0F
        mcc3 = int(hb[1], 16) & 0x0F
        mnc3 = (int(hb[1], 16) >> 4) & 0x0F
        mnc1 = int(hb[2], 16) & 0x0F
        mnc2 = (int(hb[2], 16) >> 4) & 0x0F
        plmn = f"{mcc1}{mcc2}{mcc3}{mnc1}{mnc2}"
        if mnc3 != 0xF:
            plmn += f"{mnc3}"
        idx = 3

        # --- BER-TLV length of URSP rules block ---
        ursp_block_len, idx = _parse_ber_length(hb, idx)
        ursp_end = idx + ursp_block_len

        # --- Parse URSP rules ---
        ursp_rules = []
        while idx < ursp_end and idx < len(hb):
            rule, idx = _parse_ursp_rule(hb, idx)
            if rule:
                ursp_rules.append(rule)

        return {'success': True, 'plmn': plmn, 'ursp_rules': ursp_rules}

    except Exception as e:
        return {'success': False, 'error': str(e)}


def _parse_ursp_rule(hb, idx):
    """Parse one URSP rule. Returns (rule_dict, new_idx)."""
    if idx + 1 >= len(hb):
        return None, idx

    rule_len = (int(hb[idx], 16) << 8) + int(hb[idx + 1], 16)
    idx += 2
    rule_end = idx + rule_len

    # Precedence
    pv = int(hb[idx], 16)
    idx += 1

    # TD length (2 bytes)
    td_len = (int(hb[idx], 16) << 8) + int(hb[idx + 1], 16)
    idx += 2
    td_end = idx + td_len

    td_components = []
    if td_len > 0:
        while idx < td_end and idx < len(hb):
            comp, idx = _parse_td_component(hb, idx, td_end)
            if comp:
                td_components.append(comp)
    else:
        td_components.append({'type': 'Match-all', 'value': ''})

    # RSD list length (2 bytes)
    rsd_list_len = (int(hb[idx], 16) << 8) + int(hb[idx + 1], 16)
    idx += 2
    rsd_end = idx + rsd_list_len

    rsd_list = []
    while idx < rsd_end and idx < len(hb):
        rsd, idx = _parse_rsd(hb, idx)
        if rsd:
            rsd_list.append(rsd)

    return {'precedence_value': pv, 'td_components': td_components, 'rsd_list': rsd_list}, rule_end


def _parse_td_component(hb, idx, td_end):
    """Parse one TD component. Returns (component_dict, new_idx)."""
    if idx >= td_end or idx >= len(hb):
        return None, idx

    type_id = int(hb[idx], 16)
    type_name = TD_TYPES_BY_ID.get(type_id, f"Unknown(0x{type_id:02X})")
    idx += 1
    comp = {'type': type_name, 'value': ''}

    # Match-all (0x01) - zero length
    if type_name == "Match-all":
        pass

    # OS Id + OS App Id (0x08)
    elif type_name == "OS Id + OS App Id":
        os_id = ''.join(hb[idx:idx + 16])
        idx += 16
        app_len = int(hb[idx], 16)
        idx += 1
        app_id = ''.join(chr(int(hb[idx + i], 16)) for i in range(app_len) if idx + i < len(hb))
        idx += app_len
        if os_id == ANDROID_OS_ID:
            comp['value'] = f"Android:{app_id}"
        else:
            uid = f"{os_id[0:8]}-{os_id[8:12]}-{os_id[12:16]}-{os_id[16:20]}-{os_id[20:32]}"
            comp['value'] = f"{uid}:{app_id}"

    # IPv4 remote address (0x10) - 8 bytes
    elif type_name == "IPv4 remote address":
        addr = '.'.join(str(int(hb[idx + i], 16)) for i in range(4))
        idx += 4
        mask = '.'.join(str(int(hb[idx + i], 16)) for i in range(4))
        idx += 4
        comp['value'] = f"{addr}/{mask}"

    # IPv6 remote address/prefix (0x21) - 17 bytes
    elif type_name == "IPv6 remote address/prefix length":
        v6 = int(''.join(hb[idx:idx + 16]), 16)
        idx += 16
        pfx = int(hb[idx], 16)
        idx += 1
        comp['value'] = f"{ipaddress.IPv6Address(v6)}/{pfx}"

    # Protocol (0x30) - 1 byte
    elif type_name == "Protocol identifier/next header":
        p = int(hb[idx], 16)
        comp['value'] = PROTOCOL_MAP.get(p, str(p))
        idx += 1

    # Single remote port (0x50) - 2 bytes
    elif type_name == "Single remote port":
        comp['value'] = str((int(hb[idx], 16) << 8) + int(hb[idx + 1], 16))
        idx += 2

    # Remote port range (0x51) - 4 bytes
    elif type_name == "Remote port range":
        lo = (int(hb[idx], 16) << 8) + int(hb[idx + 1], 16)
        hi = (int(hb[idx + 2], 16) << 8) + int(hb[idx + 3], 16)
        comp['value'] = f"{lo}-{hi}"
        idx += 4

    # IP 3 tuple (0x52) - bitmap based
    elif type_name == "IP 3 tuple":
        bitmap = int(hb[idx], 16)
        idx += 1
        v = {'ipType': '', 'portType': '', 'address': '', 'mask': '', 'prefix': '', 'protocol': '', 'port': '', 'portLow': '', 'portHigh': ''}
        if bitmap & 0x01:
            v['ipType'] = 'IPv4'
            v['address'] = '.'.join(str(int(hb[idx + i], 16)) for i in range(4)); idx += 4
            v['mask'] = '.'.join(str(int(hb[idx + i], 16)) for i in range(4)); idx += 4
        if bitmap & 0x02:
            v['ipType'] = 'IPv6'
            v['address'] = str(ipaddress.IPv6Address(int(''.join(hb[idx:idx + 16]), 16))); idx += 16
            v['prefix'] = str(int(hb[idx], 16)); idx += 1
        if bitmap & 0x04:
            pid = int(hb[idx], 16); v['protocol'] = PROTOCOL_MAP.get(pid, str(pid)); idx += 1
        if bitmap & 0x08:
            v['portType'] = 'Single'; v['port'] = str((int(hb[idx], 16) << 8) + int(hb[idx + 1], 16)); idx += 2
        if bitmap & 0x10:
            v['portType'] = 'Range'
            v['portLow'] = str((int(hb[idx], 16) << 8) + int(hb[idx + 1], 16)); idx += 2
            v['portHigh'] = str((int(hb[idx], 16) << 8) + int(hb[idx + 1], 16)); idx += 2
        comp['value'] = v

    # Security parameter index (0x60) - 4 bytes
    elif type_name == "Security parameter index":
        spi = 0
        for i in range(4): spi = (spi << 8) + int(hb[idx + i], 16)
        comp['value'] = f"0x{spi:08X}"; idx += 4

    # ToS/TC (0x70) - 1 byte
    elif type_name == "Type of service/traffic class":
        comp['value'] = f"0x{int(hb[idx], 16):02X}"; idx += 1

    # Flow label (0x80) - 3 bytes
    elif type_name == "Flow label":
        fl = 0
        for i in range(3): fl = (fl << 8) + int(hb[idx + i], 16)
        comp['value'] = f"0x{fl:05X}"; idx += 3

    # Destination MAC (0x81) - 6 bytes
    elif type_name == "Destination MAC address":
        comp['value'] = ':'.join(hb[idx + i] for i in range(6)); idx += 6

    # C-TAG VID (0x83) - 2 bytes
    elif type_name == "802.1Q C-TAG VID":
        comp['value'] = str((int(hb[idx], 16) << 8) + int(hb[idx + 1], 16)); idx += 2

    # S-TAG VID (0x84) - 2 bytes
    elif type_name == "802.1Q S-TAG VID":
        comp['value'] = str((int(hb[idx], 16) << 8) + int(hb[idx + 1], 16)); idx += 2

    # C-TAG PCP/DEI (0x85) - 1 byte
    elif type_name == "802.1Q C-TAG PCP/DEI":
        comp['value'] = f"0x{int(hb[idx], 16):02X}"; idx += 1

    # S-TAG PCP/DEI (0x86) - 1 byte
    elif type_name == "802.1Q S-TAG PCP/DEI":
        comp['value'] = f"0x{int(hb[idx], 16):02X}"; idx += 1

    # Ethertype (0x87) - 2 bytes
    elif type_name == "Ethertype":
        comp['value'] = f"0x{(int(hb[idx], 16) << 8) + int(hb[idx + 1], 16):04X}"; idx += 2

    # DNN (0x88) - variable
    elif type_name == "DNN":
        dnn_len = int(hb[idx], 16); idx += 1
        apn_len = int(hb[idx], 16); idx += 1
        comp['value'] = ''.join(chr(int(hb[idx + i], 16)) for i in range(apn_len)); idx += apn_len

    # Connection capabilities (0x90) - variable
    elif type_name == "Connection capabilities":
        n = int(hb[idx], 16); idx += 1
        caps = []
        for _ in range(n):
            cid = int(hb[idx], 16)
            caps.append(CONNECTION_CAPABILITY_MAP.get(cid, f"0x{cid:02X}"))
            idx += 1
        comp['value'] = ', '.join(caps)

    # Destination FQDN (0x91) - variable
    elif type_name == "Destination FQDN":
        flen = int(hb[idx], 16); idx += 1
        comp['value'] = ''.join(chr(int(hb[idx + i], 16)) for i in range(flen)); idx += flen

    # Regular expression (0x92) - variable
    elif type_name == "Regular expression":
        rlen = int(hb[idx], 16); idx += 1
        comp['value'] = ''.join(chr(int(hb[idx + i], 16)) for i in range(rlen)); idx += rlen

    # OS App Id (0xA0) - variable
    elif type_name == "OS App Id":
        alen = int(hb[idx], 16); idx += 1
        comp['value'] = ''.join(chr(int(hb[idx + i], 16)) for i in range(alen)); idx += alen

    # Destination MAC range (0xA1) - 12 bytes
    elif type_name == "Destination MAC address range":
        lo = ':'.join(hb[idx + i] for i in range(6)); idx += 6
        hi = ':'.join(hb[idx + i] for i in range(6)); idx += 6
        comp['value'] = f"{lo}-{hi}"

    # PIN ID (0xA2) - variable
    elif type_name == "PIN ID":
        plen = int(hb[idx], 16); idx += 1
        comp['value'] = ''.join(chr(int(hb[idx + i], 16)) for i in range(plen)); idx += plen

    # Connectivity group ID (0xA3) - variable
    elif type_name == "Connectivity group ID":
        glen = int(hb[idx], 16); idx += 1
        comp['value'] = ''.join(chr(int(hb[idx + i], 16)) for i in range(glen)); idx += glen

    # Unknown - try length+skip
    else:
        if idx < len(hb):
            skip = int(hb[idx], 16); idx += 1 + skip

    return comp, idx


def _parse_rsd(hb, idx):
    """Parse one RSD block. Returns (rsd_dict, new_idx)."""
    if idx + 1 >= len(hb):
        return None, idx

    rsd_len = (int(hb[idx], 16) << 8) + int(hb[idx + 1], 16)
    idx += 2
    rsd_end = idx + rsd_len

    pv = int(hb[idx], 16); idx += 1

    cont_len = (int(hb[idx], 16) << 8) + int(hb[idx + 1], 16)
    idx += 2
    cont_end = idx + cont_len

    components = []
    while idx < cont_end and idx < len(hb):
        type_id = int(hb[idx], 16)
        type_name = RSD_TYPES_BY_ID.get(type_id, f"Unknown(0x{type_id:02X})")
        idx += 1
        comp = {'type': type_name, 'value': ''}

        if type_name == "SSC mode":
            v = int(hb[idx], 16); comp['value'] = SSC_MODE_MAP.get(v, str(v)); idx += 1
        elif type_name == "S-NSSAI":
            slen = int(hb[idx], 16); idx += 1
            sst = int(hb[idx], 16); idx += 1
            sst_name = SST_STANDARD_VALUES.get(sst, "")
            if slen == 4:
                sd = (int(hb[idx], 16) << 16) | (int(hb[idx + 1], 16) << 8) | int(hb[idx + 2], 16)
                idx += 3
                comp['value'] = f"SST {sst} + SD {sd}"
            else:
                comp['value'] = f"SST {sst}"
        elif type_name == "DNN":
            dlen = int(hb[idx], 16); idx += 1
            alen = int(hb[idx], 16); idx += 1
            comp['value'] = ''.join(chr(int(hb[idx + i], 16)) for i in range(alen)); idx += alen
        elif type_name == "PDU session type":
            v = int(hb[idx], 16); comp['value'] = PDU_SESSION_TYPE_MAP.get(v, str(v)); idx += 1
        elif type_name == "Preferred access type":
            v = int(hb[idx], 16); comp['value'] = PREFERRED_ACCESS_TYPE_MAP.get(v, str(v)); idx += 1
        elif type_name == "PDU session pair ID":
            v = int(hb[idx], 16); comp['value'] = PDU_SESSION_PAIR_ID_MAP.get(v, str(v)); idx += 1
        elif type_name == "RSN":
            v = int(hb[idx], 16); comp['value'] = RSN_MAP.get(v, str(v)); idx += 1
        elif type_name in RSD_ZERO:
            pass
        else:
            if idx < len(hb):
                skip = int(hb[idx], 16); idx += 1 + skip

        components.append(comp)

    return {'precedence_value': pv, 'rsd_components': components}, rsd_end
