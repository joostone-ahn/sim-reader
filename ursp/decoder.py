"""
URSP Rule Analyzer - Decoder Module
Parses hex data from DL NAS Transport messages into ursp_rules structure and breakdown data
"""

import re
import sys
import os
import ipaddress

# Add src directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from spec import get_td_type_name_by_id, get_rsd_type_name_by_id, get_connection_capability_name, SST_STANDARD_VALUES, rsd_zero

def decode_ursp(log_text):
    """
    Decode hex data from DL NAS Transport message log into ursp_rules structure
    
    Args:
        log_text: Hex log text containing DL NAS Transport message
    
    Returns:
        dict: Decoded ursp_rules and success status
    """
    try:
        print(f"[DECODER] decode_ursp called with log_text length: {len(log_text)}")
        print(f"[DECODER] First 100 chars: {log_text[:100]}")
        
        # Extract hex data from log
        hex_data = extract_hex_from_log(log_text)
        if not hex_data:
            print(f"[DECODER] No valid hex data found")
            return {
                'success': False,
                'error': 'No valid hex data found in log'
            }
        
        print(f"[DECODER] Extracted hex data length: {len(hex_data)} chars")
        print(f"[DECODER] First 50 chars of hex: {hex_data[:50]}")
        
        # Parse hex data into ursp_rules structure and breakdown
        ursp_rules, pti, plmn, upsc, breakdown_data = parse_dl_nas_transport(hex_data)
        
        print(f"[DECODER] Parsing completed. Found {len(ursp_rules)} URSP rules")
        print(f"[DECODER] Breakdown data entries: {len(breakdown_data)}")
        
        return {
            'success': True,
            'message_type': 'DL NAS Transport',
            'dl_nas': hex_data.upper(),
            'hex_data': hex_data.upper(),
            'ursp_rules': ursp_rules,
            'pti': pti,
            'plmn': plmn,
            'upsc': upsc,
            'breakdown_data': breakdown_data  # Structured breakdown for display
        }
        
    except Exception as e:
        print(f"[DECODER] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            'success': False,
            'error': str(e)
        }

def extract_hex_from_log(log_text):
    """Extract hex data from log text - supports v1 format and finds DL NAS Transport message"""
    lines = log_text.strip().split('\n')
    hex_data = ''
    
    # First pass: extract all hex data
    for line in lines:
        # Handle v1 format: "0000   68 05 00 1F 97 01 00 1B 00 19 54 F0 60 00 14 00"
        # Remove line numbers/addresses at the beginning
        line = re.sub(r'^\s*[0-9a-fA-F]{4}\s*', '', line)
        
        # Remove ASCII parts (anything after | or multiple spaces)
        line = re.sub(r'\s*\|.*', '', line)
        line = re.sub(r'\s{4,}.*', '', line)  # Remove ASCII part after 4+ spaces
        
        # Extract hex bytes (2 hex digits optionally separated by spaces)
        hex_bytes = re.findall(r'[0-9a-fA-F]{2}', line)
        hex_data += ''.join(hex_bytes)
    
    # Second pass: find DL NAS Transport message (68 05 pattern)
    if hex_data:
        hex_data = hex_data.upper()
        dl_nas_start = hex_data.find('6805')
        if dl_nas_start != -1:
            # Extract from DL NAS Transport message start
            hex_data = hex_data[dl_nas_start:]
            print(f"[DECODER] Found DL NAS Transport at position {dl_nas_start//2}")
        else:
            print(f"[DECODER] Warning: DL NAS Transport pattern (68 05) not found")
    
    print(f"[DECODER] Extracted hex data length: {len(hex_data)} chars")
    print(f"[DECODER] First 20 chars: {hex_data[:20] if hex_data else 'None'}")
    return hex_data if hex_data else None

def parse_dl_nas_transport(hex_data):
    """
    Parse DL NAS Transport message into ursp_rules structure and breakdown data
    
    Args:
        hex_data: Hex string from DL NAS Transport message
    
    Returns:
        tuple: (ursp_rules, pti, plmn, upsc, breakdown_data)
    """
    hex_bytes = [hex_data[i:i+2] for i in range(0, len(hex_data), 2)]
    idx = 0
    breakdown_data = []  # Store breakdown entries
    
    print(f"[DECODER] Starting parse_dl_nas_transport with {len(hex_bytes)} bytes")
    print(f"[DECODER] First 20 bytes: {' '.join(hex_bytes[:20])}")
    
    # ===== NAS MESSAGE HEADER =====
    if idx < len(hex_bytes) and hex_bytes[idx] == '68':
        print(f"[DECODER] idx={idx}: {hex_bytes[idx]} = DL NAS Transport")
        breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], "DL NAS Transport"])
        idx += 1
    
    if idx < len(hex_bytes) and hex_bytes[idx] == '05':
        print(f"[DECODER] idx={idx}: {hex_bytes[idx]} = Payload container type")
        breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], "Payload container type: UE policy container"])
        idx += 1
    
    # Bytes 2-3: Payload container length
    if idx + 1 < len(hex_bytes):
        payload_len = (int(hex_bytes[idx], 16) << 8) + int(hex_bytes[idx + 1], 16)
        print(f"[DECODER] idx={idx}-{idx+1}: {hex_bytes[idx]} {hex_bytes[idx+1]} = Payload length {payload_len}")
        breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], "Length of payload container contents[0]"])
        breakdown_data.append([str(idx + 1), str(int(hex_bytes[idx + 1], 16)), hex_bytes[idx + 1], "Length of payload container contents[1]"])
        idx += 2
    
    # ===== UE POLICY DELIVERY SERVICE MESSAGE =====
    pti = hex_bytes[idx] if idx < len(hex_bytes) else '97'
    if idx < len(hex_bytes):
        breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], "Procedure transaction identity(PTI)"])
        idx += 1
    
    if idx < len(hex_bytes):
        breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], "UE policy delivery service message type: MANAGE UE POLICY COMMAND"])
        idx += 1
    
    # ===== UE POLICY SECTION MANAGEMENT =====
    if idx + 1 < len(hex_bytes):
        breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], "Length of UE policy section management list contents[0]"])
        breakdown_data.append([str(idx + 1), str(int(hex_bytes[idx + 1], 16)), hex_bytes[idx + 1], "Length of UE policy section management list contents[1]"])
        idx += 2
    
    if idx + 1 < len(hex_bytes):
        breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], "Length of UE policy section management sublist[0]"])
        breakdown_data.append([str(idx + 1), str(int(hex_bytes[idx + 1], 16)), hex_bytes[idx + 1], "Length of UE policy section management sublist[1]"])
        idx += 2
    
    # ===== PLMN IDENTIFICATION =====
    plmn = ''
    if idx + 2 < len(hex_bytes):
        plmn_bytes = hex_bytes[idx:idx+3]
        breakdown_data.append([str(idx), str(int(plmn_bytes[0], 16)), plmn_bytes[0], "MCC digit 2, MCC digit 1"])
        breakdown_data.append([str(idx + 1), str(int(plmn_bytes[1], 16)), plmn_bytes[1], "MNC digit 3, MCC digit 3"])
        breakdown_data.append([str(idx + 2), str(int(plmn_bytes[2], 16)), plmn_bytes[2], "MNC digit 2, MNC digit 1"])
        
        # PLMN decoding: 3 bytes = [MCC2|MCC1][MNC3|MCC3][MNC2|MNC1]
        # Extract digits from each byte
        mcc1 = (int(plmn_bytes[0], 16) & 0x0F)  # Lower nibble of byte 0
        mcc2 = (int(plmn_bytes[0], 16) & 0xF0) >> 4  # Upper nibble of byte 0
        mcc3 = (int(plmn_bytes[1], 16) & 0x0F)  # Lower nibble of byte 1
        mnc3 = (int(plmn_bytes[1], 16) & 0xF0) >> 4  # Upper nibble of byte 1
        mnc1 = (int(plmn_bytes[2], 16) & 0x0F)  # Lower nibble of byte 2
        mnc2 = (int(plmn_bytes[2], 16) & 0xF0) >> 4  # Upper nibble of byte 2
        
        # Build PLMN string
        plmn = f"{mcc1}{mcc2}{mcc3}{mnc1}{mnc2}"
        if mnc3 != 0xF:  # If MNC3 is not padding
            plmn += f"{mnc3}"
        
        idx += 3
    
    # ===== INSTRUCTION CONTENTS =====
    if idx + 1 < len(hex_bytes):
        breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], "Instruction contents length[0]"])
        breakdown_data.append([str(idx + 1), str(int(hex_bytes[idx + 1], 16)), hex_bytes[idx + 1], "Instruction contents length[1]"])
        idx += 2
    
    # UPSC (2 bytes)
    upsc = ''
    if idx + 1 < len(hex_bytes):
        upsc = hex_bytes[idx] + hex_bytes[idx + 1]
        breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], "UPSC[0]"])
        breakdown_data.append([str(idx + 1), str(int(hex_bytes[idx + 1], 16)), hex_bytes[idx + 1], "UPSC[1]"])
        idx += 2
    
    # ===== UE POLICY PART =====
    pol_len = 0
    if idx + 1 < len(hex_bytes):
        pol_len = (int(hex_bytes[idx], 16) << 8) + int(hex_bytes[idx + 1], 16)
        breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], "UE policy part contents length[0]"])
        breakdown_data.append([str(idx + 1), str(int(hex_bytes[idx + 1], 16)), hex_bytes[idx + 1], "UE policy part contents length[1]"])
        idx += 2
    
    # UE policy part type (0x01 = URSP)
    if idx < len(hex_bytes):
        breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], "UE policy part type: URSP"])
        idx += 1
        breakdown_data.append(["===", "===", "===", "==="])
    
    # ===== URSP RULES PARSING =====
    ursp_rules = []
    ursp_data_end = idx + pol_len - 1
    
    print(f"[DECODER] Starting URSP rules parsing at idx={idx}, ursp_data_end={ursp_data_end}")
    
    while idx < ursp_data_end and idx < len(hex_bytes):
        print(f"[DECODER] === URSP RULE {len(ursp_rules)} ===")
        
        # URSP rule length (2 bytes)
        if idx + 1 < len(hex_bytes):
            ursp_rule_len = (int(hex_bytes[idx], 16) << 8) + int(hex_bytes[idx + 1], 16)
            rule_count = len(ursp_rules)
            print(f"[DECODER] idx={idx}-{idx+1}: {hex_bytes[idx]} {hex_bytes[idx+1]} = URSP rule length {ursp_rule_len}")
            breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], f"Length of URSP rule[0]: URSP_{rule_count}"])
            breakdown_data.append([str(idx + 1), str(int(hex_bytes[idx + 1], 16)), hex_bytes[idx + 1], f"Length of URSP rule[1]: URSP_{rule_count}"])
            idx += 2
        else:
            break
        
        rule_end = idx + ursp_rule_len
        print(f"[DECODER] URSP rule ends at idx={rule_end}")
        
        # URSP rule precedence
        ursp_pv = int(hex_bytes[idx], 16) if idx < len(hex_bytes) else 1
        print(f"[DECODER] idx={idx}: {hex_bytes[idx]} = URSP precedence {ursp_pv}")
        breakdown_data.append([str(idx), str(ursp_pv), hex_bytes[idx], "Precedence value of URSP rule"])
        idx += 1
        
        breakdown_data.append(["---", "---", "---", "---"])
        
        # ===== TRAFFIC DESCRIPTOR SECTION =====
        if idx + 1 < len(hex_bytes):
            td_len = (int(hex_bytes[idx], 16) << 8) + int(hex_bytes[idx + 1], 16)
            print(f"[DECODER] idx={idx}-{idx+1}: {hex_bytes[idx]} {hex_bytes[idx+1]} = TD length {td_len}")
            breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], "Length of traffic descriptor[0]"])
            breakdown_data.append([str(idx + 1), str(int(hex_bytes[idx + 1], 16)), hex_bytes[idx + 1], "Length of traffic descriptor[1]"])
            idx += 2
        else:
            break
        
        td_components = []
        if td_len > 0:
            td_end = idx + td_len
            print(f"[DECODER] TD parsing: td_len={td_len}, idx={idx}, td_end={td_end}")
            while idx < td_end and idx < len(hex_bytes):
                td_type_id = int(hex_bytes[idx], 16)
                td_type_name = get_td_type_name_by_id(td_type_id)
                print(f"[DECODER] TD type at idx {idx}: {hex_bytes[idx]} = {td_type_id} ({td_type_name})")
                breakdown_data.append([str(idx), str(td_type_id), hex_bytes[idx], f"Traffic descriptor type: {td_type_name}"])
                idx += 1
                
                component = {'type': td_type_name, 'value': ''}
                
                # ===== TD Component Value Decoding (3GPP TS 24.526 순서) =====
                
                # 0x01: Match-all - zero-length
                if td_type_name == "Match-all":
                    print(f"[DECODER] Match-all detected")
                    pass
                
                # 0x08: OS Id + OS App Id
                elif td_type_name == "OS Id + OS App Id":
                    # 16 bytes OS ID + length + app ID string
                    os_id_bytes = []
                    for i in range(16):
                        if idx < len(hex_bytes):
                            os_id_bytes.append(hex_bytes[idx])
                            breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], f"OS Id[{i}]"])
                            idx += 1
                    
                    if idx < len(hex_bytes):
                        app_id_len = int(hex_bytes[idx], 16)
                        breakdown_data.append([str(idx), str(app_id_len), hex_bytes[idx], "OS App Id length"])
                        idx += 1
                        
                        app_id = ''
                        for i in range(app_id_len):
                            if idx < len(hex_bytes):
                                val = int(hex_bytes[idx], 16)
                                char = chr(val) if 32 <= val <= 126 else '.'
                                breakdown_data.append([str(idx), str(val), hex_bytes[idx], f"OS App Id[{i}]: '{char}'"])
                                app_id += chr(val)
                                idx += 1
                        
                        # Determine OS type
                        from spec import ANDROID_OS_ID, ANDROID_APP_IDS
                        os_id_hex = ''.join(os_id_bytes)
                        
                        if os_id_hex == ANDROID_OS_ID:
                            # Android - App Id를 키로 매칭
                            os_name = "Android"
                            app_id_key = None
                            for key, info in ANDROID_APP_IDS.items():
                                if info['string'] == app_id:
                                    app_id_key = key
                                    break
                            component['value'] = f"{os_name}:{app_id_key if app_id_key else app_id}"
                        else:
                            # Custom (non-Android)
                            # OS Id를 UUID 형식으로 변환
                            uuid_str = f"{os_id_hex[0:8]}-{os_id_hex[8:12]}-{os_id_hex[12:16]}-{os_id_hex[16:20]}-{os_id_hex[20:32]}"
                            component['value'] = f"{uuid_str}:{app_id}"
                
                # 0x10: IPv4 remote address - 8 bytes (NO length)
                elif td_type_name == "IPv4 remote address":
                    if idx + 7 < len(hex_bytes):
                        # 4 bytes address
                        addr = []
                        for i in range(4):
                            addr.append(str(int(hex_bytes[idx], 16)))
                            breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], f"IPv4 address[{i}]"])
                            idx += 1
                        # 4 bytes mask
                        mask = []
                        for i in range(4):
                            mask.append(str(int(hex_bytes[idx], 16)))
                            breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], f"IPv4 subnet mask[{i}]"])
                            idx += 1
                        component['value'] = f"{'.'.join(addr)}/{'.'.join(mask)}"
                
                # 0x21: IPv6 remote address/prefix length - 17 bytes (NO length)
                elif td_type_name == "IPv6 remote address/prefix length":
                    if idx + 16 < len(hex_bytes):
                        # 16 bytes address
                        ipv6_bytes = []
                        for i in range(16):
                            ipv6_bytes.append(hex_bytes[idx])
                            breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], f"IPv6 address[{i}]"])
                            idx += 1
                        # 1 byte prefix length
                        prefix_len = int(hex_bytes[idx], 16)
                        breakdown_data.append([str(idx), str(prefix_len), hex_bytes[idx], "IPv6 prefix length"])
                        idx += 1
                        
                        # Format IPv6 address
                        ipv6_int = int(''.join(ipv6_bytes), 16)
                        ipv6_addr = ipaddress.IPv6Address(ipv6_int)
                        component['value'] = f"{ipv6_addr}/{prefix_len}"
                
                # 0x30: Protocol identifier/next header - 1 byte (NO length)
                elif td_type_name == "Protocol identifier/next header":
                    if idx < len(hex_bytes):
                        from spec import PROTOCOL_MAP
                        protocol = int(hex_bytes[idx], 16)
                        protocol_name = PROTOCOL_MAP.get(protocol, f"Unknown({protocol})")
                        breakdown_data.append([str(idx), str(protocol), hex_bytes[idx], f"IPv4 protocol identifier or IPv6 next header: {protocol_name}"])
                        component['value'] = protocol_name
                        idx += 1
                
                # 0x50: Single remote port - 2 bytes (NO length)
                elif td_type_name == "Single remote port":
                    if idx + 1 < len(hex_bytes):
                        port = (int(hex_bytes[idx], 16) << 8) + int(hex_bytes[idx + 1], 16)
                        breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], "Port number[0]"])
                        breakdown_data.append([str(idx + 1), str(int(hex_bytes[idx + 1], 16)), hex_bytes[idx + 1], "Port number[1]"])
                        component['value'] = str(port)
                        idx += 2
                
                # 0x51: Remote port range - 4 bytes (NO length)
                elif td_type_name == "Remote port range":
                    if idx + 3 < len(hex_bytes):
                        port_low = (int(hex_bytes[idx], 16) << 8) + int(hex_bytes[idx + 1], 16)
                        breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], "Port range low limit[0]"])
                        breakdown_data.append([str(idx + 1), str(int(hex_bytes[idx + 1], 16)), hex_bytes[idx + 1], "Port range low limit[1]"])
                        idx += 2
                        
                        port_high = (int(hex_bytes[idx], 16) << 8) + int(hex_bytes[idx + 1], 16)
                        breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], "Port range high limit[0]"])
                        breakdown_data.append([str(idx + 1), str(int(hex_bytes[idx + 1], 16)), hex_bytes[idx + 1], "Port range high limit[1]"])
                        idx += 2
                        
                        component['value'] = f"{port_low}-{port_high}"
                
                # 0x52: IP 3 tuple - variable length based on bitmap
                elif td_type_name == "IP 3 tuple":
                    if idx < len(hex_bytes):
                        bitmap = int(hex_bytes[idx], 16)
                        
                        # Bitmap 필드 목록 생성 (사용하지 않음 - binary만 표시)
                        # Binary representation (8 bits)
                        bitmap_binary = format(bitmap, '08b')
                        bitmap_desc = f"IP 3 tuple - Information bitmap : 0b{bitmap_binary}"
                        
                        breakdown_data.append([str(idx), str(bitmap), hex_bytes[idx], bitmap_desc])
                        idx += 1
                        
                        # 결과를 객체 형식으로 저장
                        ip3_value = {
                            'ipType': '',  # bitmap을 보고 결정
                            'portType': '',  # bitmap을 보고 결정
                            'address': '',
                            'mask': '',
                            'prefix': '',
                            'protocol': '',
                            'port': '',
                            'portLow': '',
                            'portHigh': ''
                        }
                        
                        # Bitmap을 보고 ipType 결정
                        if bitmap & 0x01:  # bit 1: IPv4
                            ip3_value['ipType'] = 'IPv4'
                        elif bitmap & 0x02:  # bit 2: IPv6
                            ip3_value['ipType'] = 'IPv6'
                        
                        # Bitmap을 보고 portType 결정
                        if bitmap & 0x08:  # bit 4: Single port
                            ip3_value['portType'] = 'Single'
                        elif bitmap & 0x10:  # bit 5: Port range
                            ip3_value['portType'] = 'Range'
                        
                        # IPv4 address and subnet mask (bit 1)
                        if bitmap & 0x01 and idx + 7 < len(hex_bytes):
                            addr = []
                            for i in range(4):
                                addr.append(str(int(hex_bytes[idx], 16)))
                                breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], f"IP 3 tuple - IPv4 address[{i}]"])
                                idx += 1
                            mask = []
                            for i in range(4):
                                mask.append(str(int(hex_bytes[idx], 16)))
                                breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], f"IP 3 tuple - IPv4 subnet mask[{i}]"])
                                idx += 1
                            ip3_value['address'] = '.'.join(addr)
                            ip3_value['mask'] = '.'.join(mask)
                        
                        # IPv6 address and prefix (bit 2)
                        if bitmap & 0x02 and idx + 16 < len(hex_bytes):
                            # IPv6 address (16 bytes)
                            ipv6_bytes = []
                            for i in range(16):
                                ipv6_bytes.append(int(hex_bytes[idx], 16))
                                breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], f"IP 3 tuple - IPv6 address[{i}]"])
                                idx += 1
                            ipv6_addr = ipaddress.IPv6Address(bytes(ipv6_bytes))
                            ip3_value['address'] = str(ipv6_addr)
                            
                            # Prefix length (1 byte)
                            if idx < len(hex_bytes):
                                prefix_len = int(hex_bytes[idx], 16)
                                breakdown_data.append([str(idx), str(prefix_len), hex_bytes[idx], "IP 3 tuple - IPv6 prefix length"])
                                ip3_value['prefix'] = str(prefix_len)
                                idx += 1
                        
                        # Protocol identifier (bit 3)
                        if bitmap & 0x04 and idx < len(hex_bytes):
                            from spec import PROTOCOL_MAP
                            protocol_id = int(hex_bytes[idx], 16)
                            protocol_name = PROTOCOL_MAP.get(protocol_id, str(protocol_id))
                            breakdown_data.append([str(idx), str(protocol_id), hex_bytes[idx], f"IP 3 tuple - Protocol identifier/next header : {protocol_name}"])
                            # 프로토콜 이름으로 변환
                            ip3_value['protocol'] = protocol_name
                            idx += 1
                        
                        # Single remote port (bit 4)
                        if bitmap & 0x08 and idx + 1 < len(hex_bytes):
                            port = (int(hex_bytes[idx], 16) << 8) + int(hex_bytes[idx + 1], 16)
                            breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], "IP 3 tuple - Single remote port[0]"])
                            breakdown_data.append([str(idx + 1), str(int(hex_bytes[idx + 1], 16)), hex_bytes[idx + 1], "IP 3 tuple - Single remote port[1]"])
                            ip3_value['port'] = str(port)
                            idx += 2
                        
                        # Remote port range (bit 5)
                        if bitmap & 0x10 and idx + 3 < len(hex_bytes):
                            port_low = (int(hex_bytes[idx], 16) << 8) + int(hex_bytes[idx + 1], 16)
                            breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], "IP 3 tuple - Port range low limit[0]"])
                            breakdown_data.append([str(idx + 1), str(int(hex_bytes[idx + 1], 16)), hex_bytes[idx + 1], "IP 3 tuple - Port range low limit[1]"])
                            idx += 2
                            
                            port_high = (int(hex_bytes[idx], 16) << 8) + int(hex_bytes[idx + 1], 16)
                            breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], "IP 3 tuple - Port range high limit[0]"])
                            breakdown_data.append([str(idx + 1), str(int(hex_bytes[idx + 1], 16)), hex_bytes[idx + 1], "IP 3 tuple - Port range high limit[1]"])
                            idx += 2
                            
                            ip3_value['portLow'] = str(port_low)
                            ip3_value['portHigh'] = str(port_high)
                        
                        # 객체 형식으로 저장
                        component['value'] = ip3_value
                
                # 0x60: Security parameter index - 4 bytes (NO length)
                elif td_type_name == "Security parameter index":
                    if idx + 3 < len(hex_bytes):
                        spi = 0
                        for i in range(4):
                            spi = (spi << 8) + int(hex_bytes[idx], 16)
                            breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], f"SPI byte[{i}]"])
                            idx += 1
                        component['value'] = f"0x{spi:08X}"
                
                # 0x70: Type of service/traffic class - 1 byte (NO length)
                elif td_type_name == "Type of service/traffic class":
                    if idx < len(hex_bytes):
                        tos = int(hex_bytes[idx], 16)
                        breakdown_data.append([str(idx), str(tos), hex_bytes[idx], f"ToS/TC value: 0x{tos:02X}"])
                        component['value'] = f"0x{tos:02X}"
                        idx += 1
                
                # 0x80: Flow label - 3 bytes (NO length)
                elif td_type_name == "Flow label":
                    if idx + 2 < len(hex_bytes):
                        flow = 0
                        for i in range(3):
                            flow = (flow << 8) + int(hex_bytes[idx], 16)
                            breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], f"Flow label byte[{i}]"])
                            idx += 1
                        component['value'] = f"0x{flow:05X}"
                
                # 0x81: Destination MAC address - 6 bytes (NO length)
                elif td_type_name == "Destination MAC address":
                    if idx + 5 < len(hex_bytes):
                        mac = []
                        for i in range(6):
                            mac.append(hex_bytes[idx].upper())
                            breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], f"MAC address[{i}]"])
                            idx += 1
                        component['value'] = ':'.join(mac)
                
                # 0x83: 802.1Q C-TAG VID - 2 bytes (NO length)
                elif td_type_name == "802.1Q C-TAG VID":
                    if idx + 1 < len(hex_bytes):
                        vid = (int(hex_bytes[idx], 16) << 8) + int(hex_bytes[idx + 1], 16)
                        breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], "C-TAG VID (high byte)"])
                        breakdown_data.append([str(idx + 1), str(int(hex_bytes[idx + 1], 16)), hex_bytes[idx + 1], "C-TAG VID (low byte)"])
                        component['value'] = str(vid)
                        idx += 2
                
                # 0x84: 802.1Q S-TAG VID - 2 bytes (NO length)
                elif td_type_name == "802.1Q S-TAG VID":
                    if idx + 1 < len(hex_bytes):
                        vid = (int(hex_bytes[idx], 16) << 8) + int(hex_bytes[idx + 1], 16)
                        breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], "S-TAG VID (high byte)"])
                        breakdown_data.append([str(idx + 1), str(int(hex_bytes[idx + 1], 16)), hex_bytes[idx + 1], "S-TAG VID (low byte)"])
                        component['value'] = str(vid)
                        idx += 2
                
                # 0x85: 802.1Q C-TAG PCP/DEI - 1 byte (NO length)
                elif td_type_name == "802.1Q C-TAG PCP/DEI":
                    if idx < len(hex_bytes):
                        pcp_dei = int(hex_bytes[idx], 16)
                        breakdown_data.append([str(idx), str(pcp_dei), hex_bytes[idx], f"C-TAG PCP/DEI: 0x{pcp_dei:02X}"])
                        component['value'] = f"0x{pcp_dei:02X}"
                        idx += 1
                
                # 0x86: 802.1Q S-TAG PCP/DEI - 1 byte (NO length)
                elif td_type_name == "802.1Q S-TAG PCP/DEI":
                    if idx < len(hex_bytes):
                        pcp_dei = int(hex_bytes[idx], 16)
                        breakdown_data.append([str(idx), str(pcp_dei), hex_bytes[idx], f"S-TAG PCP/DEI: 0x{pcp_dei:02X}"])
                        component['value'] = f"0x{pcp_dei:02X}"
                        idx += 1
                
                # 0x87: Ethertype - 2 bytes (NO length)
                elif td_type_name == "Ethertype":
                    if idx + 1 < len(hex_bytes):
                        ethertype = (int(hex_bytes[idx], 16) << 8) + int(hex_bytes[idx + 1], 16)
                        breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], "Ethertype (high byte)"])
                        breakdown_data.append([str(idx + 1), str(int(hex_bytes[idx + 1], 16)), hex_bytes[idx + 1], "Ethertype (low byte)"])
                        component['value'] = f"0x{ethertype:04X}"
                        idx += 2
                
                # 0x88: DNN - variable length
                elif td_type_name == "DNN":
                    if idx < len(hex_bytes):
                        dnn_len = int(hex_bytes[idx], 16)
                        breakdown_data.append([str(idx), str(dnn_len), hex_bytes[idx], "DNN length"])
                        idx += 1
                        if idx < len(hex_bytes):
                            apn_len = int(hex_bytes[idx], 16)
                            breakdown_data.append([str(idx), str(apn_len), hex_bytes[idx], "APN length"])
                            idx += 1
                            dnn_value = ''
                            for i in range(apn_len):
                                if idx < len(hex_bytes):
                                    val = int(hex_bytes[idx], 16)
                                    char = chr(val) if 32 <= val <= 126 else '.'
                                    breakdown_data.append([str(idx), str(val), hex_bytes[idx], f"APN value: '{char}'"])
                                    dnn_value += chr(val)
                                    idx += 1
                            component['value'] = dnn_value
                
                # 0x90: Connection capabilities - variable length
                elif td_type_name == "Connection capabilities":
                    if idx < len(hex_bytes):
                        num_capabilities = int(hex_bytes[idx], 16)
                        breakdown_data.append([str(idx), str(num_capabilities), hex_bytes[idx], "Number of connection capabilities"])
                        idx += 1
                        capabilities = []
                        for i in range(num_capabilities):
                            if idx < len(hex_bytes):
                                capability_id = int(hex_bytes[idx], 16)
                                capability_name = get_connection_capability_name(capability_id)
                                breakdown_data.append([str(idx), str(capability_id), hex_bytes[idx], f"Connection capability: {capability_name}"])
                                capabilities.append(capability_name)
                                idx += 1
                        component['value'] = ', '.join(capabilities)
                
                # 0x91: Destination FQDN - variable length
                elif td_type_name == "Destination FQDN":
                    if idx < len(hex_bytes):
                        fqdn_len = int(hex_bytes[idx], 16)
                        breakdown_data.append([str(idx), str(fqdn_len), hex_bytes[idx], "FQDN length"])
                        idx += 1
                        fqdn = ''
                        for i in range(fqdn_len):
                            if idx < len(hex_bytes):
                                val = int(hex_bytes[idx], 16)
                                char = chr(val) if 32 <= val <= 126 else '.'
                                breakdown_data.append([str(idx), str(val), hex_bytes[idx], f"FQDN: '{char}'"])
                                fqdn += chr(val)
                                idx += 1
                        component['value'] = fqdn
                
                # 0x92: Regular expression - variable length
                elif td_type_name == "Regular expression":
                    if idx < len(hex_bytes):
                        regex_len = int(hex_bytes[idx], 16)
                        breakdown_data.append([str(idx), str(regex_len), hex_bytes[idx], "Regex length"])
                        idx += 1
                        regex = ''
                        for i in range(regex_len):
                            if idx < len(hex_bytes):
                                val = int(hex_bytes[idx], 16)
                                char = chr(val) if 32 <= val <= 126 else '.'
                                breakdown_data.append([str(idx), str(val), hex_bytes[idx], f"Regex: '{char}'"])
                                regex += chr(val)
                                idx += 1
                        component['value'] = regex
                
                # 0xA0: OS App Id - variable length
                elif td_type_name == "OS App Id":
                    if idx < len(hex_bytes):
                        app_id_len = int(hex_bytes[idx], 16)
                        breakdown_data.append([str(idx), str(app_id_len), hex_bytes[idx], "OS App Id length"])
                        idx += 1
                        app_id = ''
                        for i in range(app_id_len):
                            if idx < len(hex_bytes):
                                val = int(hex_bytes[idx], 16)
                                char = chr(val) if 32 <= val <= 126 else '.'
                                breakdown_data.append([str(idx), str(val), hex_bytes[idx], f"OS App Id[{i}]: '{char}'"])
                                app_id += chr(val)
                                idx += 1
                        component['value'] = app_id
                
                # 0xA1: Destination MAC address range - 12 bytes (NO length)
                elif td_type_name == "Destination MAC address range":
                    if idx + 11 < len(hex_bytes):
                        mac_start = []
                        for i in range(6):
                            mac_start.append(hex_bytes[idx].upper())
                            breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], f"MAC address range low limit[{i}]"])
                            idx += 1
                        mac_end = []
                        for i in range(6):
                            mac_end.append(hex_bytes[idx].upper())
                            breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], f"MAC address range high limit[{i}]"])
                            idx += 1
                        component['value'] = f"{':'.join(mac_start)}-{':'.join(mac_end)}"
                
                # 0xA2: PIN ID - variable length
                elif td_type_name == "PIN ID":
                    if idx < len(hex_bytes):
                        pin_len = int(hex_bytes[idx], 16)
                        breakdown_data.append([str(idx), str(pin_len), hex_bytes[idx], "PIN ID length"])
                        idx += 1
                        pin = ''
                        for i in range(pin_len):
                            if idx < len(hex_bytes):
                                val = int(hex_bytes[idx], 16)
                                char = chr(val) if 32 <= val <= 126 else '.'
                                breakdown_data.append([str(idx), str(val), hex_bytes[idx], f"PIN ID: '{char}'"])
                                pin += chr(val)
                                idx += 1
                        component['value'] = pin
                
                # 0xA3: Connectivity group ID - variable length
                elif td_type_name == "Connectivity group ID":
                    if idx < len(hex_bytes):
                        group_len = int(hex_bytes[idx], 16)
                        breakdown_data.append([str(idx), str(group_len), hex_bytes[idx], "Connectivity group ID length"])
                        idx += 1
                        group = ''
                        for i in range(group_len):
                            if idx < len(hex_bytes):
                                val = int(hex_bytes[idx], 16)
                                char = chr(val) if 32 <= val <= 126 else '.'
                                breakdown_data.append([str(idx), str(val), hex_bytes[idx], f"Group ID: '{char}'"])
                                group += chr(val)
                                idx += 1
                        component['value'] = group
                
                # Unknown TD types - fallback
                else:
                    # Try to read a length byte and skip
                    if idx < len(hex_bytes):
                        comp_len = int(hex_bytes[idx], 16)
                        breakdown_data.append([str(idx), str(comp_len), hex_bytes[idx], f"{td_type_name} length (unknown type)"])
                        idx += 1
                        idx += comp_len
                
                td_components.append(component)
        else:
            td_components.append({'type': 'Match-all', 'value': ''})
        
        # ===== ROUTE SELECTION DESCRIPTOR SECTION =====
        breakdown_data.append(["---", "---", "---", "---"])
        
        if idx + 1 < len(hex_bytes):
            rsd_len = (int(hex_bytes[idx], 16) << 8) + int(hex_bytes[idx + 1], 16)
            breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], "Length of route selection descriptor list[0]"])
            breakdown_data.append([str(idx + 1), str(int(hex_bytes[idx + 1], 16)), hex_bytes[idx + 1], "Length of route selection descriptor list[1]"])
            idx += 2
        else:
            break
        
        rsd_list = []
        rsd_end = idx + rsd_len
        rsd_count = 0
        while idx < rsd_end and idx < len(hex_bytes):
            rsd, new_idx = parse_rsd(hex_bytes, idx, breakdown_data, len(ursp_rules), rsd_count)
            if rsd:
                rsd_list.append(rsd)
            idx = new_idx
            rsd_count += 1
        
        ursp_rule = {
            'precedence_value': ursp_pv,
            'td_components': td_components,
            'rsd_list': rsd_list
        }
        ursp_rules.append(ursp_rule)
        
        idx = rule_end
        
        if idx < ursp_data_end and idx < len(hex_bytes):
            breakdown_data.append(["===", "===", "===", "==="])
    
    return ursp_rules, pti, plmn, upsc, breakdown_data

def parse_rsd(hex_bytes, idx, breakdown_data, rule_count, rsd_count):
    """Parse a single RSD and return (rsd_dict, new_idx)"""
    if idx + 1 >= len(hex_bytes):
        return None, idx
    
    rsd_len = (int(hex_bytes[idx], 16) << 8) + int(hex_bytes[idx + 1], 16)
    breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], f"Length of route selection descriptor[0]: RSD_{rule_count}_{rsd_count}"])
    breakdown_data.append([str(idx + 1), str(int(hex_bytes[idx + 1], 16)), hex_bytes[idx + 1], f"Length of route selection descriptor[1]: RSD_{rule_count}_{rsd_count}"])
    idx += 2
    
    rsd_end = idx + rsd_len
    
    rsd_pv = int(hex_bytes[idx], 16) if idx < len(hex_bytes) else 1
    breakdown_data.append([str(idx), str(rsd_pv), hex_bytes[idx], "Precedence value of route selection descriptor"])
    idx += 1
    
    if idx + 1 < len(hex_bytes):
        rsd_cont_len = (int(hex_bytes[idx], 16) << 8) + int(hex_bytes[idx + 1], 16)
        breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], "Length of route selection descriptor contents[0]"])
        breakdown_data.append([str(idx + 1), str(int(hex_bytes[idx + 1], 16)), hex_bytes[idx + 1], "Length of route selection descriptor contents[1]"])
        idx += 2
    else:
        return None, idx
    
    rsd_components = []
    rsd_cont_end = idx + rsd_cont_len
    
    while idx < rsd_cont_end and idx < len(hex_bytes):
        rsd_type_id = int(hex_bytes[idx], 16)
        rsd_type_name = get_rsd_type_name_by_id(rsd_type_id)
        breakdown_data.append([str(idx), str(rsd_type_id), hex_bytes[idx], f"Route selection descriptor component type identifier: {rsd_type_name}"])
        idx += 1
        
        component = {'type': rsd_type_name, 'value': ''}
        
        if rsd_type_name == "SSC mode":
            if idx < len(hex_bytes):
                val = int(hex_bytes[idx], 16)
                # Convert to user-friendly format using SSC_MODE_MAP
                from spec import SSC_MODE_MAP
                if val in SSC_MODE_MAP:
                    component['value'] = SSC_MODE_MAP[val]
                    breakdown_data.append([str(idx), str(val), hex_bytes[idx], f"SSC mode value: {SSC_MODE_MAP[val]}"])
                else:
                    # Fallback to decimal format if not found in map
                    component['value'] = str(val)
                    breakdown_data.append([str(idx), str(val), hex_bytes[idx], "SSC mode value"])
                idx += 1
        elif rsd_type_name == "S-NSSAI":
            if idx < len(hex_bytes):
                snssai_len = int(hex_bytes[idx], 16)
                breakdown_data.append([str(idx), str(snssai_len), hex_bytes[idx], "S-NSSAI length"])
                idx += 1
                
                # SST (공통)
                if idx < len(hex_bytes):
                    sst = int(hex_bytes[idx], 16)
                    sst_desc = SST_STANDARD_VALUES.get(sst, "Unknown")
                    breakdown_data.append([str(idx), str(sst), hex_bytes[idx], f"SST value: {sst}({sst_desc})"])
                    idx += 1
                    
                    # SD (선택적)
                    if snssai_len == 4 and idx + 2 < len(hex_bytes):
                        sd = (int(hex_bytes[idx], 16) << 16) | (int(hex_bytes[idx+1], 16) << 8) | int(hex_bytes[idx+2], 16)
                        breakdown_data.append([str(idx), str(int(hex_bytes[idx], 16)), hex_bytes[idx], "SD value[0]"])
                        breakdown_data.append([str(idx+1), str(int(hex_bytes[idx+1], 16)), hex_bytes[idx+1], "SD value[1]"])
                        breakdown_data.append([str(idx+2), str(int(hex_bytes[idx+2], 16)), hex_bytes[idx+2], "SD value[2]"])
                        idx += 3
                        component['value'] = f"SST {sst} + SD {sd}"
                    else:
                        component['value'] = f"SST {sst}"
        elif rsd_type_name == "DNN":
            if idx < len(hex_bytes):
                dnn_len = int(hex_bytes[idx], 16)
                breakdown_data.append([str(idx), str(dnn_len), hex_bytes[idx], "DNN length"])
                idx += 1
                if idx < len(hex_bytes):
                    apn_len = int(hex_bytes[idx], 16)
                    breakdown_data.append([str(idx), str(apn_len), hex_bytes[idx], "APN length"])
                    idx += 1
                    dnn_value = ''
                    for i in range(apn_len):
                        if idx < len(hex_bytes):
                            val = int(hex_bytes[idx], 16)
                            char = chr(val) if 32 <= val <= 126 else '.'
                            breakdown_data.append([str(idx), str(val), hex_bytes[idx], f"APN value[{i}]: '{char}'"])
                            dnn_value += chr(val)
                            idx += 1
                    component['value'] = dnn_value
        elif rsd_type_name == "PDU session type":
            if idx < len(hex_bytes):
                val = int(hex_bytes[idx], 16)
                # Convert to user-friendly format using PDU_SESSION_TYPE_MAP
                from spec import PDU_SESSION_TYPE_MAP
                if val in PDU_SESSION_TYPE_MAP:
                    component['value'] = PDU_SESSION_TYPE_MAP[val]
                    breakdown_data.append([str(idx), str(val), hex_bytes[idx], f"PDU session type value: {PDU_SESSION_TYPE_MAP[val]}"])
                else:
                    # Fallback to decimal format if not found in map
                    component['value'] = str(val)
                    breakdown_data.append([str(idx), str(val), hex_bytes[idx], "PDU session type value"])
                idx += 1
        elif rsd_type_name == "Preferred access type":
            if idx < len(hex_bytes):
                val = int(hex_bytes[idx], 16)
                # Convert to user-friendly format using PREFERRED_ACCESS_TYPE_MAP
                from spec import PREFERRED_ACCESS_TYPE_MAP
                if val in PREFERRED_ACCESS_TYPE_MAP:
                    component['value'] = PREFERRED_ACCESS_TYPE_MAP[val]
                    breakdown_data.append([str(idx), str(val), hex_bytes[idx], f"Preferred access type value: {PREFERRED_ACCESS_TYPE_MAP[val]}"])
                else:
                    # Fallback to decimal format if not found in map
                    component['value'] = str(val)
                    breakdown_data.append([str(idx), str(val), hex_bytes[idx], "Preferred access type value"])
                idx += 1
        elif rsd_type_name == "PDU session pair ID":
            if idx < len(hex_bytes):
                val = int(hex_bytes[idx], 16)
                # Convert to user-friendly format using PDU_SESSION_PAIR_ID_MAP
                from spec import PDU_SESSION_PAIR_ID_MAP
                if val in PDU_SESSION_PAIR_ID_MAP:
                    component['value'] = PDU_SESSION_PAIR_ID_MAP[val]
                    breakdown_data.append([str(idx), str(val), hex_bytes[idx], f"PDU session pair ID value: {PDU_SESSION_PAIR_ID_MAP[val]}"])
                else:
                    # Fallback to decimal format if not found in map
                    component['value'] = str(val)
                    breakdown_data.append([str(idx), str(val), hex_bytes[idx], "PDU session pair ID value"])
                idx += 1
        elif rsd_type_name == "RSN":
            if idx < len(hex_bytes):
                val = int(hex_bytes[idx], 16)
                # Convert to user-friendly format using RSN_MAP
                from spec import RSN_MAP
                if val in RSN_MAP:
                    component['value'] = RSN_MAP[val]
                    breakdown_data.append([str(idx), str(val), hex_bytes[idx], f"RSN value: {RSN_MAP[val]}"])
                else:
                    # Fallback to decimal format if not found in map
                    component['value'] = str(val)
                    breakdown_data.append([str(idx), str(val), hex_bytes[idx], "RSN value"])
                idx += 1
        elif rsd_type_name in rsd_zero:
            pass
        else:
            if idx < len(hex_bytes):
                comp_len = int(hex_bytes[idx], 16)
                breakdown_data.append([str(idx), str(comp_len), hex_bytes[idx], f"{rsd_type_name} length"])
                idx += 1
                idx += comp_len
        
        rsd_components.append(component)
    
    rsd = {'precedence_value': rsd_pv, 'rsd_components': rsd_components}
    return rsd, rsd_end
