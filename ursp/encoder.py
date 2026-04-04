import pandas as pd
import sys
import os
import ipaddress

# Add current directory to path if running directly
if __name__ == '__main__' and __package__ is None:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import spec

debug_mode = 0


def ber_tlv_length(byte_count):
    """
    Encode length per ISO/IEC 8825-1 (BER-TLV length coding).
    Each element in the input list represents 1 byte (2 hex chars).
    
    Returns list of hex strings representing the encoded length.
    """
    if byte_count <= 127:
        return [format(byte_count, '02X')]
    elif byte_count <= 255:
        return ['81', format(byte_count, '02X')]
    else:
        return ['82', format(byte_count >> 8, '02X'), format(byte_count & 0xFF, '02X')]


def encode_ursp(pti, plmn, upsc, ursp_rules):
    """
    Encode URSP rules to hex format
    
    Args:
        pti: Procedure Transaction Identity
        plmn: Public Land Mobile Network ID
        upsc: UE Policy Section Contents
        ursp_rules: List of URSP rules (JSON structure)
    
    Returns:
        dict: Encoding result with success status and hex data
    """
    try:
        print(f"[ENCODER] Starting encoding with {len(ursp_rules)} URSP rules")
        
        # Generate hex data (existing logic)
        df_dl_nas, ef_ursp, dl_nas = ursp_encoder(ursp_rules, pti, plmn, upsc)
        
        return {
            'success': True,
            'ef_ursp': ef_ursp,
            'dl_nas': dl_nas
        }
        
    except Exception as e:
        print(f"[ENCODER] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            'success': False,
            'error': str(e)
        }

def ursp_encoder(ursp_rules, PTI, PLMN, UPSC):
    """
    Encode URSP rules directly from JSON structure
    
    Args:
        ursp_rules: List of URSP rules in JSON format
        PTI: Procedure Transaction Identity
        PLMN: Public Land Mobile Network ID
        UPSC: UE Policy Section Contents
    
    Returns:
        tuple: (df_dl_nas, ef_ursp, dl_nas)
    """
    payload_pvtd_list = []
    payload_rsd_list = []

    # Convert PLMN to 3GPP format
    if len(PLMN) == 5:
        PLMN += 'F'  # Add F for 2-digit MNC
    
    # PLMN 45006F -> 3GPP format: 54F060
    # MCC=450, MNC=06 -> [MCC2][MCC1][MNC3][MCC3][MNC2][MNC1]
    mcc = PLMN[:3]  # "450"
    mnc = PLMN[3:]  # "06F"
    
    PLMN = mcc[1] + mcc[0] + mnc[2] + mcc[2] + mnc[1] + mnc[0]  # "54F060"

    for ursp_cnt, rule in enumerate(ursp_rules):
        ursp_pv = rule.get('precedence_value', 1)
        td_components = rule.get('td_components', [])

        payload_pvtd = []
        
        # Process TD components
        if not td_components:
            # Match-all rule (type_id = 0x01)
            payload_pvtd.append('01')
        else:
            print(f"[ENCODER] Processing {len(td_components)} TD components for URSP rule {ursp_cnt}")
            
            # Process each TD component
            for td_idx, td_comp in enumerate(td_components):
                comp_type = td_comp.get('type', 'DNN')
                comp_value = td_comp.get('value', 'internet')
                
                print(f"[ENCODER] TD component {td_idx}: {comp_type} = {comp_value}")
                
                # Add TD component type using TD_TYPES_BY_NAME
                if comp_type in spec.TD_TYPES_BY_NAME:
                    td_type_hex = format(spec.TD_TYPES_BY_NAME[comp_type], '02X')
                    payload_pvtd.append(td_type_hex)
                else:
                    print(f"*Unknown td_type: {comp_type}")
                    continue

                # Add TD component value (if not zero-length type)
                if comp_type not in spec.td_zero:
                    # ===== TD Component Value Encoding (3GPP TS 24.526 순서) =====
                    
                    # 0x01: Match-all - zero-length (handled above)
                    
                    # 0x08: OS Id + OS App Id
                    if comp_type == "OS Id + OS App Id":
                        # 값 형식: "Android:ENTERPRISE" 또는 "UUID:AppIdString"
                        parts = comp_value.split(':')
                        
                        if len(parts) < 2:
                            print(f"[ENCODER] Error: Invalid OS Id + App Id format: {comp_value}")
                            continue
                        
                        # Android로 시작하면 Android, 그 외는 Custom
                        if parts[0] == 'Android':
                            # Android OS Id (고정값)
                            from spec import ANDROID_OS_ID, ANDROID_APP_IDS
                            os_id_hex = ANDROID_OS_ID
                            
                            # OS Id를 16 bytes로 추가
                            for i in range(0, len(os_id_hex), 2):
                                payload_pvtd.append(os_id_hex[i:i + 2])
                            
                            # App Id 키로 hex 값 가져오기
                            app_id_key = parts[1]
                            if app_id_key in ANDROID_APP_IDS:
                                app_id_info = ANDROID_APP_IDS[app_id_key]
                                app_id_len = app_id_info['length']
                                app_id_hex = app_id_info['hex']
                                
                                # Length 추가
                                payload_pvtd.append(format(app_id_len, '02X'))
                                
                                # App Id hex 추가
                                for i in range(0, len(app_id_hex), 2):
                                    payload_pvtd.append(app_id_hex[i:i + 2])
                            else:
                                print(f"[ENCODER] Error: Unknown Android App Id: {app_id_key}")
                                continue
                        
                        else:
                            # Custom: UUID:AppIdString 형식
                            os_uuid = parts[0].replace('-', '')  # UUID에서 하이픈 제거
                            app_id_string = parts[1]
                            
                            # UUID 길이 검증 (16 bytes = 32 hex characters)
                            if len(os_uuid) != 32:
                                print(f"[ENCODER] Error: Invalid UUID length. Expected 32 hex characters, got {len(os_uuid)}: {os_uuid}")
                                raise ValueError(f"Invalid UUID format for OS Id. UUID must be 32 hex characters (16 bytes). Got: {parts[0]}")
                            
                            # UUID가 유효한 hex 문자열인지 검증
                            try:
                                int(os_uuid, 16)
                            except ValueError:
                                print(f"[ENCODER] Error: Invalid UUID hex format: {os_uuid}")
                                raise ValueError(f"Invalid UUID format for OS Id. Must contain only hex characters (0-9, A-F). Got: {parts[0]}")
                            
                            # OS UUID를 16 bytes로 추가
                            for i in range(0, len(os_uuid), 2):
                                payload_pvtd.append(os_uuid[i:i + 2].upper())
                            
                            # App Id를 ASCII로 인코딩
                            app_id_bytes = app_id_string.encode('ascii')
                            app_id_len = len(app_id_bytes)
                            
                            # Length 추가
                            payload_pvtd.append(format(app_id_len, '02X'))
                            
                            # App Id bytes 추가
                            for byte in app_id_bytes:
                                payload_pvtd.append(format(byte, '02X'))
                    
                    # 0x10: IPv4 remote address
                    elif comp_type == "IPv4 remote address":
                        # 8 bytes: 4 bytes address + 4 bytes mask (NO length field)
                        parts = comp_value.split('/')
                        if len(parts) == 2:
                            # IPv4 address (4 bytes)
                            addr_parts = parts[0].split('.')
                            for part in addr_parts:
                                payload_pvtd.append(format(int(part), '02X'))
                            # IPv4 mask (4 bytes)
                            mask_parts = parts[1].split('.')
                            for part in mask_parts:
                                payload_pvtd.append(format(int(part), '02X'))
                    
                    # 0x21: IPv6 remote address/prefix length
                    elif comp_type == "IPv6 remote address/prefix length":
                        # 17 bytes: 16 bytes address + 1 byte prefix (NO length field)
                        parts = comp_value.split('/')
                        if len(parts) == 2:
                            ipv6_addr = ipaddress.IPv6Address(parts[0])
                            ipv6_bytes = ipv6_addr.packed
                            # IPv6 address (16 bytes)
                            for byte in ipv6_bytes:
                                payload_pvtd.append(format(byte, '02X'))
                            # Prefix length (1 byte)
                            prefix_len = int(parts[1])
                            payload_pvtd.append(format(prefix_len, '02X'))
                    
                    # 0x30: Protocol identifier/next header
                    elif comp_type == "Protocol identifier/next header":
                        # 1 byte (NO length field)
                        from spec import PROTOCOL_REV
                        if comp_value in PROTOCOL_REV:
                            protocol = PROTOCOL_REV[comp_value]  # "TCP" → 0x06
                        else:
                            protocol = int(comp_value)  # 숫자도 허용 (하위 호환)
                        payload_pvtd.append(format(protocol, '02X'))
                    
                    # 0x50: Single remote port
                    elif comp_type == "Single remote port":
                        # 2 bytes: port number (NO length field)
                        port = int(comp_value)
                        payload_pvtd.append(format(port >> 8, '02X'))  # High byte
                        payload_pvtd.append(format(port & 0xFF, '02X'))  # Low byte
                    
                    # 0x51: Remote port range
                    elif comp_type == "Remote port range":
                        # 4 bytes: 2 bytes low + 2 bytes high (NO length field)
                        ports = comp_value.split('-')
                        if len(ports) == 2:
                            port_low = int(ports[0].strip())
                            port_high = int(ports[1].strip())
                            payload_pvtd.append(format(port_low >> 8, '02X'))
                            payload_pvtd.append(format(port_low & 0xFF, '02X'))
                            payload_pvtd.append(format(port_high >> 8, '02X'))
                            payload_pvtd.append(format(port_high & 0xFF, '02X'))
                    
                    # 0x52: IP 3 tuple
                    elif comp_type == "IP 3 tuple":
                        # comp_value는 객체 형식: {ipType, portType, address, mask/prefix, protocol, port/portLow/portHigh}
                        if isinstance(comp_value, dict):
                            ip_type = comp_value.get('ipType', 'IPv4')
                            port_type = comp_value.get('portType', 'Single')
                            address = comp_value.get('address', '').strip()
                            mask = comp_value.get('mask', '').strip()
                            prefix = comp_value.get('prefix', '').strip()
                            protocol = comp_value.get('protocol', '').strip()
                            port = comp_value.get('port', '').strip()
                            port_low = comp_value.get('portLow', '').strip()
                            port_high = comp_value.get('portHigh', '').strip()
                            
                            # Debug logging
                            print(f"[ENCODE] IP 3-tuple values: address='{address}', mask='{mask}', prefix='{prefix}', protocol='{protocol}', port='{port}', port_low='{port_low}', port_high='{port_high}'")
                            
                            # Bitmap 생성
                            bitmap = 0
                            
                            # Validation: IPv4 address and subnet mask must be used together
                            if ip_type == 'IPv4' and (address or mask):
                                if not address or not mask:
                                    raise ValueError("IP 3-tuple: IPv4 address and subnet mask must both be specified")
                            
                            # Validation: IPv6 address and prefix length must be used together
                            if ip_type == 'IPv6' and (address or prefix):
                                if not address or not prefix:
                                    raise ValueError("IP 3-tuple: IPv6 address and prefix length must both be specified")
                            
                            # Validation: IPv4 address format
                            if address and ip_type == 'IPv4':
                                try:
                                    parts = address.split('.')
                                    if len(parts) != 4:
                                        raise ValueError("IP 3-tuple: Invalid IPv4 address format, e.g., 192.168.1.1")
                                    for part in parts:
                                        val = int(part)
                                        if val < 0 or val > 255:
                                            raise ValueError(f"IP 3-tuple: Invalid IPv4 address octet value {val}, must be 0-255")
                                except ValueError as e:
                                    if "IP 3-tuple" in str(e):
                                        raise
                                    raise ValueError("IP 3-tuple: Invalid IPv4 address format")
                            
                            # Validation: IPv4 subnet mask format
                            if mask and ip_type == 'IPv4':
                                try:
                                    parts = mask.split('.')
                                    if len(parts) != 4:
                                        raise ValueError("IP 3-tuple: Invalid subnet mask format, e.g., 255.255.255.0")
                                    for part in parts:
                                        val = int(part)
                                        if val < 0 or val > 255:
                                            raise ValueError(f"IP 3-tuple: Invalid subnet mask octet value {val}, must be 0-255")
                                    
                                    # Validation: Check for contiguous 1s (no 0s followed by 1s)
                                    # Convert mask to 32-bit binary string
                                    mask_binary = ''.join([bin(int(part))[2:].zfill(8) for part in parts])
                                    
                                    # Check if mask has contiguous 1s (valid pattern: 1*0*)
                                    # Invalid if we find '01' pattern (0 followed by 1)
                                    if '01' in mask_binary:
                                        raise ValueError("IP 3-tuple: Invalid subnet mask, must be contiguous from MSB, e.g., 255.255.255.0")
                                    
                                except ValueError as e:
                                    if "IP 3-tuple" in str(e):
                                        raise
                                    raise ValueError("IP 3-tuple: Invalid subnet mask format")
                            
                            # Validation: IPv6 address format
                            if address and ip_type == 'IPv6':
                                try:
                                    ipaddress.IPv6Address(address)
                                except Exception:
                                    raise ValueError("IP 3-tuple: Invalid IPv6 address format")
                            
                            # Validation: IPv6 prefix length
                            if prefix and ip_type == 'IPv6':
                                try:
                                    prefix_val = int(prefix)
                                    if prefix_val < 0 or prefix_val > 128:
                                        raise ValueError("IP 3-tuple: Invalid IPv6 prefix length, must be 0-128")
                                except ValueError as e:
                                    if "IP 3-tuple" in str(e):
                                        raise
                                    raise ValueError("IP 3-tuple: Invalid IPv6 prefix length format")
                            
                            # Validation: Port values
                            if port:
                                try:
                                    port_val = int(port)
                                    if port_val < 0 or port_val > 65535:
                                        raise ValueError("IP 3-tuple: Invalid port number, must be 0-65535")
                                except ValueError as e:
                                    if "IP 3-tuple" in str(e):
                                        raise
                                    raise ValueError("IP 3-tuple: Invalid port number format")
                            
                            if port_low or port_high:
                                try:
                                    if port_low:
                                        low_val = int(port_low)
                                        if low_val < 0 or low_val > 65535:
                                            raise ValueError("IP 3-tuple: Invalid port range low limit, must be 0-65535")
                                    if port_high:
                                        high_val = int(port_high)
                                        if high_val < 0 or high_val > 65535:
                                            raise ValueError("IP 3-tuple: Invalid port range high limit, must be 0-65535")
                                    if port_low and port_high:
                                        if int(port_low) > int(port_high):
                                            raise ValueError("IP 3-tuple: Port range low limit must be less than or equal to high limit")
                                except ValueError as e:
                                    if "IP 3-tuple" in str(e):
                                        raise
                                    raise ValueError("IP 3-tuple: Invalid port range format")
                            
                            # Bit 1: IPv4 address field present
                            if ip_type == 'IPv4' and address and mask:
                                bitmap |= 0x01
                            
                            # Bit 2: IPv6 address field present
                            if ip_type == 'IPv6' and address and prefix:
                                bitmap |= 0x02
                            
                            # Bit 3: Protocol identifier present
                            if protocol:
                                bitmap |= 0x04
                            
                            # Bit 4: Single remote port present
                            if port_type == 'Single' and port:
                                bitmap |= 0x08
                            
                            # Bit 5: Remote port range present
                            if port_type == 'Range' and port_low and port_high:
                                bitmap |= 0x10
                            
                            # 최소 하나의 필드 검증
                            if bitmap == 0:
                                raise ValueError("IP 3-tuple: At least one of IP address, protocol, or port must be specified")
                            
                            # Bitmap 추가 (1 byte)
                            payload_pvtd.append(format(bitmap, '02X'))
                            
                            # IPv4 address and mask (if bit 1 is set)
                            if bitmap & 0x01:
                                # IPv4 address (4 bytes)
                                addr_parts = address.split('.')
                                if len(addr_parts) == 4:
                                    for part in addr_parts:
                                        payload_pvtd.append(format(int(part), '02X'))
                                
                                # IPv4 mask (4 bytes)
                                mask_parts = mask.split('.')
                                if len(mask_parts) == 4:
                                    for part in mask_parts:
                                        payload_pvtd.append(format(int(part), '02X'))
                            
                            # IPv6 address and prefix (if bit 2 is set)
                            if bitmap & 0x02:
                                # IPv6 address (16 bytes)
                                ipv6_addr = ipaddress.IPv6Address(address)
                                ipv6_bytes = ipv6_addr.packed
                                for byte in ipv6_bytes:
                                    payload_pvtd.append(format(byte, '02X'))
                                
                                # Prefix length (1 byte)
                                prefix_len = int(prefix)
                                payload_pvtd.append(format(prefix_len, '02X'))
                            
                            # Protocol identifier (if bit 3 is set)
                            if bitmap & 0x04:
                                from spec import PROTOCOL_REV
                                if protocol in PROTOCOL_REV:
                                    protocol_id = PROTOCOL_REV[protocol]  # "TCP" → 0x06
                                else:
                                    protocol_id = int(protocol)  # 숫자도 허용
                                payload_pvtd.append(format(protocol_id, '02X'))
                            
                            # Single remote port (if bit 4 is set)
                            if bitmap & 0x08:
                                port_num = int(port)
                                payload_pvtd.append(format(port_num >> 8, '02X'))  # High byte
                                payload_pvtd.append(format(port_num & 0xFF, '02X'))  # Low byte
                            
                            # Remote port range (if bit 5 is set)
                            if bitmap & 0x10:
                                port_low_num = int(port_low)
                                port_high_num = int(port_high)
                                payload_pvtd.append(format(port_low_num >> 8, '02X'))
                                payload_pvtd.append(format(port_low_num & 0xFF, '02X'))
                                payload_pvtd.append(format(port_high_num >> 8, '02X'))
                                payload_pvtd.append(format(port_high_num & 0xFF, '02X'))
                    
                    # 0x60: Security parameter index
                    elif comp_type == "Security parameter index":
                        # 4 bytes (NO length field)
                        spi = int(comp_value, 16) if comp_value.startswith('0x') else int(comp_value)
                        payload_pvtd.append(format((spi >> 24) & 0xFF, '02X'))
                        payload_pvtd.append(format((spi >> 16) & 0xFF, '02X'))
                        payload_pvtd.append(format((spi >> 8) & 0xFF, '02X'))
                        payload_pvtd.append(format(spi & 0xFF, '02X'))
                    
                    # 0x70: Type of service/traffic class
                    elif comp_type == "Type of service/traffic class":
                        # 1 byte (NO length field)
                        tos = int(comp_value, 16) if comp_value.startswith('0x') else int(comp_value)
                        payload_pvtd.append(format(tos, '02X'))
                    
                    # 0x80: Flow label
                    elif comp_type == "Flow label":
                        # 3 bytes (NO length field)
                        flow = int(comp_value, 16) if comp_value.startswith('0x') else int(comp_value)
                        payload_pvtd.append(format((flow >> 16) & 0xFF, '02X'))
                        payload_pvtd.append(format((flow >> 8) & 0xFF, '02X'))
                        payload_pvtd.append(format(flow & 0xFF, '02X'))
                    
                    # 0x81: Destination MAC address
                    elif comp_type == "Destination MAC address":
                        # 6 bytes (NO length field)
                        mac_parts = comp_value.replace(':', '').replace('-', '')
                        for i in range(0, 12, 2):
                            payload_pvtd.append(mac_parts[i:i+2].upper())
                    
                    # 0x83: 802.1Q C-TAG VID
                    elif comp_type == "802.1Q C-TAG VID":
                        # 2 bytes (NO length field)
                        vid = int(comp_value)
                        payload_pvtd.append(format(vid >> 8, '02X'))
                        payload_pvtd.append(format(vid & 0xFF, '02X'))
                    
                    # 0x84: 802.1Q S-TAG VID
                    elif comp_type == "802.1Q S-TAG VID":
                        # 2 bytes (NO length field)
                        vid = int(comp_value)
                        payload_pvtd.append(format(vid >> 8, '02X'))
                        payload_pvtd.append(format(vid & 0xFF, '02X'))
                    
                    # 0x85: 802.1Q C-TAG PCP/DEI
                    elif comp_type == "802.1Q C-TAG PCP/DEI":
                        # 1 byte (NO length field)
                        pcp_dei = int(comp_value, 16) if comp_value.startswith('0x') else int(comp_value)
                        payload_pvtd.append(format(pcp_dei, '02X'))
                    
                    # 0x86: 802.1Q S-TAG PCP/DEI
                    elif comp_type == "802.1Q S-TAG PCP/DEI":
                        # 1 byte (NO length field)
                        pcp_dei = int(comp_value, 16) if comp_value.startswith('0x') else int(comp_value)
                        payload_pvtd.append(format(pcp_dei, '02X'))
                    
                    # 0x87: Ethertype
                    elif comp_type == "Ethertype":
                        # 2 bytes (NO length field)
                        ethertype = int(comp_value, 16) if comp_value.startswith('0x') else int(comp_value)
                        payload_pvtd.append(format(ethertype >> 8, '02X'))
                        payload_pvtd.append(format(ethertype & 0xFF, '02X'))
                    
                    # 0x88: DNN
                    elif comp_type == 'DNN':
                        # Variable length: DNN length + APN length + string
                        td_val_byte = comp_value.encode('ascii')
                        apn_len = len(td_val_byte)
                        dnn_len = apn_len + 1

                        payload_pvtd.append(format(dnn_len, '02X'))
                        payload_pvtd.append(format(apn_len, '02X'))

                        for byte in td_val_byte:
                            payload_pvtd.append(format(byte, '02X'))

                    # 0x90: Connection capabilities
                    elif comp_type == "Connection capabilities":
                        # Variable length: count + capability IDs
                        td_conn_capa = comp_value.split(',')
                        valid_capabilities = []
                        
                        for item in td_conn_capa:
                            item = item.strip()
                            if item in spec.CONNECTION_CAPABILITY_REV:
                                capability_id = spec.CONNECTION_CAPABILITY_REV[item]
                                valid_capabilities.append(capability_id)
                        
                        payload_pvtd.append(format(len(valid_capabilities), '02X'))
                        
                        for capability_id in valid_capabilities:
                            payload_pvtd.append(format(capability_id, '02X'))

                    # 0x91: Destination FQDN
                    elif comp_type == "Destination FQDN":
                        # Variable length: length + string
                        fqdn_bytes = comp_value.encode('ascii')
                        fqdn_len = len(fqdn_bytes)
                        payload_pvtd.append(format(fqdn_len, '02X'))
                        for byte in fqdn_bytes:
                            payload_pvtd.append(format(byte, '02X'))
                    
                    # 0x92: Regular expression
                    elif comp_type == "Regular expression":
                        # Variable length: length + string
                        regex_bytes = comp_value.encode('utf-8')
                        regex_len = len(regex_bytes)
                        payload_pvtd.append(format(regex_len, '02X'))
                        for byte in regex_bytes:
                            payload_pvtd.append(format(byte, '02X'))
                    
                    # 0xA0: OS App Id
                    elif comp_type == "OS App Id":
                        # Same as OS Id + OS App Id but without OS ID
                        app_id = comp_value.replace(' ', '')
                        app_id_byte = app_id.encode('ascii')
                        app_id_len = len(app_id_byte)
                        payload_pvtd.append(format(app_id_len, '02X'))
                        for byte in app_id_byte:
                            payload_pvtd.append(format(byte, '02X'))
                    
                    # 0xA1: Destination MAC address range
                    elif comp_type == "Destination MAC address range":
                        # 12 bytes: 6 bytes start + 6 bytes end (NO length field)
                        macs = comp_value.split('-')
                        if len(macs) == 2:
                            for mac in macs:
                                mac_clean = mac.strip().replace(':', '').replace('-', '')
                                for i in range(0, 12, 2):
                                    payload_pvtd.append(mac_clean[i:i+2].upper())
                    
                    # 0xA2: PIN ID
                    elif comp_type == "PIN ID":
                        # Variable length: length + string
                        pin_bytes = comp_value.encode('ascii')
                        pin_len = len(pin_bytes)
                        payload_pvtd.append(format(pin_len, '02X'))
                        for byte in pin_bytes:
                            payload_pvtd.append(format(byte, '02X'))
                    
                    # 0xA3: Connectivity group ID
                    elif comp_type == "Connectivity group ID":
                        # Variable length: length + string
                        group_bytes = comp_value.encode('ascii')
                        group_len = len(group_bytes)
                        payload_pvtd.append(format(group_len, '02X'))
                        for byte in group_bytes:
                            payload_pvtd.append(format(byte, '02X'))
                    
                    else:
                        print(f"Unknown TD component type: {comp_type}")

        # Calculate TD length and add precedence
        td_len = len(payload_pvtd)
        td_len_hex = format(td_len, '04X')
        payload_pvtd.insert(0, td_len_hex[2:])
        payload_pvtd.insert(0, td_len_hex[:2])

        payload_pvtd.insert(0, format(int(ursp_pv), '02X'))
        payload_pvtd_list.append(payload_pvtd)

        print(f"[ENCODER] URSP rule {ursp_cnt} TD payload: {' '.join(payload_pvtd)}")

        # Process RSD components for this URSP rule
        rsd_list = rule.get('rsd_list', [])
        for rsd_idx, rsd in enumerate(rsd_list):
            rsd_pv = rsd.get('precedence_value', 1)
            rsd_components = rsd.get('rsd_components', [])

            payload_rsd = []
            for comp_idx, comp in enumerate(rsd_components):
                rsd_conts_type = comp.get('type', 'SSC mode')
                rsd_conts_val = comp.get('value', '1')

                if rsd_conts_type in spec.RSD_TYPES_BY_NAME:
                    rsd_conts_type_hex = format(spec.RSD_TYPES_BY_NAME[rsd_conts_type], '02X')
                else:
                    print("*Unknown rsd_conts_type")
                    continue
                payload_rsd.append(rsd_conts_type_hex)

                if rsd_conts_type == 'S-NSSAI':
                    # Parse S-NSSAI value: "SST 1" or "SST 1 + SD 100"
                    if ' + SD ' in rsd_conts_val:
                        # SST + SD (Length = 4)
                        SST, SD = rsd_conts_val.split(' + ')
                        sst_value = int(SST.split(' ')[1])
                        sd_value = int(SD.split(' ')[1])
                        
                        rsd_conts_len = '04'  # Length = 4 bytes
                        payload_rsd.append(rsd_conts_len)
                        payload_rsd.append(format(sst_value, '02X'))
                        
                        sd_hex = format(sd_value, '06X')
                        for i in range(0, len(sd_hex), 2):
                            payload_rsd.append(sd_hex[i:i + 2])
                    else:
                        # SST only (Length = 1)
                        sst_value = int(rsd_conts_val.split(' ')[1])
                        
                        rsd_conts_len = '01'  # Length = 1 byte
                        payload_rsd.append(rsd_conts_len)
                        payload_rsd.append(format(sst_value, '02X'))

                elif rsd_conts_type == 'DNN':
                    rsd_conts_val_byte = rsd_conts_val.encode('ascii')

                    apn_len = len(rsd_conts_val_byte)
                    dnn_len = apn_len + 1

                    payload_rsd.append(format(dnn_len, '02X'))
                    payload_rsd.append(format(apn_len, '02X'))

                    for byte in rsd_conts_val_byte:
                        payload_rsd.append(format(byte, '02X'))

                # shall not include value field
                elif rsd_conts_type in spec.rsd_zero:
                    continue

                # value field shall be encoded as a one octet
                elif rsd_conts_type in spec.rsd_one:
                    if rsd_conts_type == "SSC mode":
                        # SSC mode: convert string to proper hex value
                        if rsd_conts_val in spec.SSC_MODE_REV:
                            ssc_mode_id = spec.SSC_MODE_REV[rsd_conts_val]
                            rsd_conts_val_hex = format(ssc_mode_id, '02X')
                        else:
                            # Fallback: try to parse as integer
                            rsd_conts_val_hex = format(int(rsd_conts_val), '02X')
                    elif rsd_conts_type == "PDU session type":
                        # PDU session type: convert string to proper hex value
                        if rsd_conts_val in spec.PDU_SESSION_TYPE_REV:
                            pdu_type_id = spec.PDU_SESSION_TYPE_REV[rsd_conts_val]
                            rsd_conts_val_hex = format(pdu_type_id, '02X')
                        else:
                            # Fallback: try to parse as integer
                            rsd_conts_val_hex = format(int(rsd_conts_val), '02X')
                    elif rsd_conts_type == "Preferred access type":
                        # Preferred access type: convert string to proper hex value
                        if rsd_conts_val in spec.PREFERRED_ACCESS_TYPE_REV:
                            access_type_id = spec.PREFERRED_ACCESS_TYPE_REV[rsd_conts_val]
                            rsd_conts_val_hex = format(access_type_id, '02X')
                        else:
                            # Fallback: try to parse as integer
                            rsd_conts_val_hex = format(int(rsd_conts_val), '02X')
                    elif rsd_conts_type == "PDU session pair ID":
                        # PDU session pair ID: convert string to proper hex value
                        if rsd_conts_val in spec.PDU_SESSION_PAIR_ID_REV:
                            pair_id = spec.PDU_SESSION_PAIR_ID_REV[rsd_conts_val]
                            rsd_conts_val_hex = format(pair_id, '02X')
                        else:
                            # Fallback: try to parse as integer
                            rsd_conts_val_hex = format(int(rsd_conts_val), '02X')
                    elif rsd_conts_type == "RSN":
                        # RSN: convert string to proper hex value
                        if rsd_conts_val in spec.RSN_REV:
                            rsn_id = spec.RSN_REV[rsd_conts_val]
                            rsd_conts_val_hex = format(rsn_id, '02X')
                        else:
                            # Fallback: try to parse as integer
                            rsd_conts_val_hex = format(int(rsd_conts_val), '02X')
                    else:
                        # Fallback: try to parse as integer
                        rsd_conts_val_hex = format(int(rsd_conts_val), '02X')
                    payload_rsd.append(rsd_conts_val_hex)

                # Location criteria or Time window (variable length, TBD)
                elif rsd_conts_type == "Location criteria":
                    print("*Location criteria type TBD - requires complex location area encoding")
                    # TODO: Implement location area encoding per 3GPP TS 24.526 Figure 5.2.5
                
                elif rsd_conts_type == "Time window":
                    print("*Time window type TBD - requires 64-bit NTP timestamp encoding")
                    # TODO: Implement NTP timestamp encoding (Starttime + Stoptime, 16 bytes total)

            # Add RSD length and precedence
            rsd_conts_len = len(payload_rsd)
            rsd_conts_len_hex = format(rsd_conts_len, '04X')
            payload_rsd.insert(0, rsd_conts_len_hex[2:])
            payload_rsd.insert(0, rsd_conts_len_hex[:2])
            payload_rsd.insert(0, format(int(rsd_pv), '02X'))

            rsd_len = len(payload_rsd)
            rsd_len_hex = format(rsd_len, '04X')
            payload_rsd.insert(0, rsd_len_hex[2:])
            payload_rsd.insert(0, rsd_len_hex[:2])

            payload_rsd_list.append(payload_rsd)

    # Build final URSP payload
    payload_ursp_list = []
    
    for ursp_cnt in range(len(ursp_rules)):
        payload_ursp = []
        payload_ursp.extend(payload_pvtd_list[ursp_cnt])

        # Calculate RSD list length for this URSP rule
        rsd_list = ursp_rules[ursp_cnt].get('rsd_list', [])
        rsd_list_len = 0
        
        # Calculate total length of all RSDs for this URSP rule
        rsd_start_idx = sum(len(ursp_rules[i].get('rsd_list', [])) for i in range(ursp_cnt))
        for rsd_cnt in range(len(rsd_list)):
            if rsd_start_idx + rsd_cnt < len(payload_rsd_list):
                rsd_list_len += len(payload_rsd_list[rsd_start_idx + rsd_cnt])

        rsd_list_len_hex = format(rsd_list_len, '04X')
        payload_ursp.append(rsd_list_len_hex[:2])
        payload_ursp.append(rsd_list_len_hex[2:])

        # Add RSD payloads for this URSP rule
        for rsd_cnt in range(len(rsd_list)):
            if rsd_start_idx + rsd_cnt < len(payload_rsd_list):
                payload_ursp.extend(payload_rsd_list[rsd_start_idx + rsd_cnt])

        ursp_len = len(payload_ursp)
        ursp_len_hex = format(ursp_len, '04X')
        payload_ursp.insert(0, ursp_len_hex[2:])
        payload_ursp.insert(0, ursp_len_hex[:2])

        payload_ursp_list.append(payload_ursp)

    # Calculate total URSP length
    ursp_total_len = 0
    for ursp_cnt in range(len(ursp_rules)):
        ursp_total_len += len(payload_ursp_list[ursp_cnt])

    # Build final payload
    payload_ursp_total = []
    for ursp_cnt in range(len(ursp_rules)):
        payload_ursp_total.extend(payload_ursp_list[ursp_cnt])

    # Add UE policy part header
    payload_ursp_total.insert(0, '01')  # UE policy part type: URSP

    ursp_total_len_hex = format(len(payload_ursp_total), '04X')
    payload_ursp_total.insert(0, ursp_total_len_hex[2:])
    payload_ursp_total.insert(0, ursp_total_len_hex[:2])

    # Add instruction contents
    payload_ursp_total.insert(0, format(int(UPSC), '04X')[2:])
    payload_ursp_total.insert(0, format(int(UPSC), '04X')[:2])

    ins_len = len(payload_ursp_total)
    ins_len_hex = format(ins_len, '04X')
    payload_ursp_total.insert(0, ins_len_hex[2:])
    payload_ursp_total.insert(0, ins_len_hex[:2])

    # Add PLMN (3 bytes) - should come right after UE policy section management sublist length
    plmn_bytes = [PLMN[i:i+2] for i in range(0, len(PLMN), 2)]
    for plmn_byte in reversed(plmn_bytes):  # Insert in reverse order to maintain correct sequence
        payload_ursp_total.insert(0, plmn_byte)

    # Add UE policy section management
    upsm_len = len(payload_ursp_total)
    upsm_len_hex = format(upsm_len, '04X')
    payload_ursp_total.insert(0, upsm_len_hex[2:])
    payload_ursp_total.insert(0, upsm_len_hex[:2])

    upsm_list_len = len(payload_ursp_total)
    upsm_list_len_hex = format(upsm_list_len, '04X')
    payload_ursp_total.insert(0, upsm_list_len_hex[2:])
    payload_ursp_total.insert(0, upsm_list_len_hex[:2])

    # Add message header
    payload_ursp_total.insert(0, '01')  # Message type: MANAGE UE POLICY COMMAND
    payload_ursp_total.insert(0, format(int(PTI), '02X'))  # PTI

    # Add payload container
    payload_len = len(payload_ursp_total)
    payload_len_hex = format(payload_len, '04X')
    payload_ursp_total.insert(0, payload_len_hex[2:])
    payload_ursp_total.insert(0, payload_len_hex[:2])
    payload_ursp_total.insert(0, '05')  # Payload container type
    payload_ursp_total.insert(0, '68')  # DL NAS Transport

    # Create dataframe and hex string
    df_dl_nas = pd.DataFrame({'hex': payload_ursp_total})
    dl_nas = ''.join(payload_ursp_total)
    
    # Build EF_URSP per 3GPP TS 31.102 Section 4.4.11.12
    # Structure: Tag(80) + BER-TLV Length + [PLMN(3B) + BER-TLV Length + URSP rules] per PLMN
    
    # 1. Collect pure URSP rules payload (24.526 clause 5.2 coded)
    ursp_rules_bytes = []
    for ursp_cnt in range(len(ursp_rules)):
        ursp_rules_bytes.extend(payload_ursp_list[ursp_cnt])
    
    # 2. Build per-PLMN block: PLMN(3B) + BER-TLV length of URSP rules + URSP rules
    plmn_block = []
    plmn_block.extend([PLMN[i:i+2] for i in range(0, len(PLMN), 2)])  # PLMN 3 bytes
    plmn_block.extend(ber_tlv_length(len(ursp_rules_bytes)))  # Total length of URSP rules
    plmn_block.extend(ursp_rules_bytes)  # URSP rules
    
    # 3. Wrap with URSP Rules data object: Tag(80) + BER-TLV length + content
    ef_ursp_list = ['80']
    ef_ursp_list.extend(ber_tlv_length(len(plmn_block)))
    ef_ursp_list.extend(plmn_block)
    
    ef_ursp = ''.join(ef_ursp_list)

    return df_dl_nas, ef_ursp, dl_nas