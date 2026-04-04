"""
URSP Rule Analyzer - Specification Module (Unified)
Based on 3GPP TS 24.526 with enhanced validation
Consolidated from spec.py and spec_v2.py

File Structure:
1. Common/General Definitions
2. TD (Traffic Descriptor) Section
3. RSD (Route Selection Descriptor) Section
4. Utility Functions
"""

# ============================================================================
# 1. COMMON/GENERAL DEFINITIONS
# ============================================================================

pol_msg_types = {
    0x01: "MANAGE UE POLICY COMMAND",
    0x02: "MANAGE UE POLICY COMPLETE",
    0x03: "MANAGE UE POLICY COMMAND REJECT",
    0x04: "UE STATE INDICATION",
    0x05: "UE POLICY PROVISIONING REQUEST",
    0x06: "UE POLICY PROVISIONING REJECT"
}

pol_part_types = {
    0x01: "URSP",
    0x02: "ANDSP",
    0x03: "V2XP",
    0x04: "ProSeP"
}


# ============================================================================
# 2. TD (TRAFFIC DESCRIPTOR) SECTION
# ============================================================================

# TD Component Types - 3GPP TS 24.526 (규격 순서대로 정렬)
TD_COMPONENT_TYPES = {
    "Match-all": {
        "type_id": 0x01,
        "has_value": False,
        "placeholder": "-",
        "description": "Match all traffic"
    },
    "OS Id + OS App Id": {
        "type_id": 0x08,
        "has_value": True,
        "placeholder": "Android:ENTERPRISE",
        "description": "Operating System ID and Application ID"
    },
    "IPv4 remote address": {
        "type_id": 0x10,
        "has_value": True,
        "placeholder": {"address": "192.168.1.1", "mask": "255.255.255.0"},
        "description": "IPv4 destination address with mask"
    },
    "IPv6 remote address/prefix length": {
        "type_id": 0x21,
        "has_value": True,
        "placeholder": {"address": "2001:db8::1", "prefix": "64"},
        "description": "IPv6 destination address with prefix"
    },
    "Protocol identifier/next header": {
        "type_id": 0x30,
        "has_value": True,
        "placeholder": "TCP",
        "description": "IP protocol number (TCP, UDP, ICMP, ICMPv6)"
    },
    "Single remote port": {
        "type_id": 0x50,
        "has_value": True,
        "placeholder": "443",
        "description": "Single destination port"
    },
    "Remote port range": {
        "type_id": 0x51,
        "has_value": True,
        "placeholder": {"low": "8000", "high": "8080"},
        "description": "Destination port range"
    },
    "IP 3 tuple": {
        "type_id": 0x52,
        "has_value": True,
        "placeholder": {
            "ipType": "IPv4",
            "portType": "Single",
            "address": "",
            "mask": "",
            "protocol": "",
            "port": ""
        },
        "placeholder_ipv4": {
            "address": "192.168.1.1",
            "mask": "255.255.255.0"
        },
        "placeholder_ipv6": {
            "address": "2001:db8::1",
            "prefix": "64"
        },
        "placeholder_port_single": {
            "port": "8080"
        },
        "placeholder_port_range": {
            "portLow": "8000",
            "portHigh": "8080"
        },
        "description": "IP address, protocol, and port combination"
    },
    "Security parameter index": {
        "type_id": 0x60,
        "has_value": True,
        "placeholder": "0x12345678",
        "description": "IPSec SPI value (4 bytes)"
    },
    "Type of service/traffic class": {
        "type_id": 0x70,
        "has_value": True,
        "placeholder": "0x10",
        "description": "IPv4 ToS or IPv6 Traffic Class (1 byte)"
    },
    "Flow label": {
        "type_id": 0x80,
        "has_value": True,
        "placeholder": "0x12345",
        "description": "IPv6 Flow Label (3 bytes)"
    },
    "Destination MAC address": {
        "type_id": 0x81,
        "has_value": True,
        "placeholder": "AA:BB:CC:DD:EE:FF",
        "description": "Ethernet destination MAC (6 bytes)"
    },
    "802.1Q C-TAG VID": {
        "type_id": 0x83,
        "has_value": True,
        "placeholder": "100",
        "description": "Customer VLAN ID (12 bits, 0-4095)"
    },
    "802.1Q S-TAG VID": {
        "type_id": 0x84,
        "has_value": True,
        "placeholder": "200",
        "description": "Service VLAN ID (12 bits, 0-4095)"
    },
    "802.1Q C-TAG PCP/DEI": {
        "type_id": 0x85,
        "has_value": True,
        "placeholder": "0x07",
        "description": "Customer VLAN Priority (3 bits) and DEI (1 bit)"
    },
    "802.1Q S-TAG PCP/DEI": {
        "type_id": 0x86,
        "has_value": True,
        "placeholder": "0x07",
        "description": "Service VLAN Priority (3 bits) and DEI (1 bit)"
    },
    "Ethertype": {
        "type_id": 0x87,
        "has_value": True,
        "placeholder": "0x0800",
        "description": "Ethernet frame type (0x0800=IPv4, 0x86DD=IPv6)"
    },
    "DNN": {
        "type_id": 0x88,
        "has_value": True,
        "placeholder": "internet",
        "description": "Data Network Name"
    },
    "Connection capabilities": {
        "type_id": 0x90,
        "has_value": True,
        "placeholder": "IMS, MMS, SUPL",
        "description": "Supported connection types",
        "is_multi_select": True,
        "options": []  # 나중에 동적으로 설정됨
    },
    "Destination FQDN": {
        "type_id": 0x91,
        "has_value": True,
        "placeholder": "example.com",
        "description": "Fully Qualified Domain Name"
    },
    "Regular expression": {
        "type_id": 0x92,
        "has_value": True,
        "placeholder": ".*\\.example\\.com",
        "description": "Pattern matching expression"
    },
    "OS App Id": {
        "type_id": 0xA0,
        "has_value": True,
        "placeholder": "com.example.app",
        "description": "Application identifier only"
    },
    "Destination MAC address range": {
        "type_id": 0xA1,
        "has_value": True,
        "placeholder": {"low": "AA:BB:CC:DD:EE:00", "high": "AA:BB:CC:DD:EE:FF"},
        "description": "MAC address range (start-end)"
    },
    "PIN ID": {
        "type_id": 0xA2,
        "has_value": True,
        "placeholder": "12345",
        "description": "Personal Identification Number"
    },
    "Connectivity group ID": {
        "type_id": 0xA3,
        "has_value": True,
        "placeholder": "group1",
        "description": "Connection group identifier"
    }
}

# TD Reverse Mappings
TD_TYPES_BY_ID = {comp_info["type_id"]: comp_name for comp_name, comp_info in TD_COMPONENT_TYPES.items()}
TD_TYPES_BY_NAME = {comp_name: comp_info["type_id"] for comp_name, comp_info in TD_COMPONENT_TYPES.items()}

# TD types with zero-length value field
td_zero = ["Match-all"]

# Protocol Identifier Map - IANA Protocol Numbers
PROTOCOL_MAP = {
    0x01: "ICMP",
    0x06: "TCP",
    0x11: "UDP",
    0x32: "ESP",
    0x3A: "ICMPv6"
}

PROTOCOL_REV = {v: k for k, v in PROTOCOL_MAP.items()}

# Set protocol identifier options dynamically
TD_COMPONENT_TYPES["Protocol identifier/next header"]["options"] = list(PROTOCOL_MAP.values())

# Connection Capability Map
CONNECTION_CAPABILITY_MAP = {
    0x01: "IMS",
    0x02: "MMS", 
    0x04: "SUPL",
    0x08: "Internet",
    0x10: "LCS user plane positioning",
    0x20: "Opeartor specific connection",
    # 0x20 to 0xA0: Operator specific connection capabilities
    0xA1: "IoT delay-tolerant",
    0xA2: "IoT non-delay-tolerant",
    0xA3: "Downlink streaming",
    0xA4: "Uplink streaming",
    0xA5: "Vehicular communications",
    0xA6: "Real time interactive",
    0xA7: "Unified communications",
    0xA8: "Background",
    0xA9: "Mission critical communications",
    0xAA: "Time critical communications",
    0xAB: "Low latency loss tolerant communications in un-acknowledged mode"
}

CONNECTION_CAPABILITY_REV = {v: k for k, v in CONNECTION_CAPABILITY_MAP.items()}

# Set connection capabilities options dynamically
TD_COMPONENT_TYPES["Connection capabilities"]["options"] = list(CONNECTION_CAPABILITY_MAP.values())

# Android OS Id + App Id - 3GPP TS 24.526 Type 0x08
ANDROID_OS_ID = "97A498E3FC925C9489860333D06E4E47"

def create_app_id_entry(app_id_string):
    """
    Create Android App ID entry with auto-calculated hex and length
    
    Args:
        app_id_string: Application ID string (e.g., "ENTERPRISE")
    
    Returns:
        dict: Entry with string, hex, and length
    """
    hex_value = app_id_string.encode('ascii').hex().upper()
    length = len(app_id_string)
    
    return {
        "string": app_id_string,
        "hex": hex_value,
        "length": length
    }

# Android App IDs - Auto-generated from strings (순서 유지됨)
ANDROID_APP_IDS = {
    "ENTERPRISE": create_app_id_entry("ENTERPRISE"),
    "ENTERPRISE2": create_app_id_entry("ENTERPRISE2"),
    "ENTERPRISE3": create_app_id_entry("ENTERPRISE3"),
    "ENTERPRISE4": create_app_id_entry("ENTERPRISE4"),
    "ENTERPRISE5": create_app_id_entry("ENTERPRISE5"),
    "CBS": create_app_id_entry("CBS"),
    "PRIORITIZE_LATENCY": create_app_id_entry("PRIORITIZE_LATENCY"),
    "PRIORITIZE_BANDWIDTH": create_app_id_entry("PRIORITIZE_BANDWIDTH"),
    "PRIORITIZE_UNIFIED_COMMUNICATIONS": create_app_id_entry("PRIORITIZE_UNIFIED_COMMUNICATIONS")
}

# TD Helper Functions
def get_td_type_name_by_id(type_id):
    """Get TD type name by type ID"""
    return TD_TYPES_BY_ID.get(type_id, f"Unknown TD type (0x{type_id:02X})")

def get_connection_capability_name(capability_id):
    """Get connection capability name by ID"""
    # Handle operator specific range
    if 0x20 <= capability_id <= 0xA0:
        return f"Operator specific connection capabilities (0x{capability_id:02X})"
    
    return CONNECTION_CAPABILITY_MAP.get(capability_id, f"Unknown capability (0x{capability_id:02X})")

# TD Validation Rules (3GPP TS 24.526)
TD_EXCLUSIVE_PAIRS = [
    ["Single remote port", "Remote port range"],
    ["Destination MAC address", "Destination MAC address range"],
]

TD_COMBINATION_RULES = {
    "PIN ID": "mutually_exclusive_to_all",
    "Connectivity group ID": [
        "IPv4 remote address", "IPv6 remote address/prefix length", 
        "Protocol identifier/next header", "Single remote port", 
        "Remote port range", "IP 3 tuple", "Security parameter index",
        "Type of service/traffic class", "Flow label", "Destination MAC address",
        "802.1Q C-TAG VID", "802.1Q S-TAG VID", "802.1Q C-TAG PCP/DEI", 
        "802.1Q S-TAG PCP/DEI", "Ethertype", "Destination MAC address range"
    ]
}

# TD Validation Function
def validate_td_components(components):
    """
    Validate TD components according to 3GPP TS 24.526 rules
    - Same type: OR logic (allowed)
    - Different types: AND logic (allowed)
    - PIN ID: mutually exclusive to all others
    - Connectivity group ID: limited combinations
    """
    if not components:
        return {'valid': True, 'errors': [], 'warnings': [], 'info': []}
    
    types = [comp.get('type') for comp in components]
    warnings = []
    info = []
    
    # Check PIN ID exclusivity
    pin_id_type = "PIN ID"
    if pin_id_type in types and len(types) > 1:
        return {
            'valid': False, 
            'errors': [f'🚫 "{pin_id_type}" cannot be used with other TD components'],
            'warnings': [],
            'info': []
        }
    
    # Check exclusive pairs
    for type1, type2 in TD_EXCLUSIVE_PAIRS:
        if type1 in types and type2 in types:
            return {
                'valid': False,
                'errors': [f'🚫 "{type1}" and "{type2}" cannot be used together'],
                'warnings': [],
                'info': []
            }
    
    # Check connectivity group ID rules
    conn_group_type = "Connectivity group ID"
    if conn_group_type in types:
        allowed_with_conn_group = TD_COMBINATION_RULES[conn_group_type]
        for comp_type in types:
            if comp_type != conn_group_type and comp_type not in allowed_with_conn_group:
                return {
                    'valid': False,
                    'errors': [f'🚫 "{conn_group_type}" cannot be used with "{comp_type}"'],
                    'warnings': [],
                    'info': []
                }
    
    return {
        'valid': True,
        'errors': [],
        'warnings': warnings,
        'info': info
    }


# ============================================================================
# 3. RSD (ROUTE SELECTION DESCRIPTOR) SECTION
# ============================================================================

# RSD Component Types with enhanced metadata
RSD_COMPONENT_TYPES = {
    "SSC mode": {
        "type_id": 0x01,
        "has_value": True,
        "placeholder": "SSC mode 1",
        "description": "Session and Service Continuity mode",
        "options": []  # 나중에 동적으로 설정됨
    },
    "S-NSSAI": {
        "type_id": 0x02,
        "has_value": True,
        "placeholder": "SST 1",
        "description": "Single Network Slice Selection Assistance Information"
    },
    "DNN": {
        "type_id": 0x04,
        "has_value": True,
        "placeholder": "internet",
        "description": "Data Network Name"
    },
    "PDU session type": {
        "type_id": 0x08,
        "has_value": True,
        "placeholder": "IPv4",
        "description": "PDU session type",
        "options": []  # 나중에 동적으로 설정됨
    },
    "Preferred access type": {
        "type_id": 0x10,
        "has_value": True,
        "placeholder": "3GPP access",
        "description": "Preferred access technology",
        "options": []  # 나중에 동적으로 설정됨
    },
    "Multi-access preference": {
        "type_id": 0x11,
        "has_value": False,
        "placeholder": "No value required",
        "description": "Multi-access preference indicator"
    },
    "Non-seamless non-3GPP offload indication": {
        "type_id": 0x20,
        "has_value": False,
        "placeholder": "No value required",
        "description": "Non-seamless offload indicator"
    },
    "Location criteria": {
        "type_id": 0x40,
        "has_value": True,
        "placeholder": "TBD",
        "description": "Location criteria"
    },
    "Time window": {
        "type_id": 0x80,
        "has_value": True,
        "placeholder": "TBD",
        "description": "Time window"
    },
    "5G ProSe layer-3 UE-to-network relay offload indication": {
        "type_id": 0x81,
        "has_value": False,
        "placeholder": "No value required",
        "description": "ProSe relay offload indicator"
    },
    "PDU session pair ID": {
        "type_id": 0x82,
        "has_value": True,
        "placeholder": "PDU session pair ID 1",
        "description": "PDU session pair identifier",
        "options": []  # 나중에 동적으로 설정됨
    },
    "RSN": {
        "type_id": 0x83,
        "has_value": True,
        "placeholder": "v1",
        "description": "Route Selection Number",
        "options": []  # 나중에 동적으로 설정됨
    },
    "5G ProSe multi-path preference": {
        "type_id": 0x84,
        "has_value": False,
        "placeholder": "No value required",
        "description": "5G ProSe multi-path preference indicator"
    }
}

# RSD Reverse Mappings
RSD_TYPES_BY_ID = {comp_info["type_id"]: comp_name for comp_name, comp_info in RSD_COMPONENT_TYPES.items()}
RSD_TYPES_BY_NAME = {comp_name: comp_info["type_id"] for comp_name, comp_info in RSD_COMPONENT_TYPES.items()}

# RSD types with zero-length value field
rsd_zero = ["Multi-access preference", "Non-seamless non-3GPP offload indication",
            "5G ProSe layer-3 UE-to-network relay offload indication", "5G ProSe multi-path preference"]

# RSD types with one-byte value field
rsd_one = ['SSC mode', "PDU session type", "Preferred access type", "PDU session pair ID", "RSN"]
# Note: "Location criteria" and "Time window" are NOT in rsd_one (variable length encoding)

# 3GPP TS 23.501 Table 5.15.2.2-1: Standardised SST values
SST_STANDARD_VALUES = {
    1: "eMBB",      # enhanced Mobile Broadband
    2: "URLLC",     # Ultra-Reliable Low Latency Communications
    3: "MIoT",      # Massive IoT
    4: "V2X",       # Vehicle-to-Everything
    5: "HMTC",      # High-Performance Machine-Type Communications
    6: "HDLLC",     # High Data rate and Low Latency Communications
    7: "GBRSS"      # Guaranteed Bit Rate Streaming Service
}

SST_STANDARD_VALUES_REV = {v: k for k, v in SST_STANDARD_VALUES.items()}

# PDU Session Type Map - 3GPP TS 24.501 clause 9.11.4.11
PDU_SESSION_TYPE_MAP = {
    0x01: "IPv4",
    0x02: "IPv6", 
    0x03: "IPv4v6"
}

PDU_SESSION_TYPE_REV = {v: k for k, v in PDU_SESSION_TYPE_MAP.items()}

# Preferred Access Type Map - 3GPP TS 24.501 clause 9.11.2.1A
PREFERRED_ACCESS_TYPE_MAP = {
    0x01: "3GPP access",
    0x02: "Non-3GPP access"
}

PREFERRED_ACCESS_TYPE_REV = {v: k for k, v in PREFERRED_ACCESS_TYPE_MAP.items()}

# SSC Mode Map - 3GPP TS 24.501 clause 9.11.4.16
SSC_MODE_MAP = {
    0x01: "SSC mode 1",
    0x02: "SSC mode 2",
    0x03: "SSC mode 3"
}

SSC_MODE_REV = {v: k for k, v in SSC_MODE_MAP.items()}

# PDU Session Pair ID Map - 3GPP TS 24.501 clause 9.11.4.32
PDU_SESSION_PAIR_ID_MAP = {
    0x00: "PDU session pair ID 0",
    0x01: "PDU session pair ID 1",
    0x02: "PDU session pair ID 2",
    0x03: "PDU session pair ID 3",
    0x04: "PDU session pair ID 4",
    0x05: "PDU session pair ID 5",
    0x06: "PDU session pair ID 6"
}

PDU_SESSION_PAIR_ID_REV = {v: k for k, v in PDU_SESSION_PAIR_ID_MAP.items()}

# RSN Map - 3GPP TS 24.501 clause 9.11.4.33
RSN_MAP = {
    0x00: "v1",
    0x01: "v2"
}

RSN_REV = {v: k for k, v in RSN_MAP.items()}

# Set RSD options dynamically
RSD_COMPONENT_TYPES["SSC mode"]["options"] = list(SSC_MODE_MAP.values())
RSD_COMPONENT_TYPES["PDU session type"]["options"] = list(PDU_SESSION_TYPE_MAP.values())
RSD_COMPONENT_TYPES["Preferred access type"]["options"] = list(PREFERRED_ACCESS_TYPE_MAP.values())
RSD_COMPONENT_TYPES["PDU session pair ID"]["options"] = list(PDU_SESSION_PAIR_ID_MAP.values())
RSD_COMPONENT_TYPES["RSN"]["options"] = list(RSN_MAP.values())

# RSD Helper Functions
def get_rsd_type_name_by_id(type_id):
    """Get RSD type name by type ID"""
    return RSD_TYPES_BY_ID.get(type_id, f"Unknown RSD type (0x{type_id:02X})")

# RSD Validation Rules (3GPP TS 24.526)

# Once-only types: Cannot appear more than once in a single RSD
RSD_ONCE_ONLY_TYPES = [
    'Multi-access preference',
    'Non-seamless non-3GPP offload indication',
    '5G ProSe layer-3 UE-to-network relay offload indication',
    '5G ProSe multi-path preference'
]

# Must-be-alone types: Cannot be combined with other RSD components
RSD_MUST_BE_ALONE_TYPES = [
    'Non-seamless non-3GPP offload indication',
    '5G ProSe layer-3 UE-to-network relay offload indication'
]

# Mutually exclusive pairs: Cannot be used together
RSD_EXCLUSIVE_PAIRS = [
    # NOTE: 5G ProSe relay and multi-path are mutually exclusive
    ['5G ProSe layer-3 UE-to-network relay offload indication', '5G ProSe multi-path preference'],
    
    # NOTE 2: UE ignores "Preferred access type" when "Multi-access preference" is present
    ['Preferred access type', 'Multi-access preference'],
    
    # NOTE 5: Redundant PDU session not applicable with multi-access or non-3GPP
    ['PDU session pair ID', 'Multi-access preference'],
    ['RSN', 'Multi-access preference']
    # Note: "PDU session pair ID" + "Preferred access type" and "RSN" + "Preferred access type"
    # are only invalid when Preferred access type = "Non-3GPP access" (value check needed)
    # For simplicity, we treat all combinations as invalid since non-3GPP is the common case
]

# RSD Validation Function
def validate_rsd_components(components):
    """
    Validate RSD components according to 3GPP TS 24.526 rules
    - Same type: NOT allowed (single value only)
    - Different types: AND logic (allowed)
    - Special constraints for zero-length types
    """
    if not components:
        return {'valid': True, 'errors': [], 'warnings': [], 'info': []}
    
    types = [comp.get('type') for comp in components]
    errors = []
    warnings = []
    
    # Count all types
    type_counts = {}
    for comp_type in types:
        type_counts[comp_type] = type_counts.get(comp_type, 0) + 1
    
    # 1. Check for once-only types (3GPP TS 24.526 specific constraints)
    for once_type in RSD_ONCE_ONLY_TYPES:
        if type_counts.get(once_type, 0) > 1:
            errors.append(f'🚫 "{once_type}" cannot be used more than once')
    
    # 2. Check for general duplicate types - WARNING
    duplicate_types = [t for t, count in type_counts.items() if count > 1 and t not in RSD_ONCE_ONLY_TYPES]
    
    for dup_type in duplicate_types:
        warnings.append(f'⚠️ "{dup_type}" used more than once causes UE implementation-dependent routing selection')
    
    # 3. Check for must-be-alone types
    for alone_type in RSD_MUST_BE_ALONE_TYPES:
        if alone_type in types and len(types) > 1:
            errors.append(f'🚫 "{alone_type}" cannot be used with other RSD components')
    
    # 4. Check for mutually exclusive pairs
    for type1, type2 in RSD_EXCLUSIVE_PAIRS:
        if type1 in types and type2 in types:
            errors.append(f'🚫 "{type1}" and "{type2}" cannot be used together')
    
    # Return result with both errors and warnings
    if errors:
        return {
            'valid': False,
            'errors': errors,
            'warnings': warnings,  # 경고도 함께 반환
            'info': []
        }
    
    # Return warnings only (valid but not recommended)
    return {
        'valid': True,
        'errors': [],
        'warnings': warnings,
        'info': []
    }


# ============================================================================
# 4. UTILITY FUNCTIONS
# ============================================================================

def get_next_precedence_value(existing_rules):
    """Get next available precedence value"""
    if not existing_rules:
        return 1
    
    used_values = [rule.get('precedence_value', 0) for rule in existing_rules]
    next_value = 1
    while next_value in used_values:
        next_value += 1
    return next_value
