"""
URSP Rule Analyzer - Display Module (Unified)
Format URSP data for human-readable display
Consolidated from display.py and display_v2.py
"""

from spec import get_td_type_name_by_id, get_rsd_type_name_by_id, get_connection_capability_name

# === Helper Functions ===

def subnet_mask_to_cidr(mask):
    """
    Convert subnet mask to CIDR prefix length
    
    Args:
        mask: Subnet mask in dotted decimal notation (e.g., "255.255.255.0")
    
    Returns:
        str: CIDR prefix length (e.g., "24")
    """
    try:
        # Convert mask to binary and count 1s
        octets = mask.split('.')
        if len(octets) != 4:
            return mask  # Return original if invalid format
        
        binary = ''.join([bin(int(octet))[2:].zfill(8) for octet in octets])
        prefix_length = binary.count('1')
        
        return str(prefix_length)
    except:
        return mask  # Return original if conversion fails

def format_ip3tuple_value(td_val):
    """
    Format IP 3-tuple value in network engineer friendly notation
    
    Format: Protocol/Address:Port
    Examples:
        - TCP/192.168.1.1/24:8080
        - UDP/2001:db8::1/64:53
        - TCP/192.168.1.0/24:8000-8080
        - TCP:8080 (protocol + port only)
        - 192.168.1.1/24 (address only)
        - TCP (protocol only)
    """
    if not isinstance(td_val, dict):
        return str(td_val)
    
    parts = []
    
    # Protocol part
    protocol = td_val.get('protocol', '').strip()
    
    # Address part
    ip_type = td_val.get('ipType', '')
    address = td_val.get('address', '').strip()
    mask = td_val.get('mask', '').strip()
    prefix = td_val.get('prefix', '').strip()
    
    address_part = ''
    if ip_type == 'IPv4' and address and mask:
        # Convert subnet mask to CIDR notation
        cidr_prefix = subnet_mask_to_cidr(mask)
        address_part = f"{address}/{cidr_prefix}"
    elif ip_type == 'IPv6' and address and prefix:
        # IPv6 with brackets if port is present
        address_part = f"[{address}]/{prefix}" if td_val.get('port') or td_val.get('portLow') else f"{address}/{prefix}"
    elif address:
        address_part = address
    
    # Port part
    port_type = td_val.get('portType', '')
    port = td_val.get('port', '').strip()
    port_low = td_val.get('portLow', '').strip()
    port_high = td_val.get('portHigh', '').strip()
    
    port_part = ''
    if port_type == 'Single' and port:
        port_part = f":{port}"
    elif port_type == 'Range' and port_low and port_high:
        port_part = f":{port_low}-{port_high}"
    
    # Build final format: Protocol/Address:Port
    if protocol and address_part and port_part:
        return f"{protocol}/{address_part}{port_part}"
    elif protocol and address_part:
        return f"{protocol}/{address_part}"
    elif protocol and port_part:
        return f"{protocol}{port_part}"
    elif address_part and port_part:
        return f"{address_part}{port_part}"
    elif protocol:
        return protocol
    elif address_part:
        return address_part
    elif port_part:
        return port_part[1:]  # Remove leading colon
    else:
        return "(empty)"

def _format_table(data, headers):
    """Format data as markdown table without pandas/tabulate"""
    if not data:
        return ""
    
    # Calculate column widths
    col_widths = []
    for i, header in enumerate(headers):
        max_width = len(header)
        for row in data:
            if i < len(row):
                max_width = max(max_width, len(str(row[i])))
        col_widths.append(max_width)
    
    # Build table
    result = []
    
    # Header row
    header_row = "| " + " | ".join(header.ljust(col_widths[i]) for i, header in enumerate(headers)) + " |"
    result.append(header_row)
    
    # Separator row
    separator = "| " + " | ".join("-" * col_widths[i] for i in range(len(headers))) + " |"
    result.append(separator)
    
    # Data rows
    for row in data:
        data_row = "| " + " | ".join(str(row[i]).ljust(col_widths[i]) if i < len(row) else "".ljust(col_widths[i]) for i in range(len(headers))) + " |"
        result.append(data_row)
    
    return "\n".join(result)

def hex_format(hex_stream, bytes_per_line=16):
    """Format hex string with line numbers"""
    try:
        # Remove spaces and ensure uppercase
        hex_clean = hex_stream.replace(' ', '').upper()
        
        # Split into bytes
        hex_list = [hex_clean[i:i+2] for i in range(0, len(hex_clean), 2)]
        
        result = []
        for i in range(0, len(hex_list), bytes_per_line):
            hex_line = hex_list[i:i + bytes_per_line]
            hex_str = ' '.join(hex_line)
            # Format with proper line number and spacing
            result.append(f"{i:04X}   {hex_str}")
        
        return '\n'.join(result)
        
    except Exception as e:
        return f"Error formatting hex: {str(e)}"

# === Main Display Function ===

def format_ursp_display(ursp_rules, encoding_result):
    """
    Format URSP rules for display in enhanced format
    
    Args:
        ursp_rules: List of URSP rules
        encoding_result: Result from encoder or decoder
    
    Returns:
        dict: Formatted display data
    """
    try:
        # Extract basic info from encoding result or use defaults
        pti = encoding_result.get('pti', '97')
        plmn = encoding_result.get('plmn', '45006F')
        upsc = encoding_result.get('upsc', '02')
        
        # Skip URSP info (basic info table) - no PTI/PLMN/UPSC display
        ursp_info = ""  # Empty string - no PTI/PLMN/UPSC table
        
        # Format URSP contents (detailed rules table)
        ursp_conts = format_ursp_contents_table(ursp_rules)
        
        # Format policy command (message breakdown table)
        pol_cmd_txt = format_policy_command_breakdown(ursp_rules, encoding_result)
        
        return {
            'ursp_info': ursp_info,
            'ursp_conts': ursp_conts,
            'pol_cmd_txt': pol_cmd_txt
        }
        
    except Exception as e:
        print(f"[DISPLAY] Error: {str(e)}")
        return {
            'ursp_info': f"Display error: {str(e)}",
            'ursp_conts': '',
            'pol_cmd_txt': ''
        }

def format_ursp_contents_table(ursp_rules):
    """Format URSP contents table showing 3-tier structure clearly"""
    try:
        result_text = []
        
        for rule_index, rule in enumerate(ursp_rules):
            ursp_num = f"URSP_{rule_index}"
            ursp_pv = str(rule.get('precedence_value', 1))
            
            # Rule header with adjusted width
            box_width = 85  # Reduced from 100 to 85
            result_text.append("┌" + "─" * (box_width - 2) + "┐")
            header = f"│ {ursp_num} (Precedence: {ursp_pv})"
            result_text.append(header.ljust(box_width - 1) + "│")
            result_text.append("├" + "─" * (box_width - 2) + "┤")
            
            # TD Components Section
            td_components = rule.get('td_components', [])
            if not td_components:
                td_line = "│ Traffic Descriptor: Match-all"
                result_text.append(td_line.ljust(box_width - 1) + "│")
            else:
                # Check if it's a single Match-all component
                if len(td_components) == 1 and td_components[0].get('type') == 'Match-all':
                    td_header = f"│ Traffic Descriptor: Match-all"
                    result_text.append(td_header.ljust(box_width - 1) + "│")
                    # For Match-all, don't show individual TD components
                else:
                    # Just show "Traffic Descriptor" without count
                    td_header = f"│ Traffic Descriptor"
                    result_text.append(td_header.ljust(box_width - 1) + "│")
                    
                    for td_index, comp in enumerate(td_components):
                        td_num = f"TD_{rule_index}_{td_index}"
                        td_type = comp.get('type', 'Unknown')
                        td_val = comp.get('value', '')
                        
                        # Format IP 3-tuple value in network engineer friendly notation
                        if td_type == 'IP 3 tuple' and isinstance(td_val, dict):
                            td_val = format_ip3tuple_value(td_val)
                        # Convert other dict values to readable string
                        elif isinstance(td_val, dict):
                            td_val = str(td_val)
                        
                        prefix = "├─" if td_index < len(td_components) - 1 else "└─"
                        
                        # Handle Match-all without value
                        if td_type == 'Match-all':
                            td_line = f"│   {prefix} {td_num}: {td_type}"
                            result_text.append(td_line.ljust(box_width - 1) + "│")
                        # Handle Connection capabilities - always show each on separate line
                        elif td_type == 'Connection capabilities':
                            # First line with TD number and type
                            td_line = f"│   {prefix} {td_num}: {td_type}"
                            result_text.append(td_line.ljust(box_width - 1) + "│")
                            
                            # Split capabilities and show each on separate line
                            capabilities = [cap.strip() for cap in str(td_val).split(',')]
                            for cap_index, cap in enumerate(capabilities):
                                # Use consistent 8-space indent (same as RSD content)
                                indent = "        "
                                
                                cap_prefix = "├─" if cap_index < len(capabilities) - 1 else "└─"
                                cap_line = f"│{indent}{cap_prefix} {cap}"
                                result_text.append(cap_line.ljust(box_width - 1) + "│")
                        else:
                            td_line = f"│   {prefix} {td_num}: {td_type} = {td_val}"
                            
                            # If line is too long, wrap it
                            if len(td_line) > box_width - 1:
                                # Split long lines
                                first_part = td_line[:box_width - 4] + "..."
                                result_text.append(first_part.ljust(box_width - 1) + "│")
                                # Add continuation line
                                continuation = f"│       {td_val[box_width - 30:]}"
                                result_text.append(continuation.ljust(box_width - 1) + "│")
                            else:
                                result_text.append(td_line.ljust(box_width - 1) + "│")
            
            # Separator line between TD and RSD
            result_text.append("├" + "─" * (box_width - 2) + "┤")
            
            # RSD Section
            rsd_list = rule.get('rsd_list', [])
            rsd_header = f"│ Route Selection Descriptors"
            result_text.append(rsd_header.ljust(box_width - 1) + "│")
            
            for rsd_index, rsd in enumerate(rsd_list):
                rsd_num = f"RSD_{rule_index}_{rsd_index}"
                rsd_pv = str(rsd.get('precedence_value', 1))
                rsd_components = rsd.get('rsd_components', [])
                
                rsd_prefix = "├─" if rsd_index < len(rsd_list) - 1 else "└─"
                rsd_line = f"│   {rsd_prefix} {rsd_num} (Precedence: {rsd_pv})"
                result_text.append(rsd_line.ljust(box_width - 1) + "│")
                
                for comp_index, rsd_comp in enumerate(rsd_components):
                    rsd_conts_num = f"RSD_{rule_index}_{rsd_index}_{comp_index}"
                    rsd_conts_type = rsd_comp.get('type', 'Unknown')
                    rsd_conts_val = rsd_comp.get('value', '')
                    
                    # Convert dict values to readable string
                    if isinstance(rsd_conts_val, dict):
                        rsd_conts_val = str(rsd_conts_val)
                    
                    comp_prefix = "├─" if comp_index < len(rsd_components) - 1 else "└─"
                    
                    if rsd_index < len(rsd_list) - 1:
                        indent = "       "
                    else:
                        indent = "        "
                    
                    # Check if this RSD type has a value field
                    from spec import RSD_COMPONENT_TYPES
                    type_info = RSD_COMPONENT_TYPES.get(rsd_conts_type, {})
                    has_value = type_info.get('has_value', True)
                    
                    # Format line based on whether type has value
                    if has_value:
                        comp_line = f"│{indent}{comp_prefix} {rsd_conts_num}: {rsd_conts_type} = {rsd_conts_val}"
                    else:
                        comp_line = f"│{indent}{comp_prefix} {rsd_conts_num}: {rsd_conts_type}"
                    
                    # Handle long RSD component values
                    if len(comp_line) > box_width - 1:
                        first_part = comp_line[:box_width - 4] + "..."
                        result_text.append(first_part.ljust(box_width - 1) + "│")
                        # Add continuation line for RSD (only if has value)
                        if has_value:
                            continuation = f"│{indent}    {rsd_conts_val[box_width - 40:]}"
                            result_text.append(continuation.ljust(box_width - 1) + "│")
                    else:
                        result_text.append(comp_line.ljust(box_width - 1) + "│")
            
            # Rule footer
            result_text.append("└" + "─" * (box_width - 2) + "┘")
            result_text.append("")
        
        return '\n'.join(result_text)
        
    except Exception as e:
        return f"Error formatting URSP contents: {str(e)}"

def format_policy_command_breakdown(ursp_rules, encoding_result):
    """
    Format policy command with detailed message breakdown
    
    Args:
        ursp_rules: List of URSP rules (for reference)
        encoding_result: Result from encoder/decoder with breakdown_data
    
    Returns:
        str: Formatted breakdown table
    """
    try:
        result_text = []
        
        # Only decoder results have breakdown_data
        if 'breakdown_data' not in encoding_result or not encoding_result['breakdown_data']:
            return ""
        
        breakdown_entries = encoding_result['breakdown_data']
        
        # Adjusted table width to fit better in terminal
        result_text.append("|=======|=======|=======|==========================================================================|")
        result_text.append("| ind   | dec   | hex   | desc                                                                     |")
        result_text.append("|=======|=======|=======|==========================================================================|")
        
        # ===== FORMAT OUTPUT TABLE =====
        for entry in breakdown_entries:
            if entry[0] == "---":
                result_text.append(f"|-------|-------|-------|--------------------------------------------------------------------------|")
            elif entry[0] == "===":
                result_text.append(f"|=======|=======|=======|==========================================================================|")
            else:
                # Adjusted description column width to 72 characters
                result_text.append(f"| {entry[0]:<5} | {entry[1]:<5} | {entry[2]:<5} | {entry[3]:<72} |")
        
        result_text.append(f"|=======|=======|=======|==========================================================================|")
        
        return '\n'.join(result_text)
        
    except Exception as e:
        return f"Error formatting policy command: {str(e)}"
