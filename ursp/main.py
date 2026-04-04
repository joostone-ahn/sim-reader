from flask import Flask, render_template, request, jsonify, session
import json
import sys
import os

# Add src directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from spec import *
from encoder import encode_ursp
from decoder import decode_ursp
from display import format_ursp_display

app = Flask(__name__)
app.secret_key = 'ursp_analyzer_secret_key'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encode', methods=['POST'])
def encode():
    try:
        data = request.get_json()
        
        # Extract data
        pti = data.get('pti', '151')
        plmn = data.get('plmn', '45006F')
        upsc = data.get('upsc', '2')
        ursp_rules = data.get('ursp_rules', [])
        
        print(f"[ENCODE] Received data: PTI={pti}, PLMN={plmn}, UPSC={upsc}")
        print(f"[ENCODE] URSP Rules count: {len(ursp_rules)}")
        
        # Debug: Print IP 3-tuple data if present
        for rule_idx, rule in enumerate(ursp_rules):
            for td_idx, td in enumerate(rule.get('td_components', [])):
                if td.get('type') == 'IP 3 tuple':
                    print(f"[ENCODE] Rule {rule_idx}, TD {td_idx}: IP 3-tuple value = {td.get('value')}")
        
        # Add Match-all rule automatically if not present
        ursp_rules_with_match_all = add_match_all_rule(ursp_rules)
        
        # Encode URSP (hex generation only)
        result = encode_ursp(pti, plmn, upsc, ursp_rules_with_match_all)
        
        if result['success']:
            # Decode the generated hex to get ursp_rules and breakdown_data
            print(f"[ENCODE] Decoding generated hex for display and breakdown")
            
            # Direct parsing without log extraction since dl_nas is already pure hex
            try:
                from decoder import parse_dl_nas_transport
                ursp_rules, parsed_pti, parsed_plmn, parsed_upsc, breakdown_data = parse_dl_nas_transport(result['dl_nas'])
                
                decode_result = {
                    'success': True,
                    'ursp_rules': ursp_rules,
                    'pti': parsed_pti,
                    'plmn': parsed_plmn,
                    'upsc': parsed_upsc,
                    'breakdown_data': breakdown_data
                }
                print(f"[ENCODE] Direct parsing successful with {len(breakdown_data)} breakdown entries")
                
            except Exception as parse_error:
                print(f"[ENCODE] Direct parsing failed: {str(parse_error)}")
                decode_result = {'success': False, 'error': str(parse_error)}
            
            if decode_result['success']:
                # Format display using decoded ursp_rules and breakdown_data
                display_result = format_ursp_display(decode_result['ursp_rules'], {
                    'pti': decode_result.get('pti', pti),
                    'plmn': decode_result.get('plmn', plmn),
                    'upsc': decode_result.get('upsc', upsc),
                    'breakdown_data': decode_result.get('breakdown_data', [])
                })
                
                # Merge encoder result with display result
                result.update(display_result)
                print(f"[ENCODE] Successfully formatted display with {len(decode_result.get('breakdown_data', []))} breakdown entries")
            else:
                print(f"[ENCODE] Decoder failed: {decode_result.get('error', 'Unknown error')}")
                # Fallback to basic display without breakdown
                display_result = format_ursp_display(ursp_rules_with_match_all, result)
                result.update(display_result)
            
        return jsonify(result)
        
    except Exception as e:
        print(f"[ENCODE] Error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/decode', methods=['POST'])
def decode():
    try:
        data = request.get_json()
        log_text = data.get('log_text', '')
        
        print(f"[DECODE] Processing log text length: {len(log_text)}")
        
        result = decode_ursp(log_text)
        
        if result['success'] and 'ursp_rules' in result:
            # Format display for decoded rules
            display_result = format_ursp_display(result['ursp_rules'], {
                'pti': result.get('pti', '97'),
                'plmn': result.get('plmn', '45006F'),
                'upsc': result.get('upsc', '02'),
                'ursp_data': result.get('hex_data', ''),
                'dl_nas': result.get('hex_data', ''),  # Use the same hex data
                'breakdown_data': result.get('breakdown_data', [])  # Pass breakdown_data from decoder
            })
            result.update(display_result)
        
        return jsonify(result)
        
    except Exception as e:
        print(f"[DECODE] Error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/validate', methods=['POST'])
def validate():
    """Real-time validation endpoint for TD/RSD rules"""
    try:
        data = request.get_json()
        validation_type = data.get('type')  # 'td' or 'rsd'
        components = data.get('components', [])
        
        if validation_type == 'td':
            result = validate_td_components(components)
        elif validation_type == 'rsd':
            result = validate_rsd_components(components)
        else:
            result = {'valid': False, 'error': 'Invalid validation type'}
            
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'valid': False,
            'error': str(e)
        })

@app.route('/connection-capabilities', methods=['GET'])
def get_connection_capabilities():
    """Get connection capabilities from spec.py"""
    try:
        # spec.py의 CONNECTION_CAPABILITY_MAP을 직접 import
        from spec import CONNECTION_CAPABILITY_MAP
        
        # 값들만 추출하여 spec.py 정의 순서대로 반환 (정렬하지 않음)
        capabilities = list(CONNECTION_CAPABILITY_MAP.values())
        
        return jsonify({
            'success': True,
            'capabilities': capabilities
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/td-types', methods=['GET'])
def get_td_types():
    """Get TD component types from spec.py"""
    try:
        from spec import TD_COMPONENT_TYPES
        
        return jsonify({
            'success': True,
            'td_types': TD_COMPONENT_TYPES
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/rsd-types', methods=['GET'])
def get_rsd_types():
    """Get RSD component types from spec.py"""
    try:
        import importlib
        import spec
        importlib.reload(spec)
        
        return jsonify({
            'success': True,
            'rsd_types': spec.RSD_COMPONENT_TYPES
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/sst-values', methods=['GET'])
def get_sst_values():
    """Get SST standard values from spec.py"""
    try:
        from spec import SST_STANDARD_VALUES
        
        return jsonify({
            'success': True,
            'sst_values': SST_STANDARD_VALUES
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/android-app-ids', methods=['GET'])
def get_android_app_ids():
    """Get Android App ID options from spec.py"""
    try:
        from spec import ANDROID_APP_IDS, ANDROID_OS_ID
        
        return jsonify({
            'success': True,
            'android_os_id': ANDROID_OS_ID,
            'app_ids': ANDROID_APP_IDS,
            'app_id_order': list(ANDROID_APP_IDS.keys())  # 딕셔너리 키 순서 사용
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

def add_match_all_rule(ursp_rules):
    """Add Match-all rule with highest precedence value"""
    if not ursp_rules:
        # If no rules, create Match-all with PV=1
        return [{
            'precedence_value': 1,
            'td_components': [],  # Empty = Match-all
            'rsd_list': [{
                'precedence_value': 1,
                'rsd_components': [{
                    'type': 'SSC mode',
                    'value': '1'
                }]
            }]
        }]
    
    # Find highest PV and add 1
    max_pv = max([rule.get('precedence_value', 0) for rule in ursp_rules])
    match_all_pv = max_pv + 1
    
    # Check if Match-all already exists
    has_match_all = any(len(rule.get('td_components', [])) == 0 for rule in ursp_rules)
    
    if not has_match_all:
        match_all_rule = {
            'precedence_value': match_all_pv,
            'td_components': [],  # Empty = Match-all
            'rsd_list': [{
                'precedence_value': 1,
                'rsd_components': [{
                    'type': 'SSC mode',
                    'value': '1'
                }]
            }]
        }
        ursp_rules.append(match_all_rule)
        print(f"[ENCODE] Added Match-all rule with PV={match_all_pv}")
    
    return ursp_rules

if __name__ == '__main__':
    print("Starting URSP Rule Analyzer...")
    print("Access the application at: http://127.0.0.1:8081")
    app.run(host='0.0.0.0', port=8081, debug=False)