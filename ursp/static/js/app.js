console.log('URSP Rule Analyzer - app.js loaded successfully');

// Global variables for v2 structure
let urspRules = [];
let connectionCapabilities = []; // spec.py에서 로드할 connection capabilities
let tdTypes = {}; // spec.py에서 로드할 TD component types
let rsdTypes = {}; // spec.py에서 로드할 RSD component types
let sstStandardValues = {}; // spec.py에서 로드할 SST standard values
let androidAppIds = {}; // spec.py에서 로드할 Android App IDs
let androidAppIdOrder = []; // spec.py에서 로드할 Android App ID 순서
let androidOsId = ''; // Android OS ID (고정값)

// RSD Type Priority for auto-selection when adding new RSD content
const RSD_TYPE_PRIORITY = [
    'DNN',
    'PDU session type',
    'SSC mode',
    'S-NSSAI',
    'Preferred access type',
    'PDU session pair ID',
    'RSN'
    // Excluded from auto-selection (must be manually selected):
    // - Zero-length types: 'Multi-access preference', 'Non-seamless non-3GPP offload indication',
    //   '5G ProSe layer-3 UE-to-network relay offload indication', '5G ProSe multi-path preference'
    // - TBD types: 'Location criteria', 'Time window'
];

// TD Type Priority for auto-selection when adding new TD component
const TD_TYPE_PRIORITY = [
    'DNN',
    'Connection capabilities',
    'OS Id + OS App Id',
    'IP 3 tuple',
    // IP 3 tuple includes IPv4/IPv6 address, protocol, and port functionality
    // so we don't need separate types for those
    'Destination MAC address range',
    // Commonly used types prioritized
    // Other types can be manually selected from dropdown
];


// Load connection capabilities from server
async function loadConnectionCapabilities() {
    try {
        const response = await fetch('/connection-capabilities');
        const result = await response.json();
        
        if (result.success) {
            connectionCapabilities = result.capabilities;
            console.log('Connection capabilities loaded:', connectionCapabilities);
        } else {
            console.error('Failed to load connection capabilities:', result.error);
            // 빈 배열로 초기화 (spec.py에서 로드 실패 시)
            connectionCapabilities = [];
        }
    } catch (error) {
        console.error('Error loading connection capabilities:', error);
        // 빈 배열로 초기화
        connectionCapabilities = [];
    }
}

// Load TD types from server
async function loadTDTypes() {
    try {
        const response = await fetch('/td-types');
        const result = await response.json();
        
        if (result.success) {
            // Convert spec.py format to app.js format and preserve type_id for sorting
            const tdTypesWithId = [];
            for (const [typeName, typeInfo] of Object.entries(result.td_types)) {
                tdTypesWithId.push({
                    name: typeName,
                    type_id: typeInfo.type_id,
                    hasValue: typeInfo.has_value,
                    placeholder: typeInfo.placeholder,
                    isMultiSelect: typeInfo.is_multi_select || false,
                    options: typeInfo.options || []
                });
            }
            
            // Sort by type_id (3GPP TS 24.526 standard order)
            tdTypesWithId.sort((a, b) => a.type_id - b.type_id);
            
            // Convert back to object maintaining sorted order
            tdTypes = {};
            for (const item of tdTypesWithId) {
                tdTypes[item.name] = {
                    type_id: item.type_id,
                    hasValue: item.hasValue,
                    placeholder: item.placeholder,
                    isMultiSelect: item.isMultiSelect,
                    options: item.options
                };
            }
            console.log('TD types loaded (sorted by type_id):', tdTypes);
        } else {
            console.error('Failed to load TD types:', result.error);
        }
    } catch (error) {
        console.error('Error loading TD types:', error);
    }
}

// Load RSD types from server
async function loadRSDTypes() {
    try {
        const response = await fetch('/rsd-types');
        const result = await response.json();
        
        if (result.success) {
            // Convert spec.py format to app.js format
            rsdTypes = {};
            for (const [typeName, typeInfo] of Object.entries(result.rsd_types)) {
                rsdTypes[typeName] = {
                    hasValue: typeInfo.has_value,
                    placeholder: typeInfo.placeholder,
                    options: typeInfo.options || []  // options 필드 추가
                };
            }
            console.log('RSD types loaded:', rsdTypes);
        } else {
            console.error('Failed to load RSD types:', result.error);
        }
    } catch (error) {
        console.error('Error loading RSD types:', error);
    }
}

// Load SST standard values from server
async function loadSSTValues() {
    try {
        const response = await fetch('/sst-values');
        const result = await response.json();
        
        if (result.success) {
            sstStandardValues = result.sst_values;
            console.log('SST standard values loaded:', sstStandardValues);
        } else {
            console.error('Failed to load SST values:', result.error);
            // 기본값 사용
            sstStandardValues = {
                1: "eMBB",
                2: "URLLC",
                3: "MIoT",
                4: "V2X",
                5: "HMTC",
                6: "HDLLC",
                7: "GBRSS"
            };
        }
    } catch (error) {
        console.error('Error loading SST values:', error);
        // 기본값 사용
        sstStandardValues = {
            1: "eMBB",
            2: "URLLC",
            3: "MIoT",
            4: "V2X",
            5: "HMTC",
            6: "HDLLC",
            7: "GBRSS"
        };
    }
}

// Load Android App IDs from server
async function loadAndroidAppIds() {
    try {
        const response = await fetch('/android-app-ids');
        const result = await response.json();
        
        if (result.success) {
            androidAppIds = result.app_ids;
            androidAppIdOrder = result.app_id_order || Object.keys(result.app_ids);
            androidOsId = result.android_os_id;
            console.log('Android App IDs loaded:', androidAppIds);
            console.log('Android App ID Order:', androidAppIdOrder);
            console.log('Android OS ID:', androidOsId);
        } else {
            console.error('Failed to load Android App IDs:', result.error);
        }
    } catch (error) {
        console.error('Error loading Android App IDs:', error);
    }
}

// Helper functions
function getNextPrecedenceValue() {
    if (urspRules.length === 0) return 1;
    const usedValues = urspRules.map(rule => rule.precedence_value).filter(val => !isNaN(val));
    let nextValue = 1;
    while (usedValues.includes(nextValue)) {
        nextValue++;
    }
    return nextValue;
}

function getNextRSDPrecedenceValue(rsdList) {
    if (!rsdList || rsdList.length === 0) return 1;
    
    // Exclude fixed RSD (PV=255) from used values
    const usedValues = rsdList
        .filter(rsd => !rsd.isFixed)  // Exclude fixed RSD
        .map(rsd => rsd.precedence_value)
        .filter(val => !isNaN(val));
    
    let nextValue = 1;
    while (usedValues.includes(nextValue)) {
        nextValue++;
    }
    return nextValue;
}

// Initialize with Match-all default rule
function initializeEmptyStructure() {
    urspRules = [];
    
    // DNN 기본값을 tdTypes에서 가져오기
    const dnnDefaultValue = tdTypes['DNN'] ? tdTypes['DNN'].placeholder : 'internet';
    
    // Add fixed Match-all URSP rule (PV=255, cannot be deleted)
    const matchAllRule = {
        precedence_value: 255,
        td_components: [], // Empty = Match-all
        rsd_list: [{
            precedence_value: 255,
            rsd_components: [{
                type: 'DNN',
                value: dnnDefaultValue
            }],
            isFixed: true  // Fixed RSD with PV=255
        }],
        isMatchAll: true, // Flag to prevent deletion and TD modification
        isFixed: true
    };
    
    urspRules.push(matchAllRule);
    console.log(`URSP structure initialized with fixed Match-all rule (PV=255) and fixed RSD (PV=255, DNN: ${dnnDefaultValue})`);
}

// Add new URSP Rule (above Match-all rule)
function addURSPRule() {
    // DNN 기본값을 tdTypes에서 가져오기
    const dnnDefaultValue = tdTypes['DNN'] ? tdTypes['DNN'].placeholder : 'internet';
    
    const newRule = {
        precedence_value: getNextPrecedenceValue(),
        td_components: [{
            type: 'DNN',
            value: dnnDefaultValue
        }],
        rsd_list: [
            {
                precedence_value: 255,
                rsd_components: [{
                    type: 'DNN',
                    value: dnnDefaultValue
                }],
                isFixed: true  // Only fixed RSD with PV=255
            }
        ],
        isMatchAll: false,
        isFixed: false
    };
    
    // Insert before the last rule (Match-all rule)
    urspRules.splice(urspRules.length - 1, 0, newRule);
    renderURSPCards();
    console.log('Added new URSP rule above Match-all with only fixed RSD (PV=255):', newRule);
}

// Remove URSP Rule (cannot remove Match-all rule)
function removeURSPRule(ruleIndex) {
    const rule = urspRules[ruleIndex];
    
    // Cannot delete Match-all rule or if it's the only rule
    if (rule && rule.isFixed) {
        console.log('Cannot delete fixed Match-all rule');
        return;
    }
    
    if (urspRules.length > 1) {
        urspRules.splice(ruleIndex, 1);
        renderURSPCards();
        console.log('Removed URSP rule at index:', ruleIndex);
    } else {
        console.log('Cannot remove the last URSP rule');
    }
}

// TD Component functions
function addTDComponent(ruleIndex) {
    const rule = urspRules[ruleIndex];
    if (!rule) return;
    
    // Match-all 규칙에는 TD 컴포넌트를 추가할 수 없음
    if (rule.isMatchAll) {
        console.log('Cannot add TD component to Match-all rule');
        return;
    }
    
    // Get existing types in this rule
    const existingTypes = rule.td_components.map(c => c.type);
    
    // Find first unused type from priority list
    let newType = null;
    for (const type of TD_TYPE_PRIORITY) {
        if (!existingTypes.includes(type)) {
            newType = type;
            break;
        }
    }
    
    // If all priority types are used, use the first one
    if (!newType) {
        newType = TD_TYPE_PRIORITY[0];
    }
    
    // Get default value from tdTypes (loaded from spec.py)
    const typeInfo = tdTypes[newType];
    let defaultValue = '';
    
    if (typeInfo) {
        if (typeInfo.hasValue) {
            const placeholder = typeInfo.placeholder;
            
            // IP 3-tuple은 특별한 객체 구조이므로 별도 처리
            if (newType === 'IP 3 tuple') {
                defaultValue = placeholder; // 객체 그대로 전달
            }
            // Check placeholder type and handle accordingly
            else if (typeof placeholder === 'object' && placeholder !== null) {
                // Object placeholder: check structure and format accordingly
                if ('low' in placeholder && 'high' in placeholder) {
                    // Range type (port range, MAC range)
                    defaultValue = `${placeholder.low}-${placeholder.high}`;
                } else if ('address' in placeholder && 'mask' in placeholder) {
                    // IPv4 address type
                    defaultValue = `${placeholder.address}/${placeholder.mask}`;
                } else if ('address' in placeholder && 'prefix' in placeholder) {
                    // IPv6 address type
                    defaultValue = `${placeholder.address}/${placeholder.prefix}`;
                } else {
                    // Unknown object structure, use placeholder as-is
                    defaultValue = JSON.stringify(placeholder);
                }
            } else if (typeInfo.isMultiSelect) {
                // Multi-select types: use placeholder as-is (comma-separated values)
                defaultValue = placeholder || '';
            } else if (typeInfo.options && typeInfo.options.length > 0) {
                // Dropdown with options: use placeholder if it exists in options, otherwise use first option
                if (placeholder && typeInfo.options.includes(placeholder)) {
                    defaultValue = placeholder;
                } else {
                    defaultValue = typeInfo.options[0];
                }
            } else {
                // Simple string placeholder
                defaultValue = placeholder || '';
            }
        } else {
            defaultValue = '-';
        }
    }
    
    rule.td_components.push({
        type: newType,
        value: defaultValue
    });
    
    renderURSPCards();
    validateTDComponents(ruleIndex);
    
    console.log(`Added TD component: ${newType} = ${defaultValue} (auto-selected from priority list)`);
}

function removeTDComponent(ruleIndex, componentIndex) {
    const rule = urspRules[ruleIndex];
    if (!rule || rule.td_components.length <= 1) return;
    
    // Clear validation for this TD component
    const tdValidationId = `td-validation-${ruleIndex}`;
    validationErrors.delete(tdValidationId);
    
    rule.td_components.splice(componentIndex, 1);
    renderURSPCards();
    validateTDComponents(ruleIndex);
}

function updateTDComponent(ruleIndex, componentIndex, field, value) {
    const rule = urspRules[ruleIndex];
    if (!rule || !rule.td_components[componentIndex]) return;
    
    rule.td_components[componentIndex][field] = value;
    
    if (field === 'type') {
        const typeInfo = tdTypes[value];
        
        // IP 3 tuple 타입의 경우 객체 구조 그대로 사용
        if (value === 'IP 3 tuple') {
            rule.td_components[componentIndex].value = typeInfo && typeInfo.placeholder ? typeInfo.placeholder : {
                ipType: 'IPv4',
                portType: 'Single',
                address: '',
                mask: '',
                protocol: '',
                port: ''
            };
        }
        // OS Id + OS App Id 타입의 경우 특별한 기본값 설정
        else if (value === 'OS Id + OS App Id') {
            // spec.py의 placeholder에서 기본값 가져오기
            const defaultValue = typeInfo && typeInfo.placeholder ? typeInfo.placeholder : 'Android:ENTERPRISE';
            rule.td_components[componentIndex].value = defaultValue;
        }
        // Remote port range 타입의 경우 기본값 설정
        else if (value === 'Remote port range') {
            const placeholders = typeInfo && typeInfo.placeholder ? typeInfo.placeholder : {low: "8000", high: "8080"};
            rule.td_components[componentIndex].value = `${placeholders.low}-${placeholders.high}`;
        }
        // Destination MAC address range 타입의 경우 기본값 설정
        else if (value === 'Destination MAC address range') {
            const placeholders = typeInfo && typeInfo.placeholder ? typeInfo.placeholder : {low: "AA:BB:CC:DD:EE:00", high: "AA:BB:CC:DD:EE:FF"};
            rule.td_components[componentIndex].value = `${placeholders.low}-${placeholders.high}`;
        }
        // IPv4 remote address 타입의 경우 기본값 설정
        else if (value === 'IPv4 remote address') {
            const placeholders = typeInfo && typeInfo.placeholder ? typeInfo.placeholder : {address: "192.168.1.1", mask: "255.255.255.0"};
            rule.td_components[componentIndex].value = `${placeholders.address}/${placeholders.mask}`;
        }
        // IPv6 remote address/prefix length 타입의 경우 기본값 설정
        else if (value === 'IPv6 remote address/prefix length') {
            const placeholders = typeInfo && typeInfo.placeholder ? typeInfo.placeholder : {address: "2001:db8::1", prefix: "64"};
            rule.td_components[componentIndex].value = `${placeholders.address}/${placeholders.prefix}`;
        }
        else {
            rule.td_components[componentIndex].value = typeInfo ? typeInfo.placeholder : '';
        }
        
        renderURSPCards();
    }
    
    validateTDComponents(ruleIndex);
}

// RSD functions
function addRSDComponent(ruleIndex) {
    const rule = urspRules[ruleIndex];
    if (!rule) return;
    
    // S-NSSAI 기본값을 rsdTypes에서 가져오기
    const snssaiDefaultValue = rsdTypes['S-NSSAI'] ? rsdTypes['S-NSSAI'].placeholder : 'SST 1';
    
    const newRSD = {
        precedence_value: getNextRSDPrecedenceValue(rule.rsd_list),
        rsd_components: [{
            type: 'S-NSSAI',
            value: snssaiDefaultValue
        }],
        isFixed: false  // New RSD is not fixed
    };
    
    // Insert before fixed RSD (PV=255) if it exists
    const fixedRsdIndex = rule.rsd_list.findIndex(rsd => rsd.isFixed);
    if (fixedRsdIndex !== -1) {
        rule.rsd_list.splice(fixedRsdIndex, 0, newRSD);
    } else {
        rule.rsd_list.push(newRSD);
    }
    
    renderURSPCards();
    console.log('Added new RSD before fixed RSD (PV=255)');
}

function removeRSDComponent(ruleIndex, rsdIndex) {
    const rule = urspRules[ruleIndex];
    if (!rule || rule.rsd_list.length <= 1) return;
    
    const rsd = rule.rsd_list[rsdIndex];
    
    // Cannot delete fixed RSD (PV=255)
    if (rsd && rsd.isFixed) {
        console.log('Cannot delete fixed RSD (PV=255)');
        return;
    }
    
    // Clear validation for this RSD component
    const rsdValidationId = `rsd-validation-${ruleIndex}-${rsdIndex}`;
    validationErrors.delete(rsdValidationId);
    
    rule.rsd_list.splice(rsdIndex, 1);
    renderURSPCards();
    
    // Update encoding button state after removal
    updateEncodingButtonState();
}

function addRSDSubComponent(ruleIndex, rsdIndex) {
    const rule = urspRules[ruleIndex];
    if (!rule || !rule.rsd_list[rsdIndex]) return;
    
    // Get existing types in this RSD
    const existingTypes = rule.rsd_list[rsdIndex].rsd_components.map(c => c.type);
    
    // Find first unused type from priority list
    let newType = null;
    for (const type of RSD_TYPE_PRIORITY) {
        if (!existingTypes.includes(type)) {
            newType = type;
            break;
        }
    }
    
    // If all priority types are used, use the first one
    if (!newType) {
        newType = RSD_TYPE_PRIORITY[0];
    }
    
    // Get default value from rsdTypes (loaded from spec.py)
    const typeInfo = rsdTypes[newType];
    let defaultValue = '';
    
    if (typeInfo) {
        if (typeInfo.hasValue) {
            // Use first option if available, otherwise use placeholder
            if (typeInfo.options && typeInfo.options.length > 0) {
                defaultValue = typeInfo.options[0];
            } else {
                defaultValue = typeInfo.placeholder || '';
            }
        } else {
            defaultValue = 'No value required';
        }
    }
    
    rule.rsd_list[rsdIndex].rsd_components.push({
        type: newType,
        value: defaultValue
    });
    
    renderURSPCards();
    validateRSDComponents(ruleIndex, rsdIndex);
    
    console.log(`Added RSD content: ${newType} = ${defaultValue} (auto-selected from priority list)`);
}

function removeRSDSubComponent(ruleIndex, rsdIndex, componentIndex) {
    const rule = urspRules[ruleIndex];
    if (!rule || !rule.rsd_list[rsdIndex] || rule.rsd_list[rsdIndex].rsd_components.length <= 1) return;
    
    rule.rsd_list[rsdIndex].rsd_components.splice(componentIndex, 1);
    renderURSPCards();
    validateRSDComponents(ruleIndex, rsdIndex);
}

function updateRSDComponent(ruleIndex, rsdIndex, componentIndex, field, value) {
    const rule = urspRules[ruleIndex];
    if (!rule || !rule.rsd_list[rsdIndex]) return;
    
    const rsd = rule.rsd_list[rsdIndex];
    
    // Cannot modify fixed RSD precedence value
    if (field === 'precedence_value' && rsd.isFixed) {
        console.log('Cannot modify fixed RSD precedence value (PV=255)');
        return;
    }
    
    if (!rule.rsd_list[rsdIndex].rsd_components[componentIndex]) return;
    
    if (field === 'precedence_value') {
        rule.rsd_list[rsdIndex].precedence_value = parseInt(value) || 1;
    } else {
        rule.rsd_list[rsdIndex].rsd_components[componentIndex][field] = value;
        
        if (field === 'type') {
            const typeInfo = rsdTypes[value];
            rule.rsd_list[rsdIndex].rsd_components[componentIndex].value = typeInfo && typeInfo.hasValue ? typeInfo.placeholder : 'No value required';
            renderURSPCards();
        }
    }
    
    validateRSDComponents(ruleIndex, rsdIndex);
}

function updateURSPPrecedence(ruleIndex, value) {
    const rule = urspRules[ruleIndex];
    if (!rule) return;
    
    rule.precedence_value = parseInt(value) || 1;
    console.log('Updated URSP precedence:', rule);
}

// Validation functions
async function validateTDComponents(ruleIndex) {
    const rule = urspRules[ruleIndex];
    if (!rule) return;
    
    try {
        const response = await fetch('/validate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                type: 'td',
                components: rule.td_components
            })
        });
        
        const result = await response.json();
        displayValidationMessage(`td-validation-${ruleIndex}`, result);
    } catch (error) {
        console.error('TD validation error:', error);
    }
}

async function validateRSDComponents(ruleIndex, rsdIndex) {
    const rule = urspRules[ruleIndex];
    if (!rule || !rule.rsd_list[rsdIndex]) return;
    
    const rsd = rule.rsd_list[rsdIndex];
    const components = rsd.rsd_components;
    
    // 서버 검증 호출 (모든 제약사항 체크)
    try {
        const response = await fetch('/validate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                type: 'rsd',
                components: components
            })
        });
        
        const result = await response.json();
        displayValidationMessage(`rsd-validation-${ruleIndex}-${rsdIndex}`, result);
    } catch (error) {
        console.error('RSD validation error:', error);
    }
}

// Global validation state tracking
let validationErrors = new Set();

function displayValidationMessage(elementId, result) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    element.innerHTML = '';
    
    // Update validation error tracking - 에러와 경고 모두 인코딩 차단
    if (!result.valid || (result.warnings && result.warnings.length > 0)) {
        validationErrors.add(elementId);
    } else {
        validationErrors.delete(elementId);
    }
    
    // Update encoding button state
    updateEncodingButtonState();
    
    // Display errors (red background)
    if (!result.valid && result.errors) {
        const errors = result.errors || [result.error];  // 하위 호환성 유지
        errors.forEach(error => {
            if (error) {  // 빈 문자열 체크
                const errorDiv = document.createElement('div');
                errorDiv.className = 'validation-message error';
                errorDiv.innerHTML = error;  // 아이콘이 spec.py에서 포함됨
                element.appendChild(errorDiv);
            }
        });
    }
    
    // Display warnings (yellow background) - 에러 유무와 관계없이 표시
    if (result.warnings && result.warnings.length > 0) {
        result.warnings.forEach(warning => {
            const warningDiv = document.createElement('div');
            warningDiv.className = 'validation-message warning';
            warningDiv.innerHTML = warning;  // 아이콘이 spec.py에서 포함됨
            element.appendChild(warningDiv);
        });
    }
    
    // Display info messages (blue background with i icon)
    if (result.info && result.info.length > 0) {
        result.info.forEach(info => {
            const infoDiv = document.createElement('div');
            infoDiv.className = 'validation-message info';
            infoDiv.innerHTML = `<span class="validation-icon">i</span> ${info}`;
            element.appendChild(infoDiv);
        });
    }
}

function updateEncodingButtonState() {
    const encodeButton = document.getElementById('encode-btn');
    if (!encodeButton) return;
    
    if (validationErrors.size > 0) {
        encodeButton.disabled = true;
        encodeButton.style.opacity = '0.5';
        encodeButton.style.cursor = 'not-allowed';
    } else {
        encodeButton.disabled = false;
        encodeButton.style.opacity = '1';
        encodeButton.style.cursor = 'pointer';
    }
}

// Create URSP card HTML with card wrapper and color coding
function createURSPCard(ruleIndex) {
    const rule = urspRules[ruleIndex];
    
    // 색상 클래스 결정 - 고정 색상
    let colorClass = '';
    if (rule.isMatchAll) {
        colorClass = 'ursp-card-gray'; // Match-all은 회색
    } else {
        colorClass = 'ursp-card-blue'; // 일반 규칙들은 모두 파란색으로 고정
    }
    
    return `
        <div class="individual-ursp-card ${colorClass}" data-rule-index="${ruleIndex}">
            <div class="individual-ursp-card-header">
                <span>URSP Rule ${ruleIndex}${rule.isMatchAll ? ' (Match-all)' : ''}</span>
                ${!rule.isFixed ? 
                    `<button type="button" class="remove-ursp-btn" onclick="removeURSPRule(${ruleIndex})">
                        ✕
                    </button>` : ''
                }
            </div>
            
            <div class="ursp-content">
                <!-- Basic Info Column (2fr) -->
                <div class="ursp-basic-info">
                    <h4>🏷️ URSP Rule Info</h4>
                    <div class="basic-info-fields">
                        <div class="inline-field ${rule.isFixed ? 'dimmed' : ''}">
                            <span class="field-label ${rule.isFixed ? 'dimmed-label' : ''}">Precedence Value${rule.isFixed ? ' (Fixed)' : ''}&nbsp;&nbsp;:</span>
                            <input type="number" value="${rule.precedence_value}" min="1" max="255"
                                   ${rule.isFixed ? 'readonly class="dimmed"' : ''}
                                   onchange="updateURSPPrecedence(${ruleIndex}, this.value)">
                        </div>
                    </div>
                </div>
                
                <!-- TD Column (4fr) -->
                <div class="ursp-td-section">
                    <div class="section-header-with-button">
                        <h4>🎯 Traffic Descriptor</h4>
                        ${!rule.isMatchAll ? `
                        <button type="button" class="add-td-btn" onclick="addTDComponent(${ruleIndex})">
                            + Add TD Component
                        </button>` : ''}
                    </div>
                    <div class="td-components-container">
                        ${rule.isMatchAll ? createMatchAllTDHTML(ruleIndex) : createTDComponentsHTML(ruleIndex)}
                    </div>
                    <div id="td-validation-${ruleIndex}"></div>
                </div>
                
                <!-- RSD Column (4fr) -->
                <div class="ursp-rsd-section">
                    <div class="section-header-with-button">
                        <h4>🚀 Route Selection Descriptor</h4>
                        <button type="button" class="add-rsd-btn" onclick="addRSDComponent(${ruleIndex})">
                            + Add RSD Component
                        </button>
                    </div>
                    <div class="rsd-list-container">
                        ${createRSDListHTML(ruleIndex)}
                    </div>
                </div>
            </div>
        </div>
    `;
}

function createMatchAllTDHTML(ruleIndex) {
    return `
        <div class="td-component-card">
            <div class="td-component-header">
                <span class="td-component-title">TD 0 (Match-all)</span>
            </div>
            <div class="td-component-fields">
                <div class="inline-field dimmed">
                    <span class="field-label dimmed-label">Type&nbsp;&nbsp;:</span>
                    <select disabled class="dimmed">
                        <option selected>Match-all</option>
                    </select>
                </div>
                <div class="inline-field dimmed">
                    <span class="field-label dimmed-label">Value&nbsp;&nbsp;:</span>
                    <input type="text" value="" readonly class="dimmed" placeholder="No value required">
                </div>
            </div>
        </div>
    `;
}

function createTDComponentsHTML(ruleIndex) {
    const rule = urspRules[ruleIndex];
    if (!rule.td_components || rule.td_components.length === 0) {
        return '<div class="empty-components">No TD components (Match-all)</div>';
    }
    
    return rule.td_components.map((component, componentIndex) => {
        const typeInfo = tdTypes[component.type] || { hasValue: true, placeholder: "" };
        const isMultiSelect = typeInfo.isMultiSelect && typeInfo.options;
        const isRangeType = component.type === 'Remote port range' || 
                           component.type === 'Destination MAC address range' ||
                           component.type === 'IPv4 remote address' ||
                           component.type === 'IPv6 remote address/prefix length';
        
        return `
            <div class="td-component-card">
                <div class="td-component-header">
                    <span class="td-component-title">TD ${componentIndex}</span>
                    ${rule.td_components.length > 1 ? 
                        `<button type="button" class="remove-td-btn" onclick="removeTDComponent(${ruleIndex}, ${componentIndex})">
                            ✕
                        </button>` : ''
                    }
                </div>
                <div class="td-component-fields">
                    <div class="inline-field">
                        <span class="field-label">Type&nbsp;&nbsp;:</span>
                        <select onchange="updateTDComponent(${ruleIndex}, ${componentIndex}, 'type', this.value)">
                            ${Object.keys(tdTypes).filter(type => type !== 'Match-all').map(type => 
                                `<option value="${type}" ${component.type === type ? 'selected' : ''}>${type}</option>`
                            ).join('')}
                        </select>
                    </div>
                    ${component.type === 'OS Id + OS App Id' || component.type === 'IP 3 tuple' || isRangeType || isMultiSelect ? 
                        createTDValueInput(ruleIndex, componentIndex, component, typeInfo) :
                        `<div class="inline-field">
                            <span class="field-label">Value&nbsp;&nbsp;:</span>
                            ${createTDValueInput(ruleIndex, componentIndex, component, typeInfo)}
                        </div>`
                    }
                </div>
            </div>
        `;
    }).join('');
}

function createRSDListHTML(ruleIndex) {
    const rule = urspRules[ruleIndex];
    
    return rule.rsd_list.map((rsd, rsdIndex) => `
        <div class="rsd-card">
            <div class="rsd-card-header">
                <span class="rsd-card-title">RSD ${rsdIndex}${rsd.isFixed ? ' (Fixed PV)' : ''}</span>
                ${!rsd.isFixed && rule.rsd_list.length > 1 ? 
                    `<button type="button" class="remove-rsd-btn" onclick="removeRSDComponent(${ruleIndex}, ${rsdIndex})">
                        ✕
                    </button>` : ''
                }
            </div>
            <div class="rsd-basic-fields">
                <div class="inline-field compact ${rsd.isFixed ? 'dimmed' : ''}">
                    <span class="field-label ${rsd.isFixed ? 'dimmed-label' : ''}">Precedence Value${rsd.isFixed ? ' (Fixed)' : ''}&nbsp;&nbsp;:</span>
                    <input type="number" value="${rsd.precedence_value}" min="1" max="255"
                           ${rsd.isFixed ? 'readonly class="dimmed"' : ''}
                           onchange="updateRSDComponent(${ruleIndex}, ${rsdIndex}, -1, 'precedence_value', this.value)">
                </div>
                <button type="button" class="add-rsd-component-btn" onclick="addRSDSubComponent(${ruleIndex}, ${rsdIndex})">
                    + Add RSD Content
                </button>
            </div>
            <div class="rsd-components-container">
                ${createRSDComponentsHTML(ruleIndex, rsdIndex)}
            </div>
            <div id="rsd-validation-${ruleIndex}-${rsdIndex}"></div>
        </div>
    `).join('');
}

function createRSDComponentsHTML(ruleIndex, rsdIndex) {
    const rule = urspRules[ruleIndex];
    const rsd = rule.rsd_list[rsdIndex];
    
    return rsd.rsd_components.map((component, componentIndex) => {
        const typeInfo = rsdTypes[component.type] || { hasValue: true, placeholder: "" };
        const isNoValue = !typeInfo.hasValue;
        
        return `
            <div class="rsd-component-card">
                <div class="rsd-component-header">
                    <span class="rsd-component-title">RSD Content ${componentIndex}</span>
                    ${rsd.rsd_components.length > 1 ? 
                        `<button type="button" class="remove-rsd-component-btn" onclick="removeRSDSubComponent(${ruleIndex}, ${rsdIndex}, ${componentIndex})">
                            ✕
                        </button>` : ''
                    }
                </div>
                <div class="rsd-component-fields">
                    <div class="inline-field">
                        <span class="field-label">Type&nbsp;&nbsp;:</span>
                        <select onchange="updateRSDComponent(${ruleIndex}, ${rsdIndex}, ${componentIndex}, 'type', this.value)">
                            ${Object.keys(rsdTypes).map(type => 
                                `<option value="${type}" ${component.type === type ? 'selected' : ''}>${type}</option>`
                            ).join('')}
                        </select>
                    </div>
                    ${component.type === 'S-NSSAI' ? 
                        createRSDValueInput(ruleIndex, rsdIndex, componentIndex, component, typeInfo) :
                        `<div class="inline-field ${isNoValue ? 'dimmed' : ''}">
                            <span class="field-label ${isNoValue ? 'dimmed-label' : ''}">Value&nbsp;&nbsp;:</span>
                            ${createRSDValueInput(ruleIndex, rsdIndex, componentIndex, component, typeInfo)}
                        </div>`
                    }
                </div>
                ${component.type === 'S-NSSAI' ? 
                    `<div class="snssai-info-text">
                        <span class="info-icon">ⓘ</span> SST is required, SD is optional
                    </div>` : ''
                }
            </div>
        `;
    }).join('');
}

// Render all URSP cards
function renderURSPCards() {
    console.log('=== renderURSPCards START ===');
    
    const container = document.getElementById('ursp-container');
    if (!container) {
        console.error('URSP container not found');
        return;
    }
    
    try {
        let html = '';
        for (let i = 0; i < urspRules.length; i++) {
            console.log(`Rendering URSP card ${i}`);
            const cardHtml = createURSPCard(i);
            if (cardHtml) {
                html += cardHtml;
            } else {
                console.error(`Failed to create URSP card ${i}`);
            }
        }
        container.innerHTML = html;
        
        // Trigger validation for all rules
        for (let i = 0; i < urspRules.length; i++) {
            validateTDComponents(i);
            for (let j = 0; j < urspRules[i].rsd_list.length; j++) {
                validateRSDComponents(i, j);
            }
        }
        
        console.log('URSP cards rendered successfully');
    } catch (error) {
        console.error('Error in renderURSPCards:', error);
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', async function() {
    console.log('DOM ready in app.js');
    
    // Load all data from server first
    await loadConnectionCapabilities();
    await loadTDTypes();
    await loadRSDTypes();
    await loadSSTValues();
    await loadAndroidAppIds();
    
    // Initialize empty structure
    initializeEmptyStructure();
    
    // Render initial cards
    renderURSPCards();
    
    // Setup tab functionality
    setupTabs();
    
    // Setup header buttons
    setupHeaderButtons();
    
    // Setup encode button
    setupEncodeButton();
    
    // Initialize encoding button state
    updateEncodingButtonState();
    
    // Setup decode button
    setupDecodeButton();
});

// Header buttons functionality
function setupHeaderButtons() {
    // Info header button
    const infoHeaderBtn = document.querySelector('.info-header-btn');
    if (infoHeaderBtn) {
        infoHeaderBtn.addEventListener('click', function() {
            // Switch to info tab
            const tabButtons = document.querySelectorAll('.tab-btn');
            const tabContents = document.querySelectorAll('.tab-content');
            const tabActions = document.querySelectorAll('.tab-action-item');
            
            // Remove active class from all tabs and contents
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));
            tabActions.forEach(action => action.classList.remove('active'));
            
            // Show info tab
            document.getElementById('info-tab').classList.add('active');
        });
    }
}

// Tab functionality
function setupTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    const tabActions = document.querySelectorAll('.tab-action-item');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', function() {
            const targetTab = this.getAttribute('data-tab');
            
            // Remove active class from all tabs and contents
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));
            tabActions.forEach(action => action.classList.remove('active'));
            
            // Add active class to clicked tab and corresponding content
            this.classList.add('active');
            document.getElementById(targetTab + '-tab').classList.add('active');
            
            // Show corresponding action button
            if (targetTab === 'encoder') {
                document.getElementById('encoding-action').classList.add('active');
            } else if (targetTab === 'decoder') {
                document.getElementById('decoding-action').classList.add('active');
            }
        });
    });
}

// Encode button functionality
function setupEncodeButton() {
    const encodeBtn = document.getElementById('encode-btn');
    const encodeStatus = document.getElementById('encode-status');
    
    if (encodeBtn) {
        let isEncoding = false;
        
        encodeBtn.addEventListener('click', async function() {
            if (isEncoding) return;
            
            isEncoding = true;
            encodeBtn.disabled = true;
            
            encodeStatus.textContent = 'Encoding...';
            encodeStatus.className = 'status-message';
            
            try {
                const data = {
                    pti: document.getElementById('pti').value,
                    plmn: document.getElementById('plmn').value,
                    upsc: document.getElementById('upsc').value,
                    ursp_rules: urspRules
                };
                
                console.log('Sending data to encoder v2:', data);
                
                const response = await fetch('/encode', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(data)
                });
                
                const result = await response.json();
                
                if (result.success) {
                    // 성공 메시지 제거 - 성공 시에는 아무 메시지도 표시하지 않음
                    encodeStatus.textContent = '';
                    encodeStatus.className = '';
                    
                    displayResults(result);
                    document.querySelector('[data-tab="result"]').click();
                } else {
                    encodeStatus.textContent = 'Error: ' + result.error;
                    encodeStatus.className = 'status-message error';
                }
            } catch (error) {
                encodeStatus.textContent = 'Error: ' + error.message;
                encodeStatus.className = 'status-message error';
            } finally {
                isEncoding = false;
                setTimeout(() => {
                    encodeBtn.disabled = false;
                }, 1000);
            }
        });
    }
}

// Decode button functionality
function setupDecodeButton() {
    const decodeBtn = document.getElementById('decode-btn');
    const decodeStatus = document.getElementById('decode-status');
    
    if (decodeBtn) {
        decodeBtn.addEventListener('click', async function() {
            const logText = document.getElementById('log-text').value;
            
            if (!logText.trim()) {
                decodeStatus.textContent = 'Please enter hex log data';
                decodeStatus.className = 'status-message error';
                return;
            }
            
            decodeStatus.textContent = 'Decoding...';
            decodeStatus.className = 'status-message';
            
            try {
                const response = await fetch('/decode', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ log_text: logText })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    // 성공 메시지 제거 - 성공 시에는 아무 메시지도 표시하지 않음
                    decodeStatus.textContent = '';
                    decodeStatus.className = '';
                    
                    displayResults(result);
                    document.querySelector('[data-tab="result"]').click();
                } else {
                    decodeStatus.textContent = 'Error: ' + result.error;
                    decodeStatus.className = 'status-message error';
                }
            } catch (error) {
                decodeStatus.textContent = 'Network error: ' + error.message;
                decodeStatus.className = 'status-message error';
            }
        });
    }
}

// Display results in Result tab
function displayResults(result) {
    const resultSections = document.getElementById('result-sections');
    
    if (!resultSections) {
        console.error('result-sections element not found');
        return;
    }
    
    let output = '';
    
    // Check if this is a decoder result
    const isDecoderResult = result.message_type === 'DL NAS Transport';
    
    // Create 2x2 grid structure
    output += '<div class="result-sections-grid">';
    
    // First row: SIM EF_URSP and DL NAS TRANSPORT (only for encoder results)
    if (result.ef_ursp && !isDecoderResult) {
        output += '<div class="result-section-card">';
        output += '<div class="result-section-header ef-ursp">';
        output += '<span>SIM EF_URSP</span>';
        output += '<button class="copy-btn" onclick="copyResultText(this, \'' + escapeForJS(formatHexDisplay(result.ef_ursp)) + '\')">📋 Copy</button>';
        output += '</div>';
        output += '<div class="result-section-content">';
        output += '<pre class="hex-display">' + formatHexDisplay(result.ef_ursp) + '</pre>';
        output += '</div></div>';
    }
    
    if (result.dl_nas && !isDecoderResult) {
        output += '<div class="result-section-card">';
        output += '<div class="result-section-header dl-nas">';
        output += '<span>DL NAS TRANSPORT</span>';
        output += '<button class="copy-btn" onclick="copyResultText(this, \'' + escapeForJS(formatHexDisplay(result.dl_nas)) + '\')">📋 Copy</button>';
        output += '</div>';
        output += '<div class="result-section-content">';
        output += '<pre class="hex-display">' + formatHexDisplay(result.dl_nas) + '</pre>';
        output += '</div></div>';
    }
    
    // Second row: URSP RULE and MANAGE UE POLICY COMMAND
    if (result.ursp_conts) {  // Check ursp_conts instead of ursp_info
        output += '<div class="result-section-card">';
        output += '<div class="result-section-header ursp-rule">';
        output += '<span>URSP RULE</span>';
        output += '<button class="copy-btn" onclick="copyResultText(this, \'' + escapeForJS(result.ursp_conts) + '\')">📋 Copy</button>';
        output += '</div>';
        output += '<div class="result-section-content">';
        output += '<pre class="text-display">' + escapeHtml(result.ursp_conts) + '</pre>';  // Only show ursp_conts
        output += '</div></div>';
    }
    
    if (result.pol_cmd_txt) {
        output += '<div class="result-section-card">';
        output += '<div class="result-section-header policy-command">';
        output += '<span>MANAGE UE POLICY COMMAND</span>';
        output += '<button class="copy-btn" onclick="copyResultText(this, \'' + escapeForJS(result.pol_cmd_txt) + '\')">📋 Copy</button>';
        output += '</div>';
        output += '<div class="result-section-content">';
        output += '<pre class="text-display">' + escapeHtml(result.pol_cmd_txt) + '</pre>';
        output += '</div></div>';
    }
    
    output += '</div>'; // Close result-sections-grid
    
    resultSections.innerHTML = output;
}

// Helper function to escape text for JavaScript string
function escapeForJS(text) {
    return text.replace(/'/g, "\\'").replace(/\n/g, '\\n').replace(/\r/g, '\\r');
}

// Helper function to escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Function to copy result text
function copyResultText(button, text) {
    navigator.clipboard.writeText(text).then(function() {
        const originalText = button.textContent;
        button.textContent = '✅ Copied!';
        button.style.background = '#10b981';
        
        setTimeout(() => {
            button.textContent = originalText;
            button.style.background = '';
        }, 2000);
    }).catch(function(err) {
        console.error('Failed to copy: ', err);
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        
        const originalText = button.textContent;
        button.textContent = '✅ Copied!';
        button.style.background = '#10b981';
        
        setTimeout(() => {
            button.textContent = originalText;
            button.style.background = '';
        }, 2000);
    });
}

// TD Value Input Creation
function createTDValueInput(ruleIndex, componentIndex, component, typeInfo) {
    if (!typeInfo.hasValue) {
        return `<input type="text" value="-" disabled>`;
    }
    
    // OS Id + OS App Id 특수 처리
    if (component.type === "OS Id + OS App Id") {
        return createOSIdAppIdInput(ruleIndex, componentIndex, component);
    }
    
    // IP 3 tuple 특수 처리
    if (component.type === "IP 3 tuple") {
        return createIP3TupleInput(ruleIndex, componentIndex, component);
    }
    
    // IPv4 remote address 특수 처리
    if (component.type === "IPv4 remote address") {
        return createIPv4AddressInput(ruleIndex, componentIndex, component);
    }
    
    // IPv6 remote address/prefix length 특수 처리
    if (component.type === "IPv6 remote address/prefix length") {
        return createIPv6AddressInput(ruleIndex, componentIndex, component);
    }
    
    // Remote port range 특수 처리
    if (component.type === "Remote port range") {
        return createPortRangeInlineInput(ruleIndex, componentIndex, component);
    }
    
    // Destination MAC address range 특수 처리
    if (component.type === "Destination MAC address range") {
        return createMACRangeInlineInput(ruleIndex, componentIndex, component);
    }
    
    if (typeInfo.isMultiSelect && component.type === "Connection capabilities") {
        // Connection capabilities의 경우 서버에서 로드된 options 사용
        const options = connectionCapabilities.length > 0 ? connectionCapabilities : (typeInfo.options || []);
        const selectedValues = component.value ? component.value.split(', ') : [];
        const displayText = selectedValues.length > 0 ? selectedValues.join(', ') : 'Select items...';
        
        return `
            <div class="inline-field">
                <span class="field-label">Selected&nbsp;&nbsp;:</span>
                <div class="connection-capabilities-dropdown">
                    <button type="button" class="cc-dropdown-toggle" 
                            onclick="toggleConnectionCapabilities(${ruleIndex}, ${componentIndex})">
                        <span class="cc-selected-text">${displayText}</span>
                        <span class="cc-dropdown-arrow">▼</span>
                    </button>
                    <div class="cc-dropdown-menu" id="cc-dropdown-${ruleIndex}-${componentIndex}" style="display: none;">
                        ${options.map(option => `
                            <label class="cc-dropdown-option">
                                <input type="checkbox" value="${option}" 
                                       ${selectedValues.includes(option) ? 'checked' : ''}
                                       onchange="updateTDMultiSelect(${ruleIndex}, ${componentIndex})">
                                <span>${option}</span>
                            </label>
                        `).join('')}
                    </div>
                    <input type="hidden" value="${component.value}" 
                           id="td-multiselect-${ruleIndex}-${componentIndex}">
                </div>
            </div>
        `;
    }
    
    // options가 있으면 드롭다운으로 표시 (Protocol identifier 등)
    if (typeInfo.options && typeInfo.options.length > 0) {
        return `
            <select onchange="updateTDComponent(${ruleIndex}, ${componentIndex}, 'value', this.value)">
                ${typeInfo.options.map(option => 
                    `<option value="${option}" ${component.value === option ? 'selected' : ''}>${option}</option>`
                ).join('')}
            </select>
        `;
    }
    
    // Regular text input
    return `
        <input type="text" value="${component.value}" 
               placeholder="${typeInfo.placeholder}"
               onchange="updateTDComponent(${ruleIndex}, ${componentIndex}, 'value', this.value)">
    `;
}

// RSD Value Input Creation
function createRSDValueInput(ruleIndex, rsdIndex, componentIndex, component, typeInfo) {
    // S-NSSAI 특수 처리
    if (component.type === 'S-NSSAI') {
        return createSNSSAIInlineInput(ruleIndex, rsdIndex, componentIndex, component);
    }
    
    if (!typeInfo.hasValue) {
        return `<input type="text" value="No value required" disabled class="dimmed">`;
    }
    
    // options가 있으면 드롭다운으로 표시
    if (typeInfo.options && typeInfo.options.length > 0) {
        return `
            <select onchange="updateRSDComponent(${ruleIndex}, ${rsdIndex}, ${componentIndex}, 'value', this.value)">
                ${typeInfo.options.map(option => 
                    `<option value="${option}" ${component.value === option ? 'selected' : ''}>${option}</option>`
                ).join('')}
            </select>
        `;
    } else {
        // Regular text input
        return `
            <input type="text" value="${component.value}" 
                   placeholder="${typeInfo.placeholder}"
                   onchange="updateRSDComponent(${ruleIndex}, ${rsdIndex}, ${componentIndex}, 'value', this.value)">
        `;
    }
}

// OS Id + OS App Id 입력 UI (Type 행에 OS 선택 추가, 아래에 OS Id/OS App Id 세로 배치)
function createOSIdAppIdInput(ruleIndex, componentIndex, component) {
    // 값 파싱: "Android:ENTERPRISE" 또는 "UUID:AppIdString"
    let currentOsType = 'Android';
    let currentOsId = '';
    // Android App ID 기본값: androidAppIds의 첫 번째 키 사용
    const defaultAppIdKey = Object.keys(androidAppIds)[0] || 'ENTERPRISE';
    let currentAppId = defaultAppIdKey;
    
    if (component.value) {
        const parts = component.value.split(':');
        if (parts.length >= 2) {
            // Android로 시작하면 Android
            if (parts[0] === 'Android') {
                currentOsType = 'Android';
                currentAppId = parts[1];
            } else {
                // 그 외는 Custom (UUID:AppId 형식)
                currentOsType = 'Custom';
                currentOsId = parts[0];
                currentAppId = parts[1];
            }
        }
    }
    
    // 정보 문구 결정
    const infoMessage = currentOsType === 'Android' 
        ? 'Android uses predefined OS Id and OS App Id categories for network slicing.'
        : 'Custom requires manual UUID format for OS Id and string for OS App Id.';
    
    // Android App ID 옵션 생성 (spec.py에서 받은 순서 사용)
    const androidAppIdOptions = androidAppIdOrder
        .filter(key => androidAppIds[key])  // 존재하는 키만 필터링
        .map(key => 
            `<option value="${key}" ${currentAppId === key ? 'selected' : ''}>${androidAppIds[key].string}</option>`
        ).join('');
    
    return `
        <!-- OS + OS Id + OS App Id를 하나의 테두리로 묶음 -->
        <div class="os-id-app-id-wrapper">
            <!-- OS 선택 필드 -->
            <div class="inline-field">
                <span class="field-label">OS&nbsp;&nbsp;:</span>
                <select id="os-type-${ruleIndex}-${componentIndex}" 
                        onchange="updateOSIdAppId(${ruleIndex}, ${componentIndex})">
                    <option value="Android" ${currentOsType === 'Android' ? 'selected' : ''}>Android</option>
                    <option value="Custom" ${currentOsType === 'Custom' ? 'selected' : ''}>Custom</option>
                </select>
            </div>
            
            <!-- OS Id 필드 -->
            <div class="inline-field ${currentOsType === 'Android' ? 'dimmed' : ''}">
                <span class="field-label ${currentOsType === 'Android' ? 'dimmed-label' : ''}">OS Id&nbsp;&nbsp;:</span>
                ${currentOsType === 'Android' ? 
                    `<input type="text" 
                            value="${androidOsId || '97A498E3FC925C9489860333D06E4E47'}" 
                            readonly 
                            class="dimmed">` :
                    `<input type="text" 
                            id="os-id-input-${ruleIndex}-${componentIndex}"
                            value="${currentOsId}"
                            placeholder="12345678-1234-5678-1234-567812345678"
                            onchange="updateOSIdAppId(${ruleIndex}, ${componentIndex})">`
                }
            </div>
            
            <!-- OS App Id 필드 -->
            <div class="inline-field">
                <span class="field-label">OS App Id&nbsp;&nbsp;:</span>
                ${currentOsType === 'Android' ?
                    `<select id="os-app-id-select-${ruleIndex}-${componentIndex}" 
                             onchange="updateOSIdAppId(${ruleIndex}, ${componentIndex})">
                        ${androidAppIdOptions}
                    </select>` :
                    `<input type="text" 
                            id="os-app-id-input-${ruleIndex}-${componentIndex}"
                            value="${currentAppId}"
                            placeholder="com.example.app"
                            onchange="updateOSIdAppId(${ruleIndex}, ${componentIndex})">`
                }
            </div>
        </div>
        
        <!-- 정보 문구 (wrapper 아래에 표시) -->
        <div class="snssai-info-text os-app-id-info">
            <span class="info-icon">ⓘ</span> ${infoMessage}
        </div>
    `;
}

// OS Id + OS App Id 값 업데이트 함수
function updateOSIdAppId(ruleIndex, componentIndex) {
    const osType = document.getElementById(`os-type-${ruleIndex}-${componentIndex}`).value;
    
    // 현재 값 가져오기
    const rule = urspRules[ruleIndex];
    const component = rule.td_components[componentIndex];
    const currentValue = component.value || '';
    
    // OS 타입이 변경되었는지 확인
    const currentOsType = currentValue.startsWith('Android:') ? 'Android' : 'Custom';
    const osTypeChanged = currentOsType !== osType;
    
    let newValue = '';
    
    if (osType === 'Android') {
        // Android: "Android:APPID"
        const appIdSelect = document.getElementById(`os-app-id-select-${ruleIndex}-${componentIndex}`);
        
        // spec.py의 placeholder에서 기본값 가져오기
        const typeInfo = tdTypes['OS Id + OS App Id'];
        const defaultValue = typeInfo && typeInfo.placeholder ? typeInfo.placeholder : 'Android:ENTERPRISE';
        const defaultAppIdKey = defaultValue.split(':')[1] || 'ENTERPRISE';
        
        const appIdKey = appIdSelect ? appIdSelect.value : defaultAppIdKey;
        newValue = `Android:${appIdKey}`;
    } else {
        // Custom: "UUID:AppIdString" (Custom: 접두사 없음)
        const osIdInput = document.getElementById(`os-id-input-${ruleIndex}-${componentIndex}`);
        const appIdInput = document.getElementById(`os-app-id-input-${ruleIndex}-${componentIndex}`);
        const osId = osIdInput ? osIdInput.value : '';
        const appId = appIdInput ? appIdInput.value : '';
        newValue = `${osId}:${appId}`;
    }
    
    // 값 업데이트
    component.value = newValue;
    
    // OS 타입이 변경된 경우에만 전체 카드 다시 렌더링
    if (osTypeChanged) {
        renderURSPCards();
    }
    
    console.log('OS Id + OS App Id updated:', newValue);
}

// S-NSSAI 한 줄 배치 입력 UI (SST와 SD를 하나의 컨테이너로 묶어서 가로 배치)
function createSNSSAIInlineInput(ruleIndex, rsdIndex, componentIndex, component) {
    // 값 파싱
    let currentSST = '1';
    let currentSD = '';
    
    if (component.value) {
        const match = component.value.match(/SST (\d+)(?: \+ SD (\d+))?/);
        if (match) {
            currentSST = match[1];
            currentSD = match[2] || '';  // SD가 없으면 빈 문자열
        }
    }
    
    return `
        <div class="inline-field">
            <div class="snssai-split-container">
                <div class="snssai-sst-part">
                    <span class="field-label">SST&nbsp;&nbsp;:</span>
                    <select class="snssai-sst-select-inline" 
                            id="sst-${ruleIndex}-${rsdIndex}-${componentIndex}"
                            onchange="updateSNSSAIValue(${ruleIndex}, ${rsdIndex}, ${componentIndex})">
                        ${Object.entries(sstStandardValues).map(([sst, desc]) => 
                            `<option value="${sst}" ${currentSST == sst ? 'selected' : ''}>
                                ${sst} (${desc})
                            </option>`
                        ).join('')}
                    </select>
                </div>
                <div class="snssai-sd-part">
                    <span class="field-label">SD&nbsp;&nbsp;:</span>
                    <input type="number" 
                           class="snssai-sd-input-inline"
                           id="sd-${ruleIndex}-${rsdIndex}-${componentIndex}"
                           min="0" 
                           max="16777215"
                           ${currentSD ? `value="${currentSD}"` : ''}
                           placeholder="0-16777215"
                           onchange="updateSNSSAIValue(${ruleIndex}, ${rsdIndex}, ${componentIndex})">
                </div>
            </div>
        </div>
    `;
}

// Remote port range 입력 UI (Low limit과 High limit을 분리)
function createPortRangeInlineInput(ruleIndex, componentIndex, component) {
    // 값 파싱: "8000-8080" 형태
    let lowLimit = '';
    let highLimit = '';
    
    if (component.value) {
        const parts = component.value.split('-');
        if (parts.length === 2) {
            lowLimit = parts[0].trim();
            highLimit = parts[1].trim();
        }
    }
    
    // typeInfo에서 placeholder 가져오기
    const typeInfo = tdTypes[component.type] || {};
    const placeholders = typeInfo.placeholder || {low: "8000", high: "8080"};
    
    return `
        <div class="inline-field">
            <div class="snssai-split-container">
                <div class="snssai-sst-part">
                    <span class="field-label">Low limit&nbsp;&nbsp;:</span>
                    <input type="number" 
                           id="port-low-${ruleIndex}-${componentIndex}"
                           min="0" 
                           max="65535"
                           value="${lowLimit}"
                           placeholder="${placeholders.low}"
                           onchange="updatePortRangeValue(${ruleIndex}, ${componentIndex})">
                </div>
                <div class="snssai-sd-part">
                    <span class="field-label">High limit&nbsp;&nbsp;:</span>
                    <input type="number" 
                           id="port-high-${ruleIndex}-${componentIndex}"
                           min="0" 
                           max="65535"
                           value="${highLimit}"
                           placeholder="${placeholders.high}"
                           onchange="updatePortRangeValue(${ruleIndex}, ${componentIndex})">
                </div>
            </div>
        </div>
    `;
}

// Destination MAC address range 입력 UI (inline-field 두 개를 세로로 배치)
function createMACRangeInlineInput(ruleIndex, componentIndex, component) {
    // 값 파싱: "AA:BB:CC:DD:EE:00-AA:BB:CC:DD:EE:FF" 형태
    let lowLimit = '';
    let highLimit = '';
    
    if (component.value) {
        const parts = component.value.split('-');
        if (parts.length === 2) {
            lowLimit = parts[0].trim();
            highLimit = parts[1].trim();
        }
    }
    
    // typeInfo에서 placeholder 가져오기
    const typeInfo = tdTypes[component.type] || {};
    const placeholders = typeInfo.placeholder || {low: "AA:BB:CC:DD:EE:00", high: "AA:BB:CC:DD:EE:FF"};
    
    return `
        <div class="mac-range-wrapper">
            <div class="inline-field">
                <span class="field-label mac-range-label">Low limit&nbsp;&nbsp;:</span>
                <input type="text" 
                       id="mac-low-${ruleIndex}-${componentIndex}"
                       value="${lowLimit}"
                       placeholder="${placeholders.low}"
                       onchange="updateMACRangeValue(${ruleIndex}, ${componentIndex})">
            </div>
            <div class="inline-field">
                <span class="field-label mac-range-label">High limit&nbsp;&nbsp;:</span>
                <input type="text" 
                       id="mac-high-${ruleIndex}-${componentIndex}"
                       value="${highLimit}"
                       placeholder="${placeholders.high}"
                       onchange="updateMACRangeValue(${ruleIndex}, ${componentIndex})">
            </div>
        </div>
    `;
}

// IPv4 remote address 입력 UI (Address와 Mask를 세로로 배치)
function createIPv4AddressInput(ruleIndex, componentIndex, component) {
    // 값 파싱: "192.168.1.1/255.255.255.0" 형태
    let address = '';
    let mask = '';
    
    if (component.value) {
        const parts = component.value.split('/');
        if (parts.length === 2) {
            address = parts[0].trim();
            mask = parts[1].trim();
        }
    }
    
    // typeInfo에서 placeholder 가져오기
    const typeInfo = tdTypes[component.type] || {};
    const placeholders = typeInfo.placeholder || {address: "192.168.1.1", mask: "255.255.255.0"};
    
    return `
        <div class="mac-range-wrapper">
            <div class="inline-field">
                <span class="field-label">Address&nbsp;&nbsp;:</span>
                <input type="text" 
                       id="ipv4-addr-${ruleIndex}-${componentIndex}"
                       value="${address}"
                       placeholder="${placeholders.address}"
                       onchange="updateIPv4AddressValue(${ruleIndex}, ${componentIndex})">
            </div>
            <div class="inline-field">
                <span class="field-label">Subnet mask&nbsp;&nbsp;:</span>
                <input type="text" 
                       id="ipv4-mask-${ruleIndex}-${componentIndex}"
                       value="${mask}"
                       placeholder="${placeholders.mask}"
                       onchange="updateIPv4AddressValue(${ruleIndex}, ${componentIndex})">
            </div>
        </div>
    `;
}

// IPv6 remote address/prefix length 입력 UI (Address와 Prefix를 세로로 배치)
function createIPv6AddressInput(ruleIndex, componentIndex, component) {
    // 값 파싱: "2001:db8::1/64" 형태
    let address = '';
    let prefix = '';
    
    if (component.value) {
        const parts = component.value.split('/');
        if (parts.length === 2) {
            address = parts[0].trim();
            prefix = parts[1].trim();
        }
    }
    
    // typeInfo에서 placeholder 가져오기
    const typeInfo = tdTypes[component.type] || {};
    const placeholders = typeInfo.placeholder || {address: "2001:db8::1", prefix: "64"};
    
    return `
        <div class="mac-range-wrapper">
            <div class="inline-field">
                <span class="field-label">Address&nbsp;&nbsp;:</span>
                <input type="text" 
                       id="ipv6-addr-${ruleIndex}-${componentIndex}"
                       value="${address}"
                       placeholder="${placeholders.address}"
                       onchange="updateIPv6AddressValue(${ruleIndex}, ${componentIndex})">
            </div>
            <div class="inline-field">
                <span class="field-label">Prefix length&nbsp;&nbsp;:</span>
                <input type="number" 
                       id="ipv6-prefix-${ruleIndex}-${componentIndex}"
                       min="0"
                       max="128"
                       value="${prefix}"
                       placeholder="${placeholders.prefix}"
                       onchange="updateIPv6AddressValue(${ruleIndex}, ${componentIndex})">
            </div>
        </div>
    `;
}

// IP 3 tuple 입력 UI
function createIP3TupleInput(ruleIndex, componentIndex, component) {
    // 값 파싱
    let config = {
        ipType: 'IPv4',
        portType: 'Single',
        address: '',
        mask: '',
        prefix: '',
        protocol: '',
        port: '',
        portLow: '',
        portHigh: ''
    };
    
    if (component.value && typeof component.value === 'object') {
        config = { ...config, ...component.value };
    }
    
    // typeInfo에서 placeholder 가져오기
    const typeInfo = tdTypes[component.type] || {};
    const placeholdersIpv4 = typeInfo.placeholder_ipv4 || {};
    const placeholdersIpv6 = typeInfo.placeholder_ipv6 || {};
    const placeholdersPortSingle = typeInfo.placeholder_port_single || {};
    const placeholdersPortRange = typeInfo.placeholder_port_range || {};
    
    // 동적 placeholder 값
    const addressPlaceholder = config.ipType === 'IPv4' 
        ? (placeholdersIpv4.address || '192.168.1.1')
        : (placeholdersIpv6.address || '2001:db8::1');
    
    const maskPlaceholder = config.ipType === 'IPv4'
        ? (placeholdersIpv4.mask || '255.255.255.0')
        : (placeholdersIpv6.prefix || '64');
    
    const portPlaceholder = placeholdersPortSingle.port || '8080';
    const portLowPlaceholder = placeholdersPortRange.portLow || '8000';
    const portHighPlaceholder = placeholdersPortRange.portHigh || '8080';
    
    // 동적 레이블
    const addressLabel = config.ipType === 'IPv4' ? 'IPv4 address' : 'IPv6 address';
    const maskLabel = config.ipType === 'IPv4' ? 'Subnet mask' : 'Prefix length';
    const protocolLabel = config.ipType === 'IPv4' ? 'IPv4 Protocol identifier' : 'IPv6 Next header';
    
    return `
        <div class="ip3tuple-wrapper">
            <div class="inline-field">
                <span class="field-label">IP type&nbsp;&nbsp;:</span>
                <select id="ip3-iptype-${ruleIndex}-${componentIndex}"
                        onchange="updateIP3TupleValue(${ruleIndex}, ${componentIndex})">
                    <option value="IPv4" ${config.ipType === 'IPv4' ? 'selected' : ''}>IPv4</option>
                    <option value="IPv6" ${config.ipType === 'IPv6' ? 'selected' : ''}>IPv6</option>
                </select>
            </div>
            <div class="inline-field">
                <span class="field-label">Port type&nbsp;&nbsp;:</span>
                <select id="ip3-porttype-${ruleIndex}-${componentIndex}"
                        onchange="updateIP3TupleValue(${ruleIndex}, ${componentIndex})">
                    <option value="Single" ${config.portType === 'Single' ? 'selected' : ''}>Single remote port</option>
                    <option value="Range" ${config.portType === 'Range' ? 'selected' : ''}>Remote port range</option>
                </select>
            </div>
            
            <div class="inline-field">
                <span class="field-label">${addressLabel}&nbsp;&nbsp;:</span>
                <input type="text" 
                       id="ip3-address-${ruleIndex}-${componentIndex}"
                       value="${config.address}"
                       placeholder="${addressPlaceholder}"
                       onchange="updateIP3TupleValue(${ruleIndex}, ${componentIndex})">
            </div>
            <div class="inline-field">
                <span class="field-label">${maskLabel}&nbsp;&nbsp;:</span>
                <input type="text" 
                       id="ip3-mask-${ruleIndex}-${componentIndex}"
                       value="${config.ipType === 'IPv4' ? config.mask : config.prefix}"
                       placeholder="${maskPlaceholder}"
                       onchange="updateIP3TupleValue(${ruleIndex}, ${componentIndex})">
            </div>
            
            <div class="inline-field">
                <span class="field-label">${protocolLabel}&nbsp;&nbsp;:</span>
                <select id="ip3-protocol-${ruleIndex}-${componentIndex}"
                        onchange="updateIP3TupleValue(${ruleIndex}, ${componentIndex})">
                    <option value="">None</option>
                    <option value="TCP" ${config.protocol === 'TCP' ? 'selected' : ''}>TCP</option>
                    <option value="UDP" ${config.protocol === 'UDP' ? 'selected' : ''}>UDP</option>
                    <option value="ICMP" ${config.protocol === 'ICMP' ? 'selected' : ''}>ICMP</option>
                    <option value="ICMPv6" ${config.protocol === 'ICMPv6' ? 'selected' : ''}>ICMPv6</option>
                    <option value="ESP" ${config.protocol === 'ESP' ? 'selected' : ''}>ESP</option>
                </select>
            </div>
            
            ${config.portType === 'Single' ? `
                <div class="inline-field">
                    <span class="field-label">Single remote port&nbsp;&nbsp;:</span>
                    <input type="number" 
                           id="ip3-port-${ruleIndex}-${componentIndex}"
                           min="0"
                           max="65535"
                           value="${config.port}"
                           placeholder="${portPlaceholder}"
                           onchange="updateIP3TupleValue(${ruleIndex}, ${componentIndex})">
                </div>
            ` : `
                <div class="inline-field">
                    <span class="field-label">Port range low limit&nbsp;&nbsp;:</span>
                    <input type="number" 
                           id="ip3-portlow-${ruleIndex}-${componentIndex}"
                           min="0"
                           max="65535"
                           value="${config.portLow}"
                           placeholder="${portLowPlaceholder}"
                           onchange="updateIP3TupleValue(${ruleIndex}, ${componentIndex})">
                </div>
                <div class="inline-field">
                    <span class="field-label">Port range high limit&nbsp;&nbsp;:</span>
                    <input type="number" 
                           id="ip3-porthigh-${ruleIndex}-${componentIndex}"
                           min="0"
                           max="65535"
                           value="${config.portHigh}"
                           placeholder="${portHighPlaceholder}"
                           onchange="updateIP3TupleValue(${ruleIndex}, ${componentIndex})">
                </div>
            `}
        </div>
        
        <!-- 정보 문구 (wrapper 밖, 다음 행에 표시) -->
        <div class="snssai-info-text os-app-id-info">
            <span class="info-icon">ⓘ</span> IP 3 tuple shall contain at least one of the IPv4 address field, IPv6 remote address/prefix length field, the protocol identifier/next header field, the single remote port field and the remote port range field.
        </div>
    `;
}

// IP 3-tuple 값 업데이트
function updateIP3TupleValue(ruleIndex, componentIndex) {
    const ipTypeSelect = document.getElementById(`ip3-iptype-${ruleIndex}-${componentIndex}`);
    const portTypeSelect = document.getElementById(`ip3-porttype-${ruleIndex}-${componentIndex}`);
    const addressInput = document.getElementById(`ip3-address-${ruleIndex}-${componentIndex}`);
    const maskInput = document.getElementById(`ip3-mask-${ruleIndex}-${componentIndex}`);
    const protocolSelect = document.getElementById(`ip3-protocol-${ruleIndex}-${componentIndex}`);
    const portInput = document.getElementById(`ip3-port-${ruleIndex}-${componentIndex}`);
    const portLowInput = document.getElementById(`ip3-portlow-${ruleIndex}-${componentIndex}`);
    const portHighInput = document.getElementById(`ip3-porthigh-${ruleIndex}-${componentIndex}`);
    
    if (!ipTypeSelect || !portTypeSelect) return;
    
    const ipType = ipTypeSelect.value;
    const portType = portTypeSelect.value;
    const address = addressInput ? addressInput.value.trim() : '';
    const maskOrPrefix = maskInput ? maskInput.value.trim() : '';
    const protocol = protocolSelect ? protocolSelect.value : '';
    
    let port = '';
    let portLow = '';
    let portHigh = '';
    
    if (portType === 'Single' && portInput) {
        port = portInput.value.trim();
    } else if (portType === 'Range') {
        portLow = portLowInput ? portLowInput.value.trim() : '';
        portHigh = portHighInput ? portHighInput.value.trim() : '';
    }
    
    // 값 객체 생성
    const newValue = {
        ipType: ipType,
        portType: portType,
        address: address,
        mask: ipType === 'IPv4' ? maskOrPrefix : '',
        prefix: ipType === 'IPv6' ? maskOrPrefix : '',
        protocol: protocol,
        port: port,
        portLow: portLow,
        portHigh: portHigh
    };
    
    // 데이터 업데이트
    const rule = urspRules[ruleIndex];
    if (rule && rule.td_components[componentIndex]) {
        rule.td_components[componentIndex].value = newValue;
    }
    
    // UI 재렌더링
    renderURSPCards();
    validateTDComponents(ruleIndex);
}

// S-NSSAI 값 업데이트
function updateSNSSAIValue(ruleIndex, rsdIndex, componentIndex) {
    const sstSelect = document.getElementById(`sst-${ruleIndex}-${rsdIndex}-${componentIndex}`);
    const sdInput = document.getElementById(`sd-${ruleIndex}-${rsdIndex}-${componentIndex}`);
    
    if (!sstSelect || !sdInput) return;
    
    const sstValue = sstSelect.value;
    const sdValue = sdInput.value.trim();
    
    // SD가 비어있거나 0이면 SST only
    let newValue;
    if (sdValue === '' || sdValue === '0') {
        newValue = `SST ${sstValue}`;
    } else {
        newValue = `SST ${sstValue} + SD ${sdValue}`;
    }
    
    updateRSDComponent(ruleIndex, rsdIndex, componentIndex, 'value', newValue);
}

// Remote port range 값 업데이트
function updatePortRangeValue(ruleIndex, componentIndex) {
    const lowInput = document.getElementById(`port-low-${ruleIndex}-${componentIndex}`);
    const highInput = document.getElementById(`port-high-${ruleIndex}-${componentIndex}`);
    
    if (!lowInput || !highInput) return;
    
    const lowValue = lowInput.value.trim();
    const highValue = highInput.value.trim();
    
    if (lowValue && highValue) {
        const newValue = `${lowValue}-${highValue}`;
        updateTDComponent(ruleIndex, componentIndex, 'value', newValue);
    }
}

// Destination MAC address range 값 업데이트
function updateMACRangeValue(ruleIndex, componentIndex) {
    const lowInput = document.getElementById(`mac-low-${ruleIndex}-${componentIndex}`);
    const highInput = document.getElementById(`mac-high-${ruleIndex}-${componentIndex}`);
    
    if (!lowInput || !highInput) return;
    
    const lowValue = lowInput.value.trim();
    const highValue = highInput.value.trim();
    
    if (lowValue && highValue) {
        const newValue = `${lowValue}-${highValue}`;
        updateTDComponent(ruleIndex, componentIndex, 'value', newValue);
    }
}

// IPv4 remote address 값 업데이트
function updateIPv4AddressValue(ruleIndex, componentIndex) {
    const addrInput = document.getElementById(`ipv4-addr-${ruleIndex}-${componentIndex}`);
    const maskInput = document.getElementById(`ipv4-mask-${ruleIndex}-${componentIndex}`);
    
    if (!addrInput || !maskInput) return;
    
    const addrValue = addrInput.value.trim();
    const maskValue = maskInput.value.trim();
    
    if (addrValue && maskValue) {
        const newValue = `${addrValue}/${maskValue}`;
        updateTDComponent(ruleIndex, componentIndex, 'value', newValue);
    }
}

// IPv6 remote address/prefix length 값 업데이트
function updateIPv6AddressValue(ruleIndex, componentIndex) {
    const addrInput = document.getElementById(`ipv6-addr-${ruleIndex}-${componentIndex}`);
    const prefixInput = document.getElementById(`ipv6-prefix-${ruleIndex}-${componentIndex}`);
    
    if (!addrInput || !prefixInput) return;
    
    const addrValue = addrInput.value.trim();
    const prefixValue = prefixInput.value.trim();
    
    if (addrValue && prefixValue) {
        const newValue = `${addrValue}/${prefixValue}`;
        updateTDComponent(ruleIndex, componentIndex, 'value', newValue);
    }
}

// Destination MAC address range 값 업데이트
function updateMACRangeValue(ruleIndex, componentIndex) {
    const lowInput = document.getElementById(`mac-low-${ruleIndex}-${componentIndex}`);
    const highInput = document.getElementById(`mac-high-${ruleIndex}-${componentIndex}`);
    
    if (!lowInput || !highInput) return;
    
    const lowValue = lowInput.value.trim();
    const highValue = highInput.value.trim();
    
    if (lowValue && highValue) {
        const newValue = `${lowValue}-${highValue}`;
        updateTDComponent(ruleIndex, componentIndex, 'value', newValue);
    }
}

// Format hex data in v1 style with line numbers
function formatHexDisplay(hexString) {
    if (!hexString) return '';
    
    // Remove spaces and ensure uppercase
    const hexClean = hexString.replace(/\s/g, '').toUpperCase();
    
    // Split into bytes (2 characters each)
    const bytes = [];
    for (let i = 0; i < hexClean.length; i += 2) {
        bytes.push(hexClean.substr(i, 2));
    }
    
    // Format with line numbers (16 bytes per line)
    const lines = [];
    for (let i = 0; i < bytes.length; i += 16) {
        const lineBytes = bytes.slice(i, i + 16);
        const hexStr = lineBytes.join(' ');
        const lineNumber = i.toString(16).padStart(4, '0').toUpperCase();
        lines.push(`${lineNumber}   ${hexStr}`);
    }
    
    return lines.join('\n');
}

// Update TD Multi-Select
function updateTDMultiSelect(ruleIndex, componentIndex) {
    const hiddenInput = document.querySelector(`#td-multiselect-${ruleIndex}-${componentIndex}`);
    if (!hiddenInput) {
        console.error('Hidden input not found:', `#td-multiselect-${ruleIndex}-${componentIndex}`);
        return;
    }
    
    const container = hiddenInput.parentElement;
    const checkboxes = container.querySelectorAll('input[type="checkbox"]');
    const selectedValues = [];
    
    checkboxes.forEach(checkbox => {
        if (checkbox.checked) {
            selectedValues.push(checkbox.value);
        }
    });
    
    const newValue = selectedValues.join(', ');
    
    // Hidden input 업데이트
    hiddenInput.value = newValue;
    
    // TD component 업데이트
    updateTDComponent(ruleIndex, componentIndex, 'value', newValue);
    
    // 선택된 항목 텍스트 업데이트
    const textDisplay = container.querySelector('.cc-selected-text');
    if (textDisplay) {
        textDisplay.textContent = selectedValues.length > 0 ? newValue : 'Select items...';
    }
}

// Toggle Connection Capabilities Dropdown
function toggleConnectionCapabilities(ruleIndex, componentIndex) {
    const dropdown = document.getElementById(`cc-dropdown-${ruleIndex}-${componentIndex}`);
    if (!dropdown) return;
    
    // 현재 드롭다운의 표시 상태 토글
    const isVisible = dropdown.style.display !== 'none';
    
    // 모든 드롭다운 닫기
    document.querySelectorAll('.cc-dropdown-menu').forEach(menu => {
        menu.style.display = 'none';
    });
    
    // 현재 드롭다운만 토글
    if (!isVisible) {
        dropdown.style.display = 'block';
    }
}

// 드롭다운 외부 클릭 시 닫기
document.addEventListener('click', function(event) {
    if (!event.target.closest('.connection-capabilities-dropdown')) {
        document.querySelectorAll('.cc-dropdown-menu').forEach(menu => {
            menu.style.display = 'none';
        });
    }
});

// Load sample log into input field
function loadSampleLog() {
    const sampleLog = `0000   98 7a 10 a4 6f 51 00 15 17 ab b1 87 08 00 45 02
0010   00 bc 00 00 40 00 3d 84 7a 4e c0 a8 14 18 c0 a8
0020   2d 05 96 0c 96 0c 03 79 20 0c ef de 05 2c 00 03
0030   00 9c c6 14 7c 52 00 00 00 ad 00 00 00 3c 00 04
0040   40 80 87 00 00 04 00 0a 00 06 80 c8 00 00 00 20
0050   00 55 00 03 40 70 21 00 26 00 61 60 7e 02 c4 e5
0060   ff de 04 7e 00 68 05 00 53 01 01 00 4f 00 4d 02
0070   f8 23 00 48 00 03 00 44 01 00 1f 01 00 0b 88 09
0080   08 62 75 73 69 6e 65 73 73 00 0f 00 0d ff 00 0a
0090   02 04 01 e2 e1 11 08 01 10 01 00 20 02 00 01 01
00a0   00 1a 00 18 ff 00 15 02 04 01 de f2 22 04 09 08
00b0   69 6e 74 65 72 6e 65 74 08 01 10 01 00 6e 40 0a
00c0   0c 3b 9a ca 00 30 3b 9a ca 00`;
    
    const logTextarea = document.getElementById('log-text');
    
    if (logTextarea) {
        logTextarea.value = sampleLog;
        console.log('Sample log loaded into input field');
        
        // Show visual feedback
        logTextarea.style.backgroundColor = '#e8f5e8';
        setTimeout(() => {
            logTextarea.style.backgroundColor = '';
        }, 500);
    }
}

// Clear log text from input field
function clearLogText() {
    const logTextarea = document.getElementById('log-text');
    
    if (logTextarea) {
        logTextarea.value = '';
        console.log('Log text cleared');
        
        // Show visual feedback
        logTextarea.style.backgroundColor = '#ffe8e8';
        setTimeout(() => {
            logTextarea.style.backgroundColor = '';
        }, 500);
    }
}

// Load example log into input field (legacy function for compatibility)
function loadExampleLog(element) {
    const logText = element.textContent.trim();
    const logTextarea = document.getElementById('log-text');
    
    if (logTextarea) {
        logTextarea.value = logText;
        console.log('Example log loaded into input field');
        
        // Optional: Show visual feedback
        element.style.backgroundColor = '#e8f5e8';
        setTimeout(() => {
            element.style.backgroundColor = '';
        }, 500);
    }
}