#!/usr/bin/env python3
"""
Arista Enhanced Audit Module - Structured Configuration Parser
Integrated with Flask NCM - No hardcoded credentials
"""

from datetime import datetime
from tabulate import tabulate
import re
import json
import requests
from requests.auth import HTTPBasicAuth
import logging

logger = logging.getLogger(__name__)

def execute_eapi_command_single(device_config, command):
    """
    Execute a SINGLE command via eAPI
    
    Args:
        device_config: dict with host, username, password, eapi_port, use_https
        command: string command to execute
    
    Returns:
        string output or None
    """
    protocol = 'https' if device_config.get('use_https', True) else 'http'
    url = f"{protocol}://{device_config['host']}:{device_config.get('eapi_port', 443)}/command-api"
    
    headers = {'Content-Type': 'application/json-rpc'}
    payload = {
        "jsonrpc": "2.0",
        "method": "runCmds",
        "params": {
            "version": 1,
            "cmds": [command],
            "format": "text"
        },
        "id": "audit_script"
    }
    
    try:
        response = requests.post(
            url,
            auth=HTTPBasicAuth(device_config['username'], device_config['password']),
            headers=headers,
            data=json.dumps(payload),
            verify=False,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            if 'result' in result and len(result['result']) > 0:
                return result['result'][0].get('output', '')
        return None
    except Exception as e:
        logger.error(f"eAPI command failed: {command} - {e}")
        return None

def parse_running_config_structured(config_text):
    """Parse running config into structured sections"""
    
    sections = {
        'hostname': None,
        'interfaces': [],
        'isis': [],
        'bgp': [],
        'mpls': [],
        'ldp': [],
        'snmp': [],
        'vlans': [],
        'vrfs': [],
        'route_maps': [],
        'prefix_lists': [],
        'access_lists': [],
        'static_routes': []
    }
    
    if not config_text:
        return sections
    
    lines = config_text.split('\n')
    i = 0
    
    while i < len(lines):
        line = lines[i].strip()
        
        if not line or line.startswith('!'):
            i += 1
            continue
        
        # Hostname
        if line.startswith('hostname '):
            sections['hostname'] = line.replace('hostname ', '')
            i += 1
            continue
        
        # MPLS
        if line.startswith('mpls '):
            sections['mpls'].append(line)
            i += 1
            continue
        
        # Router ISIS
        if line.startswith('router isis '):
            block = [line]
            i += 1
            while i < len(lines):
                next_line = lines[i].strip()
                if not next_line or next_line.startswith('!'):
                    break
                if next_line.startswith('router ') or next_line.startswith('interface '):
                    break
                block.append('   ' + next_line)
                i += 1
            sections['isis'].append('\n'.join(block))
            continue
        
        # Router BGP
        if line.startswith('router bgp '):
            block = [line]
            i += 1
            while i < len(lines):
                next_line = lines[i].strip()
                if not next_line or next_line.startswith('!'):
                    break
                if next_line.startswith('router ') or next_line.startswith('interface '):
                    break
                block.append('   ' + next_line)
                i += 1
            sections['bgp'].append('\n'.join(block))
            continue
        
        # MPLS LDP
        if line.startswith('mpls ldp'):
            block = [line]
            i += 1
            while i < len(lines):
                next_line = lines[i].strip()
                if not next_line or next_line.startswith('!'):
                    break
                if not next_line.startswith('router-id') and (next_line.startswith('router ') or next_line.startswith('interface ')):
                    break
                block.append('   ' + next_line)
                i += 1
            sections['ldp'].append('\n'.join(block))
            continue
        
        # SNMP
        if line.startswith('snmp-server '):
            sections['snmp'].append(line)
            i += 1
            continue
        
        # VRF
        if line.startswith('vrf instance ') or line.startswith('ip vrf '):
            block = [line]
            i += 1
            while i < len(lines):
                next_line = lines[i].strip()
                if not next_line or next_line.startswith('!'):
                    break
                if next_line.startswith('vrf ') or next_line.startswith('interface ') or next_line.startswith('router '):
                    break
                block.append('   ' + next_line)
                i += 1
            sections['vrfs'].append('\n'.join(block))
            continue
        
        # VLAN
        if re.match(r'^vlan \d+', line):
            block = [line]
            i += 1
            while i < len(lines):
                next_line = lines[i].strip()
                if not next_line or next_line.startswith('!'):
                    break
                if next_line.startswith('vlan ') or next_line.startswith('interface '):
                    break
                block.append('   ' + next_line)
                i += 1
            sections['vlans'].append('\n'.join(block))
            continue
        
        # Interface
        if line.startswith('interface '):
            block = [line]
            i += 1
            while i < len(lines):
                next_line = lines[i].strip()
                if not next_line or next_line.startswith('!'):
                    break
                if next_line.startswith('interface ') or next_line.startswith('router ') or next_line.startswith('vrf '):
                    break
                block.append('   ' + next_line)
                i += 1
            sections['interfaces'].append('\n'.join(block))
            continue
        
        # Route Map
        if line.startswith('route-map '):
            block = [line]
            i += 1
            while i < len(lines):
                next_line = lines[i].strip()
                if not next_line or next_line.startswith('!'):
                    break
                if next_line.startswith('route-map ') or next_line.startswith('interface ') or next_line.startswith('router '):
                    break
                block.append('   ' + next_line)
                i += 1
            sections['route_maps'].append('\n'.join(block))
            continue
        
        # Prefix List
        if line.startswith('ip prefix-list '):
            sections['prefix_lists'].append(line)
        
        # Access List
        if line.startswith('ip access-list ') or line.startswith('access-list '):
            sections['access_lists'].append(line)
        
        # Static Routes
        if line.startswith('ip route '):
            sections['static_routes'].append(line)
        
        i += 1
    
    return sections

def parse_show_command_output(output, command_type):
    """Parse show command output into structured data"""
    
    if not output or not isinstance(output, str):
        return []
    
    lines = output.strip().split('\n')
    lines = [l for l in lines if l.strip() and not l.strip().startswith('---')]
    
    if command_type == 'mpls_route':
        data = []
        current_label = None
        
        for line in lines:
            if re.match(r'^\s*\d{5,}', line):
                parts = line.split()
                if len(parts) >= 1:
                    current_label = parts[0]
            elif 'via M,' in line and current_label:
                parts = line.split(',')
                if len(parts) >= 2:
                    next_hop = parts[1].strip().split()[0]
                    data.append({
                        'Label': current_label,
                        'Next Hop': next_hop,
                        'Action': 'pop' if 'pop' in line else 'N/A'
                    })
        return data
    
    elif command_type == 'ldp_neighbor':
        data = []
        for line in lines:
            if line.startswith('Peer LDP ID:'):
                peer_info = {}
                match = re.search(r'Peer LDP ID:\s+(\S+)', line)
                if match:
                    peer_info['Peer LDP ID'] = match.group(1)
                
                idx = lines.index(line)
                for i in range(idx, min(idx + 10, len(lines))):
                    if 'State:' in lines[i]:
                        state_match = re.search(r'State:\s+(\S+)', lines[i])
                        if state_match:
                            peer_info['State'] = state_match.group(1)
                    if 'Uptime:' in lines[i]:
                        uptime_match = re.search(r'Uptime:\s+(.+?)(?:\n|$)', lines[i])
                        if uptime_match:
                            peer_info['Uptime'] = uptime_match.group(1).strip()
                
                if peer_info:
                    data.append(peer_info)
        return data
    
    elif command_type == 'bgp_summary':
        data = []
        in_neighbor_section = False
        
        for line in lines:
            if 'Neighbor' in line and ('AS' in line or 'Session' in line):
                in_neighbor_section = True
                continue
            
            if in_neighbor_section and re.search(r'\d+\.\d+\.\d+\.\d+', line):
                parts = line.split()
                if len(parts) >= 3:
                    data.append({
                        'Neighbor': parts[0],
                        'AS': parts[1] if len(parts) > 1 else 'N/A',
                        'State': parts[2] if len(parts) > 2 else 'N/A',
                        'AFI/SAFI': parts[3] if len(parts) > 3 else 'N/A',
                        'Prefixes': parts[-1] if len(parts) > 4 else 'N/A'
                    })
        return data
    
    elif command_type == 'isis_neighbor':
        data = []
        for line in lines:
            if re.search(r'[A-Za-z0-9_-]+\s+(L\d|Ethernet|GigabitEthernet)', line):
                parts = line.split()
                if len(parts) >= 4:
                    data.append({
                        'System Id': parts[2],
                        'Type': parts[3],
                        'Interface': parts[4] if len(parts) > 4 else 'N/A',
                        'State': parts[6] if len(parts) > 6 else 'N/A'
                    })
        return data
    
    elif command_type == 'vrf':
        data = []
        for line in lines:
            if line.strip() and not any(x in line for x in ['VRF', 'Maximum', '---']):
                parts = line.split()
                if len(parts) >= 2 and not line.startswith(' '):
                    data.append({
                        'VRF Name': parts[0],
                        'Protocols': parts[1] if len(parts) > 1 else 'N/A',
                        'State': parts[2] if len(parts) > 2 else 'N/A',
                        'Interfaces': ' '.join(parts[3:]) if len(parts) > 3 else 'N/A'
                    })
        return data
    
    return []

def create_comprehensive_report_text(device_info, device_name):
    """
    Create detailed structured audit report as text
    
    Args:
        device_info: dict with collected data
        device_name: string device name
    
    Returns:
        string with complete audit report
    """
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []
    
    # Header
    lines.append("=" * 120)
    lines.append(" " * 35 + "ARISTA DEVICE COMPREHENSIVE AUDIT REPORT")
    lines.append(" " * 30 + "Structured Configuration & Operational Data")
    lines.append("=" * 120)
    lines.append("")
    
    lines.append(f"Generated:    {timestamp}")
    lines.append(f"Device:       {device_info.get('hostname', device_name)}")
    lines.append(f"Device IP:    {device_info.get('device_ip', 'N/A')}")
    lines.append("")
    lines.append("=" * 120)
    lines.append("")
    
    # TABLE OF CONTENTS
    lines.append("TABLE OF CONTENTS")
    lines.append("=" * 120)
    lines.append("1.  System Information")
    lines.append("2.  MPLS Configuration & Routes")
    lines.append("3.  LDP Configuration & Neighbors")
    lines.append("4.  ISIS Configuration & Neighbors")
    lines.append("5.  BGP Configuration & Neighbors")
    lines.append("6.  VRF Configuration")
    lines.append("7.  Interface Configuration")
    lines.append("8.  SNMP Configuration")
    lines.append("9.  VLAN Configuration")
    lines.append("10. Routing Policies (Route-Maps, Prefix-Lists, ACLs)")
    lines.append("")
    lines.append("=" * 120)
    lines.append("")
    
    # 1. SYSTEM INFORMATION
    lines.append("")
    lines.append("=" * 120)
    lines.append("1. SYSTEM INFORMATION")
    lines.append("=" * 120)
    lines.append("")
    
    if device_info.get('show isis summary'):
        lines.append("--- ISIS Summary ---")
        lines.append(device_info['show isis summary'])
        lines.append("")
    
    # 2. MPLS CONFIGURATION & ROUTES
    lines.append("")
    lines.append("=" * 120)
    lines.append("2. MPLS CONFIGURATION & OPERATIONAL STATE")
    lines.append("=" * 120)
    lines.append("")
    
    if device_info.get('config_sections', {}).get('mpls'):
        lines.append("--- MPLS Configuration ---")
        for config in device_info['config_sections']['mpls']:
            lines.append(config)
        lines.append("")
    
    if device_info.get('show mpls route'):
        lines.append("--- MPLS Forwarding Table (show mpls route) ---")
        lines.append(device_info['show mpls route'])
        lines.append("")
        
        if device_info.get('MPLS Routes Table'):
            lines.append("--- MPLS Routes Summary ---")
            table = tabulate(device_info['MPLS Routes Table'], headers='keys', tablefmt='grid')
            lines.append(table)
            lines.append("")
    
    # 3. LDP CONFIGURATION & NEIGHBORS
    lines.append("")
    lines.append("=" * 120)
    lines.append("3. MPLS LDP CONFIGURATION & NEIGHBORS")
    lines.append("=" * 120)
    lines.append("")
    
    if device_info.get('config_sections', {}).get('ldp'):
        lines.append("--- LDP Configuration ---")
        for config in device_info['config_sections']['ldp']:
            lines.append(config)
        lines.append("")
    
    if device_info.get('show mpls ldp neighbor'):
        lines.append("--- LDP Neighbors (show mpls ldp neighbor) ---")
        lines.append(device_info['show mpls ldp neighbor'])
        lines.append("")
        
        if device_info.get('LDP Neighbors Table'):
            lines.append("--- LDP Neighbors Summary ---")
            table = tabulate(device_info['LDP Neighbors Table'], headers='keys', tablefmt='grid')
            lines.append(table)
            lines.append("")
    
    if device_info.get('show mpls ldp discovery'):
        lines.append("--- LDP Discovery (show mpls ldp discovery) ---")
        lines.append(device_info['show mpls ldp discovery'])
        lines.append("")
    
    # 4. ISIS CONFIGURATION & NEIGHBORS
    lines.append("")
    lines.append("=" * 120)
    lines.append("4. ISIS CONFIGURATION & NEIGHBORS")
    lines.append("=" * 120)
    lines.append("")
    
    if device_info.get('config_sections', {}).get('isis'):
        lines.append("--- ISIS Configuration ---")
        for config in device_info['config_sections']['isis']:
            lines.append(config)
            lines.append("")
    
    if device_info.get('show isis neighbors'):
        lines.append("--- ISIS Neighbors (show isis neighbors) ---")
        lines.append(device_info['show isis neighbors'])
        lines.append("")
    
    if device_info.get('show isis database'):
        lines.append("--- ISIS Database (show isis database) ---")
        lines.append(device_info['show isis database'])
        lines.append("")
    
    # 5. BGP CONFIGURATION & NEIGHBORS
    lines.append("")
    lines.append("=" * 120)
    lines.append("5. BGP CONFIGURATION & NEIGHBORS")
    lines.append("=" * 120)
    lines.append("")
    
    if device_info.get('config_sections', {}).get('bgp'):
        lines.append("--- BGP Configuration ---")
        for config in device_info['config_sections']['bgp']:
            lines.append(config)
            lines.append("")
    
    if device_info.get('show bgp summary'):
        lines.append("--- BGP Summary (show bgp summary) ---")
        lines.append(device_info['show bgp summary'])
        lines.append("")
        
        if device_info.get('BGP Summary Table'):
            lines.append("--- BGP Neighbors Summary ---")
            table = tabulate(device_info['BGP Summary Table'], headers='keys', tablefmt='grid')
            lines.append(table)
            lines.append("")
    
    if device_info.get('show bgp neighbors'):
        lines.append("--- BGP Neighbors Detail (show bgp neighbors) ---")
        lines.append(device_info['show bgp neighbors'])
        lines.append("")
    
    if device_info.get('show bgp ipv4 unicast'):
        lines.append("--- BGP IPv4 Unicast Routes (show bgp ipv4 unicast) ---")
        lines.append(device_info['show bgp ipv4 unicast'])
        lines.append("")
    
    # 6. VRF CONFIGURATION
    lines.append("")
    lines.append("=" * 120)
    lines.append("6. VRF CONFIGURATION")
    lines.append("=" * 120)
    lines.append("")
    
    if device_info.get('config_sections', {}).get('vrfs'):
        lines.append("--- VRF Configuration ---")
        for config in device_info['config_sections']['vrfs']:
            lines.append(config)
            lines.append("")
    
    if device_info.get('show vrf'):
        lines.append("--- VRF Status (show vrf) ---")
        lines.append(device_info['show vrf'])
        lines.append("")
        
        if device_info.get('VRF Table'):
            lines.append("--- VRF Summary ---")
            table = tabulate(device_info['VRF Table'], headers='keys', tablefmt='grid')
            lines.append(table)
            lines.append("")
    
    # 7. INTERFACE CONFIGURATION
    lines.append("")
    lines.append("=" * 120)
    lines.append("7. INTERFACE CONFIGURATION")
    lines.append("=" * 120)
    lines.append("")
    
    if device_info.get('show ip interface brief'):
        lines.append("--- Interface Status (show ip interface brief) ---")
        lines.append(device_info['show ip interface brief'])
        lines.append("")
    
    if device_info.get('config_sections', {}).get('interfaces'):
        lines.append("--- Detailed Interface Configuration ---")
        for config in device_info['config_sections']['interfaces']:
            lines.append(config)
            lines.append("")
    
    # 8. SNMP CONFIGURATION
    lines.append("")
    lines.append("=" * 120)
    lines.append("8. SNMP CONFIGURATION")
    lines.append("=" * 120)
    lines.append("")
    
    if device_info.get('config_sections', {}).get('snmp'):
        lines.append("--- SNMP Configuration ---")
        for config in device_info['config_sections']['snmp']:
            lines.append(config)
        lines.append("")
    
    if device_info.get('show snmp community'):
        lines.append("--- SNMP Communities (show snmp community) ---")
        lines.append(device_info['show snmp community'])
        lines.append("")
    
    if device_info.get('show snmp group'):
        lines.append("--- SNMP Groups (show snmp group) ---")
        lines.append(device_info['show snmp group'])
        lines.append("")
    
    # 9. VLAN CONFIGURATION
    lines.append("")
    lines.append("=" * 120)
    lines.append("9. VLAN CONFIGURATION")
    lines.append("=" * 120)
    lines.append("")
    
    if device_info.get('config_sections', {}).get('vlans'):
        for config in device_info['config_sections']['vlans']:
            lines.append(config)
            lines.append("")
    else:
        lines.append("No VLANs configured")
        lines.append("")
    
    # 10. ROUTING POLICIES
    lines.append("")
    lines.append("=" * 120)
    lines.append("10. ROUTING POLICIES")
    lines.append("=" * 120)
    lines.append("")
    
    if device_info.get('config_sections', {}).get('route_maps'):
        lines.append("--- Route Maps ---")
        for config in device_info['config_sections']['route_maps']:
            lines.append(config)
            lines.append("")
    
    if device_info.get('config_sections', {}).get('prefix_lists'):
        lines.append("--- Prefix Lists ---")
        for config in device_info['config_sections']['prefix_lists']:
            lines.append(config)
        lines.append("")
    
    if device_info.get('config_sections', {}).get('access_lists'):
        lines.append("--- Access Lists ---")
        for config in device_info['config_sections']['access_lists']:
            lines.append(config)
        lines.append("")
    
    if device_info.get('config_sections', {}).get('static_routes'):
        lines.append("--- Static Routes ---")
        for config in device_info['config_sections']['static_routes']:
            lines.append(config)
        lines.append("")
    
    # Footer
    lines.append("")
    lines.append("=" * 120)
    lines.append(" " * 45 + "END OF AUDIT REPORT")
    lines.append("=" * 120)
    
    return '\n'.join(lines)

def collect_arista_audit_data(device_info):
    """
    Main audit collection function
    
    Args:
        device_info: dict with ip, username, password, eapi_port (optional), use_https (optional)
    
    Returns:
        dict with collected audit data or None on failure
    """
    
    # Prepare device config for eAPI
    device_config = {
        'host': device_info['ip'],
        'username': device_info['username'],
        'password': device_info['password'],
        'eapi_port': device_info.get('eapi_port', 443),
        'use_https': device_info.get('use_https', True)
    }
    
    collected_data = {
        'device_ip': device_info['ip'],
        'timestamp': datetime.now().isoformat()
    }
    
    logger.info("=" * 80)
    logger.info("Collecting Arista Audit Data via eAPI")
    logger.info("=" * 80)
    
    show_commands = [
        'show mpls route',
        'show mpls ldp neighbor',
        'show mpls ldp discovery',
        'show bgp summary',
        'show bgp neighbors',
        'show bgp ipv4 unicast',
        'show isis summary',
        'show isis neighbors',
        'show isis database',
        'show snmp community',
        'show snmp group',
        'show vrf',
        'show ip vrf',
        'show ip interface brief',
        'show running-config'
    ]
    
    success_count = 0
    for cmd in show_commands:
        logger.info(f"  → {cmd}...")
        output = execute_eapi_command_single(device_config, cmd)
        
        if output and len(output) > 10:
            collected_data[cmd] = output
            success_count += 1
            logger.info(f"    ✓ ({len(output)} chars)")
            
            # Parse structured data
            if 'mpls route' in cmd:
                parsed = parse_show_command_output(output, 'mpls_route')
                if parsed:
                    collected_data['MPLS Routes Table'] = parsed
            elif 'ldp neighbor' in cmd:
                parsed = parse_show_command_output(output, 'ldp_neighbor')
                if parsed:
                    collected_data['LDP Neighbors Table'] = parsed
            elif 'bgp summary' in cmd:
                parsed = parse_show_command_output(output, 'bgp_summary')
                if parsed:
                    collected_data['BGP Summary Table'] = parsed
            elif 'isis neighbor' in cmd:
                parsed = parse_show_command_output(output, 'isis_neighbor')
                if parsed:
                    collected_data['ISIS Neighbors Table'] = parsed
            elif cmd == 'show vrf':
                parsed = parse_show_command_output(output, 'vrf')
                if parsed:
                    collected_data['VRF Table'] = parsed
        else:
            logger.warning(f"    ⚠ No output for {cmd}")
    
    # Parse running config into structured sections
    if collected_data.get('show running-config'):
        logger.info("  → Parsing running configuration into structured sections...")
        config_sections = parse_running_config_structured(collected_data['show running-config'])
        collected_data['config_sections'] = config_sections
        collected_data['hostname'] = config_sections.get('hostname', 'Unknown')
        logger.info(f"    ✓ Parsed {len(config_sections['interfaces'])} interfaces")
        logger.info(f"    ✓ Parsed {len(config_sections['isis'])} ISIS instances")
        logger.info(f"    ✓ Parsed {len(config_sections['bgp'])} BGP instances")
        logger.info(f"    ✓ Parsed {len(config_sections['mpls'])} MPLS config lines")
        logger.info(f"    ✓ Parsed {len(config_sections['ldp'])} LDP instances")
        logger.info(f"    ✓ Parsed {len(config_sections['vrfs'])} VRFs")
        logger.info(f"    ✓ Parsed {len(config_sections['vlans'])} VLANs")
        logger.info(f"    ✓ Parsed {len(config_sections['snmp'])} SNMP config lines")
    
    logger.info(f"\n✓ Collected data from {success_count}/{len(show_commands)} commands")
    
    if success_count > 0:
        return collected_data
    else:
        logger.error("✗ No data collected from device")
        return None