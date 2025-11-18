# -*- coding: utf-8 -*-
"""
Cisco IOS-XE NETCONF Audit Driver
Comprehensive device auditing via NETCONF for IOS-XE platforms
"""

from __future__ import unicode_literals

import re
import logging
import ipaddress
from datetime import datetime
from lxml import etree as ETREE

from ncclient import manager
from ncclient.xml_ import to_ele
from ncclient.operations.rpc import RPCError

logger = logging.getLogger(__name__)

# Namespace definitions for IOS-XE
NS = {
    # Native IOS-XE
    "native": "http://cisco.com/ns/yang/Cisco-IOS-XE-native",
    # Interface models
    "if": "http://cisco.com/ns/yang/Cisco-IOS-XE-interfaces-oper",
    "if-cfg": "http://cisco.com/ns/yang/Cisco-IOS-XE-interface-common",
    # Routing
    "bgp": "http://cisco.com/ns/yang/Cisco-IOS-XE-bgp-oper",
    "ospf": "http://cisco.com/ns/yang/Cisco-IOS-XE-ospf-oper",
    "isis": "http://cisco.com/ns/yang/Cisco-IOS-XE-isis-oper",
    "route": "http://cisco.com/ns/yang/Cisco-IOS-XE-routing-oper",
    # Platform
    "platform": "http://cisco.com/ns/yang/Cisco-IOS-XE-platform-oper",
    "memory": "http://cisco.com/ns/yang/Cisco-IOS-XE-memory-oper",
    "process": "http://cisco.com/ns/yang/Cisco-IOS-XE-process-cpu-oper",
    # Environment
    "env": "http://cisco.com/ns/yang/Cisco-IOS-XE-environment-oper",
    # Layer 2
    "lldp": "http://cisco.com/ns/yang/Cisco-IOS-XE-lldp-oper",
    "arp": "http://cisco.com/ns/yang/Cisco-IOS-XE-arp-oper",
    "mac": "http://cisco.com/ns/yang/Cisco-IOS-XE-matm-oper",
    # Management
    "snmp": "http://cisco.com/ns/yang/Cisco-IOS-XE-snmp",
    "ntp": "http://cisco.com/ns/yang/Cisco-IOS-XE-ntp",
}


class IOSXENetconfAudit:
    """Cisco IOS-XE NETCONF Audit Collector"""
    
    def __init__(self, hostname, username, password, port=830, timeout=60):
        """
        Initialize IOS-XE NETCONF Audit connection
        
        Args:
            hostname: Device IP/hostname
            username: SSH username
            password: SSH password
            port: NETCONF port (default 830)
            timeout: Connection timeout
        """
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.device = None
        
    def open(self):
        """Open NETCONF connection to IOS-XE device"""
        try:
            logger.info(f"Connecting to IOS-XE device {self.hostname}:{self.port}")
            self.device = manager.connect(
                host=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                device_params={"name": "iosxe"},
                hostkey_verify=False
            )
            logger.info(f"✓ Connected to {self.hostname}")
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            raise
    
    def close(self):
        """Close NETCONF connection"""
        if self.device:
            self.device.close_session()
            logger.info(f"Disconnected from {self.hostname}")
    
    def _find_text(self, tree, xpath, default='', namespaces=None):
        """Find text content using XPath"""
        try:
            ns = namespaces or NS
            elements = tree.xpath(xpath, namespaces=ns)
            if elements and len(elements) > 0:
                elem = elements[0]
                if hasattr(elem, 'text') and elem.text:
                    return elem.text.strip()
            return default
        except Exception as e:
            logger.debug(f"XPath query failed: {xpath} - {e}")
            return default
    
    def get_facts(self):
        """Get device facts"""
        facts = {
            "vendor": "Cisco",
            "os_version": "",
            "hostname": "",
            "uptime": -1,
            "serial_number": "",
            "model": "",
            "interface_list": []
        }
        
        try:
            # Get version info
            version_filter = """
            <filter>
                <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
                    <version/>
                    <hostname/>
                </native>
                <platform-software xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-platform-software-oper">
                    <control-processes/>
                </platform-software>
            </filter>
            """
            
            reply = self.device.get(filter=version_filter).data_xml
            tree = ETREE.fromstring(reply)
            
            facts["hostname"] = self._find_text(tree, './/native:hostname', '', NS)
            facts["os_version"] = self._find_text(tree, './/native:version', '', NS)
            
            # Get inventory
            inventory_filter = """
            <filter>
                <components xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-platform-oper">
                    <component/>
                </components>
            </filter>
            """
            
            reply = self.device.get(filter=inventory_filter).data_xml
            tree = ETREE.fromstring(reply)
            
            # Find chassis component
            for comp in tree.xpath('.//platform:component', namespaces=NS):
                comp_name = self._find_text(comp, './platform:name', '', NS)
                if 'Chassis' in comp_name or comp_name == 'chassis':
                    facts["model"] = self._find_text(comp, './platform:part-no', '', NS)
                    facts["serial_number"] = self._find_text(comp, './platform:serial-no', '', NS)
                    break
            
            # Get interfaces
            intf_filter = """
            <filter>
                <interfaces xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-interfaces-oper">
                    <interface>
                        <name/>
                    </interface>
                </interfaces>
            </filter>
            """
            
            reply = self.device.get(filter=intf_filter).data_xml
            tree = ETREE.fromstring(reply)
            
            for intf in tree.xpath('.//if:interface', namespaces=NS):
                name = self._find_text(intf, './if:name', '', NS)
                if name:
                    facts["interface_list"].append(name)
            
            logger.info(f"✓ Facts collected for {self.hostname}")
            
        except Exception as e:
            logger.error(f"Failed to get facts: {e}")
        
        return facts
    
    def get_interfaces(self):
        """Get interface details"""
        interfaces = {}
        
        try:
            intf_filter = """
            <filter>
                <interfaces xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-interfaces-oper">
                    <interface/>
                </interfaces>
            </filter>
            """
            
            reply = self.device.get(filter=intf_filter).data_xml
            tree = ETREE.fromstring(reply)
            
            for intf in tree.xpath('.//if:interface', namespaces=NS):
                name = self._find_text(intf, './if:name', '', NS)
                if not name:
                    continue
                
                oper_status = self._find_text(intf, './if:oper-status', '', NS)
                admin_status = self._find_text(intf, './if:admin-status', '', NS)
                
                interfaces[name] = {
                    "is_up": oper_status == "if-oper-state-ready",
                    "is_enabled": admin_status == "if-state-up",
                    "description": self._find_text(intf, './if:description', '', NS),
                    "mac_address": self._find_text(intf, './if:phys-address', '', NS),
                    "speed": int(self._find_text(intf, './if:speed', '0', NS)),
                    "mtu": int(self._find_text(intf, './if:mtu', '0', NS)),
                }
            
            logger.info(f"✓ Collected {len(interfaces)} interfaces")
            
        except Exception as e:
            logger.error(f"Failed to get interfaces: {e}")
        
        return interfaces
    
    def get_interface_counters(self):
        """Get interface statistics"""
        counters = {}
        
        try:
            stats_filter = """
            <filter>
                <interfaces xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-interfaces-oper">
                    <interface>
                        <name/>
                        <statistics/>
                    </interface>
                </interfaces>
            </filter>
            """
            
            reply = self.device.get(filter=stats_filter).data_xml
            tree = ETREE.fromstring(reply)
            
            for intf in tree.xpath('.//if:interface', namespaces=NS):
                name = self._find_text(intf, './if:name', '', NS)
                if not name:
                    continue
                
                stats = intf.find('./if:statistics', namespaces=NS)
                if stats is not None:
                    counters[name] = {
                        "rx_octets": int(self._find_text(stats, './if:in-octets', '0', NS)),
                        "tx_octets": int(self._find_text(stats, './if:out-octets', '0', NS)),
                        "rx_unicast_packets": int(self._find_text(stats, './if:in-unicast-pkts', '0', NS)),
                        "tx_unicast_packets": int(self._find_text(stats, './if:out-unicast-pkts', '0', NS)),
                        "rx_errors": int(self._find_text(stats, './if:in-errors', '0', NS)),
                        "tx_errors": int(self._find_text(stats, './if:out-errors', '0', NS)),
                        "rx_discards": int(self._find_text(stats, './if:in-discards', '0', NS)),
                        "tx_discards": int(self._find_text(stats, './if:out-discards', '0', NS)),
                    }
            
            logger.info(f"✓ Collected statistics for {len(counters)} interfaces")
            
        except Exception as e:
            logger.error(f"Failed to get interface counters: {e}")
        
        return counters
    
    def get_bgp_neighbors(self):
        """Get BGP neighbor information"""
        bgp_data = {"global": {"router_id": "", "peers": {}}}
        
        try:
            bgp_filter = """
            <filter>
                <bgp-state-data xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-bgp-oper">
                    <neighbors/>
                </bgp-state-data>
            </filter>
            """
            
            reply = self.device.get(filter=bgp_filter).data_xml
            tree = ETREE.fromstring(reply)
            
            for neighbor in tree.xpath('.//bgp:neighbor', namespaces=NS):
                neighbor_id = self._find_text(neighbor, './bgp:neighbor-id', '', NS)
                if not neighbor_id:
                    continue
                
                connection_state = self._find_text(neighbor, './bgp:connection-state', '', NS)
                
                bgp_data["global"]["peers"][neighbor_id] = {
                    "local_as": int(self._find_text(neighbor, './bgp:local-as', '0', NS)),
                    "remote_as": int(self._find_text(neighbor, './bgp:remote-as', '0', NS)),
                    "is_up": connection_state == "bgp-st-established",
                    "is_enabled": True,
                    "description": self._find_text(neighbor, './bgp:description', '', NS),
                    "uptime": int(self._find_text(neighbor, './bgp:up-time', '0', NS)),
                }
            
            logger.info(f"✓ Collected {len(bgp_data['global']['peers'])} BGP neighbors")
            
        except Exception as e:
            logger.error(f"Failed to get BGP neighbors: {e}")
        
        return bgp_data
    
    def get_environment(self):
        """Get hardware and environment status"""
        environment = {
            "hardware": {},
            "fans": {},
            "temperature": {},
            "power": {},
            "cpu": {},
            "memory": {}
        }
        
        try:
            # Hardware inventory
            hw_filter = """
            <filter>
                <components xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-platform-oper">
                    <component/>
                </components>
            </filter>
            """
            
            reply = self.device.get(filter=hw_filter).data_xml
            tree = ETREE.fromstring(reply)
            
            for comp in tree.xpath('.//platform:component', namespaces=NS):
                name = self._find_text(comp, './platform:name', '', NS)
                if name:
                    environment["hardware"][name] = {
                        "description": self._find_text(comp, './platform:description', '', NS),
                        "model": self._find_text(comp, './platform:part-no', '', NS),
                        "serial_number": self._find_text(comp, './platform:serial-no', '', NS),
                    }
            
            # Environment sensors
            env_filter = """
            <filter>
                <environment-sensors xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-environment-oper">
                    <environment-sensor/>
                </environment-sensors>
            </filter>
            """
            
            reply = self.device.get(filter=env_filter).data_xml
            tree = ETREE.fromstring(reply)
            
            for sensor in tree.xpath('.//env:environment-sensor', namespaces=NS):
                name = self._find_text(sensor, './env:name', '', NS)
                sensor_type = self._find_text(sensor, './env:sensor-type', '', NS)
                state = self._find_text(sensor, './env:state', '', NS)
                
                if 'temp' in sensor_type.lower():
                    current_reading = self._find_text(sensor, './env:current-reading', '0', NS)
                    environment["temperature"][name] = {
                        "temperature": float(current_reading),
                        "is_alert": state != "sensor-state-normal",
                        "is_critical": state == "sensor-state-critical"
                    }
                elif 'fan' in sensor_type.lower():
                    environment["fans"][name] = {
                        "status": state == "sensor-state-normal"
                    }
            
            # CPU
            cpu_filter = """
            <filter>
                <cpu-usage xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-process-cpu-oper">
                    <cpu-utilization/>
                </cpu-usage>
            </filter>
            """
            
            reply = self.device.get(filter=cpu_filter).data_xml
            tree = ETREE.fromstring(reply)
            
            for cpu in tree.xpath('.//process:cpu-utilization', namespaces=NS):
                cpu_id = self._find_text(cpu, './process:cpu-id', '0', NS)
                five_seconds = self._find_text(cpu, './process:five-seconds', '0', NS)
                environment["cpu"][f"CPU{cpu_id}"] = {
                    "%usage": float(five_seconds)
                }
            
            # Memory
            mem_filter = """
            <filter>
                <memory-statistics xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-memory-oper">
                    <memory-statistic/>
                </memory-statistics>
            </filter>
            """
            
            reply = self.device.get(filter=mem_filter).data_xml
            tree = ETREE.fromstring(reply)
            
            for mem in tree.xpath('.//memory:memory-statistic', namespaces=NS):
                total = int(self._find_text(mem, './memory:total-memory', '0', NS))
                used = int(self._find_text(mem, './memory:used-memory', '0', NS))
                
                environment["memory"] = {
                    "available_ram": total,
                    "used_ram": used
                }
                break
            
            logger.info("✓ Environment data collected")
            
        except Exception as e:
            logger.error(f"Failed to get environment: {e}")
        
        return environment
    
    def get_lldp_neighbors(self):
        """Get LLDP neighbors"""
        neighbors = {}
        
        try:
            lldp_filter = """
            <filter>
                <lldp-entries xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-lldp-oper">
                    <lldp-entry/>
                </lldp-entries>
            </filter>
            """
            
            reply = self.device.get(filter=lldp_filter).data_xml
            tree = ETREE.fromstring(reply)
            
            for entry in tree.xpath('.//lldp:lldp-entry', namespaces=NS):
                local_intf = self._find_text(entry, './lldp:local-interface', '', NS)
                if not local_intf:
                    continue
                
                device_id = self._find_text(entry, './lldp:device-id', '', NS)
                port_id = self._find_text(entry, './lldp:port-id', '', NS)
                
                if local_intf not in neighbors:
                    neighbors[local_intf] = []
                
                neighbors[local_intf].append({
                    "hostname": device_id,
                    "port": port_id
                })
            
            logger.info(f"✓ Collected LLDP neighbors on {len(neighbors)} interfaces")
            
        except Exception as e:
            logger.error(f"Failed to get LLDP neighbors: {e}")
        
        return neighbors
    
    def get_arp_table(self):
        """Get ARP table"""
        arp_table = []
        
        try:
            arp_filter = """
            <filter>
                <arp-data xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-arp-oper">
                    <arp-vrf>
                        <arp-oper/>
                    </arp-vrf>
                </arp-data>
            </filter>
            """
            
            reply = self.device.get(filter=arp_filter).data_xml
            tree = ETREE.fromstring(reply)
            
            for entry in tree.xpath('.//arp:arp-oper', namespaces=NS):
                arp_table.append({
                    "interface": self._find_text(entry, './arp:interface', '', NS),
                    "ip": self._find_text(entry, './arp:address', '', NS),
                    "mac": self._find_text(entry, './arp:hardware', '', NS),
                    "age": float(self._find_text(entry, './arp:time', '0', NS))
                })
            
            logger.info(f"✓ Collected {len(arp_table)} ARP entries")
            
        except Exception as e:
            logger.error(f"Failed to get ARP table: {e}")
        
        return arp_table
    
    def get_running_config(self):
        """Get running configuration"""
        try:
            reply = self.device.get_config(source='running')
            config_xml = reply.data_xml
            
            # Convert XML to text format
            tree = ETREE.fromstring(config_xml)
            config_text = ETREE.tostring(tree, pretty_print=True, encoding='unicode')
            
            logger.info("✓ Running configuration retrieved")
            return {"running": config_text}
            
        except Exception as e:
            logger.error(f"Failed to get running config: {e}")
            return {}
    
    def get_comprehensive_audit(self):
        """
        Perform comprehensive device audit
        Returns dict with ALL device information
        """
        audit_results = {
            "timestamp": datetime.now().isoformat(),
            "device": self.hostname,
            "port": self.port,
            "collection_started": datetime.now().isoformat(),
        }
        
        # Define audit sections
        audit_sections = {
            "facts": ("Device Facts", self.get_facts),
            "interfaces": ("Interface Details", self.get_interfaces),
            "interface_counters": ("Interface Statistics", self.get_interface_counters),
            "bgp_neighbors": ("BGP Neighbors", self.get_bgp_neighbors),
            "environment": ("Environment Status", self.get_environment),
            "lldp_neighbors": ("LLDP Neighbors", self.get_lldp_neighbors),
            "arp_table": ("ARP Table", self.get_arp_table),
            "running_config": ("Running Configuration", self.get_running_config),
        }
        
        total_sections = len(audit_sections)
        successful_sections = 0
        failed_sections = []
        
        logger.info("=" * 80)
        logger.info(f"COMPREHENSIVE AUDIT STARTING: {self.hostname}")
        logger.info(f"Total sections: {total_sections}")
        logger.info("=" * 80)
        
        for idx, (section_name, (description, method)) in enumerate(audit_sections.items(), 1):
            try:
                logger.info(f"[{idx}/{total_sections}] Collecting {description}...")
                
                result = method()
                audit_results[section_name] = result
                
                # Log success with data size
                if isinstance(result, dict):
                    item_count = len(result)
                elif isinstance(result, list):
                    item_count = len(result)
                else:
                    item_count = 1
                
                logger.info(f"  ✓ {description}: {item_count} items collected")
                successful_sections += 1
                
            except Exception as e:
                logger.error(f"  ✗ {description} FAILED: {e}")
                audit_results[section_name] = {"error": str(e)}
                failed_sections.append(section_name)
        
        audit_results["collection_completed"] = datetime.now().isoformat()
        
        logger.info("=" * 80)
        logger.info(f"✓ AUDIT COMPLETE: {self.hostname}")
        logger.info(f"  Success: {successful_sections}/{total_sections}")
        if failed_sections:
            logger.warning(f"  Failed: {', '.join(failed_sections)}")
        logger.info("=" * 80)
        
        return audit_results


# Helper function for integration with Flask app
def collect_iosxe_netconf_data(device_info):
    """
    Collect comprehensive audit data from IOS-XE device via NETCONF
    
    Args:
        device_info: dict with keys: ip, username, password, port (optional)
    
    Returns:
        dict with comprehensive audit data
    """
    audit = IOSXENetconfAudit(
        hostname=device_info['ip'],
        username=device_info['username'],
        password=device_info['password'],
        port=device_info.get('port', 830)
    )
    
    try:
        audit.open()
        data = audit.get_comprehensive_audit()
        return data
    finally:
        audit.close()