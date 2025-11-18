import os
import json
import requests
from dotenv import load_dotenv

DEFAULT_BUCKET = os.environ.get("INFLUX_BUCKET", "vayuDB1")

def _headers(api_key: str):
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

def _resolve_influx_uid(grafana_url: str, api_key: str, preferred_name: str | None = None) -> str:
    """Resolve InfluxDB datasource UID"""
    env_uid = os.environ.get("GRAFANA_DATASOURCE_UID")
    if env_uid:
        return env_uid

    r = requests.get(f"{grafana_url}/api/datasources", headers=_headers(api_key), timeout=15)
    r.raise_for_status()
    datasources = r.json()
    for ds in datasources:
        if ds.get("type") == "influxdb" and (preferred_name is None or ds.get("name") == preferred_name):
            return ds["uid"]
    raise RuntimeError("No InfluxDB datasource found")

def create_comprehensive_dashboard(grafana_url: str, api_key: str, flux_bucket: str = DEFAULT_BUCKET):
    """Create a comprehensive network device dashboard with all metrics organized by category"""
    datasource_uid = _resolve_influx_uid(grafana_url, api_key)

    dashboard = {
        "dashboard": {
            "id": None,
            "uid": "network-device-dashboard",
            "title": "Network Monitoring - Comprehensive Dashboard",
            "tags": ["network", "devices", "monitoring", "snmp"],
            "timezone": "browser",
            "schemaVersion": 30,
            "version": 0,
            "panels": [
                # Row 1: Device Health Overview
                {
                    "id": 100,
                    "title": "Device Health",
                    "type": "row",
                    "gridPos": {"h": 1, "w": 24, "x": 0, "y": 0},
                    "collapsed": False
                },
                {
                    "id": 1,
                    "title": "Device Reachability",
                    "type": "stat",
                    "gridPos": {"h": 6, "w": 4, "x": 0, "y": 1},
                    "repeat": "device",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r["_measurement"] == "device_health")
  |> filter(fn: (r) => r["device_name"] == "${{device}}")
  |> filter(fn: (r) => r["_field"] == "reachable")
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
  |> yield(name: "mean")
  |> distinct(column: "reachable")
  |> last()
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "mappings": [
                                {
                                    "options": {
                                        "0": {"text": "DOWN", "color": "red", "index": 0},
                                        "1": {"text": "UP", "color": "green", "index": 1}
                                    },
                                    "type": "value"
                                }
                            ],
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "red", "value": None},
                                    {"color": "green", "value": 1}
                                ]
                            },
                            "color": {"mode": "thresholds"}
                        }
                    },
                    "options": {
                        "graphMode": "none",
                        "textMode": "value_and_name"
                    }
                },
                {
                    "id": 2,
                    "title": "CPU Usage",
                    "type": "gauge",
                    "gridPos": {"h": 6, "w": 5, "x": 4, "y": 1},
                    "repeat": "device",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "device_health")
  |> filter(fn: (r) => r.device_name == "${{device}}")
  |> filter(fn: (r) => r._field == "cpu_usage")
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
  |> last()
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "percent",
                            "min": 0,
                            "max": 100,
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 70},
                                    {"color": "red", "value": 90}
                                ]
                            }
                        }
                    },
                    "options": {
                        "showThresholdLabels": True,
                        "showThresholdMarkers": True
                    }
                },
                {
                    "id": 3,
                    "title": "Memory Usage",
                    "type": "gauge",
                    "gridPos": {"h": 6, "w": 5, "x": 9, "y": 1},
                    "repeat": "device",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "device_health")
  |> filter(fn: (r) => r.device_name == "${{device}}")
  |> filter(fn: (r) => r._field == "memory_usage")
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
  |> last()
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "percent",
                            "min": 0,
                            "max": 100,
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 80},
                                    {"color": "red", "value": 95}
                                ]
                            }
                        }
                    },
                    "options": {
                        "showThresholdLabels": True,
                        "showThresholdMarkers": True
                    }
                },
                {
                    "id": 4,
                    "title": "CPU Trend (Last 24h)",
                    "type": "timeseries",
                    "gridPos": {"h": 6, "w": 10, "x": 14, "y": 1},
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: -24h)
  |> filter(fn: (r) => r._measurement == "device_health")
  |> filter(fn: (r) => r.device_name == "${{device}}")
  |> filter(fn: (r) => r._field == "cpu_usage")
  |> aggregateWindow(every: 5m, fn: mean, createEmpty: false)
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "percent",
                            "min": 0,
                            "max": 100,
                            "custom": {
                                "drawStyle": "line",
                                "lineWidth": 2,
                                "fillOpacity": 20,
                                "gradientMode": "hue"
                            },
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 70},
                                    {"color": "red", "value": 90}
                                ]
                            }
                        }
                    }
                },
                # Row 2: Interface Bandwidth
                {
                    "id": 200,
                    "title": "Interface Bandwidth & Traffic",
                    "type": "row",
                    "gridPos": {"h": 1, "w": 24, "x": 0, "y": 7},
                    
                    "collapsed": False
                },
                {
                    "id": 5,
                    "title": "Interface Traffic Rate (bps)",
                    "type": "timeseries",
                    "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8},
                    "repeat": "interface",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "snmp_data")
  |> filter(fn: (r) => r.device_name == "${{device}}")
  |> filter(fn: (r) => r.ifDescr =~ /^${{interface:regex}}$/)
  |> filter(fn: (r) => r.metric == "ifHCInOctets")
  |> filter(fn: (r) => r._field == "value")
  |> derivative(unit: 1s, nonNegative: true)
  |> map(fn: (r) => ({{ r with _value: r._value * 8.0 }}))
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
'''
                        },
                        {
                            "refId": "B",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "snmp_data")
  |> filter(fn: (r) => r.device_name == "${{device}}")
  |> filter(fn: (r) => r.ifDescr =~ /^${{interface:regex}}$/)
  |> filter(fn: (r) => r.metric == "ifHCOutOctets")
  |> filter(fn: (r) => r._field == "value")
  |> derivative(unit: 1s, nonNegative: true)
  |> map(fn: (r) => ({{ r with _value: r._value * 8.0 * 1.0 }}))
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "bps",
                            "custom": {
                                "drawStyle": "line",
                                "lineWidth": 1,
                                "fillOpacity": 10,
                                "gradientMode": "none",
                                "axisPlacement": "auto"
                            }
                        },
                        "overrides": [
                            {
                                "matcher": {"id": "byRegexp", "options": ".*InOctets.*"},
                                "properties": [
                                    {"id": "color", "value": {"mode": "fixed", "fixedColor": "green"}},
                                    {"id": "displayName", "value": "Inbound - ${__field.labels.ifDescr}"}
                                ]
                            },
                            {
                                "matcher": {"id": "byRegexp", "options": ".*OutOctets.*"},
                                "properties": [
                                    {"id": "color", "value": {"mode": "fixed", "fixedColor": "blue"}},
                                    {"id": "displayName", "value": "Outbound - ${__field.labels.ifDescr}"}
                                ]
                            }
                        ]
                    },
                    "options": {
                        "tooltip": {"mode": "multi"},
                        "legend": {"displayMode": "table", "placement": "bottom", "calcs": ["mean", "max", "last"]}
                    }
                },
                {
                    "id": 6,
                    "title": "Interface Utilization (% of Speed)",
                    "type": "timeseries",
                    "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8},
                    "repeat": "interface",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
// Get interface speed
ifSpeed = from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "snmp_data")
  |> filter(fn: (r) => r.device_name == "${{device}}")
  |> filter(fn: (r) => r.ifDescr =~ /^${{interface:regex}}$/)
  |> filter(fn: (r) => r.metric == "ifHCInOctets")
  |> filter(fn: (r) => r._field == "value")
  |> last()
  |> map(fn: (r) => ({{ r with _value: float(v: r.ifHighSpeed) }}))
  |> keep(columns: ["_value", "ifDescr", "device_name"])

// Get inbound traffic and calculate utilization
inTraffic = from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "snmp_data")
  |> filter(fn: (r) => r.device_name == "${{device}}")
  |> filter(fn: (r) => r.ifDescr =~ /^${{interface:regex}}$/)
  |> filter(fn: (r) => r.metric == "ifHCInOctets")
  |> filter(fn: (r) => r._field == "value")
  |> derivative(unit: 1s, nonNegative: true)
  |> map(fn: (r) => ({{ r with _value: r._value * 8.0 }}))

join(tables: {{in: inTraffic, speed: ifSpeed}}, on: ["ifDescr", "device_name"])
  |> map(fn: (r) => ({{ r with _value: (r._value_in / r._value_speed) * 100.0 }}))
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
'''
                        },
                        {
                            "refId": "B",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
// Get interface speed
ifSpeed = from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "snmp_data")
  |> filter(fn: (r) => r.device_name == "${{device}}")
  |> filter(fn: (r) => r.ifDescr =~ /^${{interface:regex}}$/)
  |> filter(fn: (r) => r.metric == "ifHCOutOctets")
  |> filter(fn: (r) => r._field == "value")
  |> last()
  |> map(fn: (r) => ({{ r with _value: float(v: r.ifHighSpeed) }}))
  |> keep(columns: ["_value", "ifDescr", "device_name"])

// Get outbound traffic and calculate utilization
outTraffic = from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "snmp_data")
  |> filter(fn: (r) => r.device_name == "${{device}}")
  |> filter(fn: (r) => r.ifDescr =~ /^${{interface:regex}}$/)
  |> filter(fn: (r) => r.metric == "ifHCOutOctets")
  |> filter(fn: (r) => r._field == "value")
  |> derivative(unit: 1s, nonNegative: true)
  |> map(fn: (r) => ({{ r with _value: r._value * 8.0 }}))

join(tables: {{out: outTraffic, speed: ifSpeed}}, on: ["ifDescr", "device_name"])
  |> map(fn: (r) => ({{ r with _value: (r._value_out / r._value_speed) * 100.0 }}))
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "percent",
                            "min": 0,
                            "max": 100,
                            "custom": {
                                "drawStyle": "line",
                                "lineWidth": 2,
                                "fillOpacity": 20,
                                "gradientMode": "none"
                            },
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 70},
                                    {"color": "red", "value": 90}
                                ]
                            }
                        },
                        "overrides": [
                            {
                                "matcher": {"id": "byFrameRefID", "options": "A"},
                                "properties": [
                                    {"id": "displayName", "value": "In Utilization - ${__field.labels.ifDescr}"},
                                    {"id": "color", "value": {"mode": "fixed", "fixedColor": "green"}}
                                ]
                            },
                            {
                                "matcher": {"id": "byFrameRefID", "options": "B"},
                                "properties": [
                                    {"id": "displayName", "value": "Out Utilization - ${__field.labels.ifDescr}"},
                                    {"id": "color", "value": {"mode": "fixed", "fixedColor": "blue"}}
                                ]
                            }
                        ]
                    },
                    "options": {
                        "tooltip": {"mode": "multi"},
                        "legend": {"displayMode": "table", "placement": "bottom", "calcs": ["mean", "max", "last"]}
                    }
                },
                # Row 3: Interface Packets & Errors
                {
                    "id": 300,
                    "title": "Interface Packets & Errors",
                    "type": "row",
                    "gridPos": {"h": 1, "w": 24, "x": 0, "y": 16},
                    "repeat": "interface",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "collapsed": False
                },
                {
                    "id": 7,
                    "title": "Packet Rate (pps)",
                    "type": "timeseries",
                    "gridPos": {"h": 8, "w": 12, "x": 0, "y": 17},
                    "repeat": "interface",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "snmp_data")
  |> filter(fn: (r) => r.device_name == "${{device}}")
  |> filter(fn: (r) => r.ifDescr =~ /^${{interface:regex}}$/)
  |> filter(fn: (r) => r.metric == "ifInUcastPkts" or r.metric == "ifInNUcastPkts")
  |> filter(fn: (r) => r._field == "value")
  |> derivative(unit: 1s, nonNegative: true)
  |> aggregateWindow(every: v.windowPeriod, fn: sum, createEmpty: false)
'''
                        },
                        {
                            "refId": "B",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "snmp_data")
  |> filter(fn: (r) => r.device_name == "${{device}}")
  |> filter(fn: (r) => r.ifDescr =~ /^${{interface:regex}}$/)
  |> filter(fn: (r) => r.metric == "ifOutUcastPkts" or r.metric == "ifOutNUcastPkts")
  |> filter(fn: (r) => r._field == "value")
  |> derivative(unit: 1s, nonNegative: true)
  |> map(fn: (r) => ({{ r with _value: r._value * 1.0 }}))
  |> aggregateWindow(every: v.windowPeriod, fn: sum, createEmpty: false)
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "pps",
                            "custom": {
                                "drawStyle": "line",
                                "lineWidth": 1,
                                "fillOpacity": 10
                            }
                        },
                        "overrides": [
                            {
                                "matcher": {"id": "byFrameRefID", "options": "A"},
                                "properties": [
                                    {"id": "displayName", "value": "In Packets - ${__field.labels.ifDescr}"},
                                    {"id": "color", "value": {"mode": "fixed", "fixedColor": "green"}}
                                ]
                            },
                            {
                                "matcher": {"id": "byFrameRefID", "options": "B"},
                                "properties": [
                                    {"id": "displayName", "value": "Out Packets - ${__field.labels.ifDescr}"},
                                    {"id": "color", "value": {"mode": "fixed", "fixedColor": "blue"}}
                                ]
                            }
                        ]
                    },
                    "options": {
                        "tooltip": {"mode": "multi"},
                        "legend": {"displayMode": "table", "placement": "bottom", "calcs": ["mean", "max", "last"]}
                    }
                },
                {
                    "id": 8,
                    "title": "Interface Errors & Discards",
                    "type": "timeseries",
                    "gridPos": {"h": 8, "w": 12, "x": 12, "y": 17},
                    "repeat": "interface",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "snmp_data")
  |> filter(fn: (r) => r.device_name == "${{device}}")
  |> filter(fn: (r) => r.ifDescr =~ /^${{interface:regex}}$/)
  |> filter(fn: (r) => r.metric == "ifInErrors" or r.metric == "ifInDiscards")
  |> filter(fn: (r) => r._field == "value")
  |> derivative(unit: 1s, nonNegative: true)
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
'''
                        },
                        {
                            "refId": "B",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "snmp_data")
  |> filter(fn: (r) => r.device_name == "${{device}}")
  |> filter(fn: (r) => r.ifDescr =~ /^${{interface:regex}}$/)
  |> filter(fn: (r) => r.metric == "ifOutErrors" or r.metric == "ifOutDiscards")
  |> filter(fn: (r) => r._field == "value")
  |> derivative(unit: 1s, nonNegative: true)
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "errors/sec",
                            "custom": {
                                "drawStyle": "line",
                                "lineWidth": 2,
                                "fillOpacity": 0
                            },
                            "color": {"mode": "palette-classic"}
                        },
                        "overrides": [
                            {
                                "matcher": {"id": "byRegexp", "options": ".*Errors.*"},
                                "properties": [
                                    {"id": "color", "value": {"mode": "fixed", "fixedColor": "red"}}
                                ]
                            },
                            {
                                "matcher": {"id": "byRegexp", "options": ".*Discards.*"},
                                "properties": [
                                    {"id": "color", "value": {"mode": "fixed", "fixedColor": "orange"}}
                                ]
                            }
                        ]
                    },
                    "options": {
                        "tooltip": {"mode": "multi"},
                        "legend": {"displayMode": "table", "placement": "bottom", "calcs": ["mean", "max", "last"]}
                    }
                },
                # Row 4: Interface Status Table
                {
                    "id": 400,
                    "title": "Interface Status & Configuration",
                    "type": "row",
                    "gridPos": {"h": 1, "w": 24, "x": 0, "y": 25},
                    "repeat": "interface",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "collapsed": False
                },
                {
                    "id": 9,
                    "title": "Interface Status Table",
                    "type": "table",
                    "gridPos": {"h": 8, "w": 24, "x": 0, "y": 26},
                    "repeat": "interface",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "snmp_data")
  |> filter(fn: (r) => r.device_name == "${{device}}")
  |> filter(fn: (r) => r.ifDescr =~ /^${{interface:regex}}$/)
  |> filter(fn: (r) => r.metric == "ifOperStatus" or r.metric == "ifAdminStatus" or r.metric == "ifHighSpeed" or r.metric == "ifType")
  |> filter(fn: (r) => r._field == "value")
  |> last()
  |> keep(columns: ["_time", "ifDescr", "metric", "_value"])
  |> pivot(rowKey: ["ifDescr"], columnKey: ["metric"], valueColumn: "_value")
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {},
                        "overrides": [
                            {
                                "matcher": {"id": "byName", "options": "ifOperStatus"},
                                "properties": [
                                    {"id": "displayName", "value": "Operational Status"},
                                    {"id": "mappings", "value": [
                                        {
                                            "type": "value",
                                            "options": {
                                                "1": {"text": "Up", "color": "green"},
                                                "2": {"text": "Down", "color": "red"},
                                                "3": {"text": "Testing", "color": "yellow"},
                                                "4": {"text": "Unknown", "color": "gray"},
                                                "5": {"text": "Dormant", "color": "orange"},
                                                "6": {"text": "NotPresent", "color": "gray"},
                                                "7": {"text": "LowerLayerDown", "color": "red"}
                                            }
                                        }
                                    ]},
                                    {"id": "custom.cellOptions", "value": {"type": "color-background"}}
                                ]
                            },
                            {
                                "matcher": {"id": "byName", "options": "ifAdminStatus"},
                                "properties": [
                                    {"id": "displayName", "value": "Admin Status"},
                                    {"id": "mappings", "value": [
                                        {
                                            "type": "value",
                                            "options": {
                                                "1": {"text": "Up", "color": "green"},
                                                "2": {"text": "Down", "color": "red"},
                                                "3": {"text": "Testing", "color": "yellow"}
                                            }
                                        }
                                    ]},
                                    {"id": "custom.cellOptions", "value": {"type": "color-background"}}
                                ]
                            },
                            {
                                "matcher": {"id": "byName", "options": "ifHighSpeed"},
                                "properties": [
                                    {"id": "displayName", "value": "Speed (Mbps)"},
                                    {"id": "unit", "value": "Mbits"}
                                ]
                            },
                            {
                                "matcher": {"id": "byName", "options": "ifDescr"},
                                "properties": [
                                    {"id": "displayName", "value": "Interface"}
                                ]
                            }
                        ]
                    },
                    "options": {
                        "showHeader": True,
                        "sortBy": [{"displayName": "Interface", "desc": False}]
                    },
                    "transformations": [
                        {
                            "id": "organize",
                            "options": {
                                "excludeByName": {
                                    "_start": True,
                                    "_stop": True,
                                    "_time": True,
                                    "device_name": True,
                                    "host": True
                                },
                                "indexByName": {
                                    "ifDescr": 0,
                                    "ifOperStatus": 1,
                                    "ifAdminStatus": 2,
                                    "ifHighSpeed": 3,
                                    "ifType": 4
                                }
                            }
                        }
                    ]
                },
                {
                    "id": 500,
                    "title": "RIB Entries (Routes)",
                    "type": "row",
                    "gridPos": {"h": 1, "w": 24, "x": 0, "y": 20},  # Adjust y based on existing panels
                    "collapsed": False
                },
                {
                    "id": 10,
                    "title": "Current RIB Routes",
                    "type": "table",  # Table panel for routes
                    "gridPos": {"h": 10, "w": 24, "x": 0, "y": 21},  # Adjust y
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
                from(bucket: "{flux_bucket}")
                |> range(start: -1h)  // Last hour; adjust as needed
                |> filter(fn: (r) => r._measurement == "rib_entries")
                |> filter(fn: (r) => r.device_name == "${{device}}")
                |> group(columns: ["prefix"])  // Group by prefix to avoid duplicates
                |> last()  // Get latest entries
                |> keep(columns: ["_time", "prefix", "device_name"])  // Add more columns if you parsed more fields
                '''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "custom": {
                                "align": "auto",
                                "width": 150
                            }
                        },
                        "overrides": [
                            {
                                "matcher": {"id": "byName", "options": "prefix"},
                                "properties": [{"id": "displayName", "value": "Route Prefix"}]
                            }
                        ]
                    },
                    "options": {
                        "showHeader": True,
                        "sortBy": [{"displayName": "Route Prefix", "desc": False}]
                    }
                }
            ],
            "time": {
                "from": "now-1h",
                "to": "now"
            },
            "refresh": "30s",
            "templating": {
                "list": [
                    {
                        "name": "device",
                        "label": "Device",
                        "type": "query",
                        "datasource": {"uid": datasource_uid, "type": "influxdb"},
                        "query": f'''
import "influxdata/influxdb/schema"
schema.tagValues(
  bucket: "{flux_bucket}",
  tag: "device_name",
  predicate: (r) => r._measurement == "device_health",
  start: -24h
)
''',
                        "refresh": 1,
                        "includeAll": False,
                        "multi": False,
                        "current": {
                            "selected": False,
                            "text": "Select Device",
                            "value": ""
                        }
                    },
                    {
                        "name": "interface",
                        "label": "Interface",
                        "type": "query",
                        "datasource": {"uid": datasource_uid, "type": "influxdb"},
                        "query": f'''
import "influxdata/influxdb/schema"
schema.tagValues(
  bucket: "{flux_bucket}",
  tag: "ifDescr",
  predicate: (r) => r._measurement == "snmp_data" and r.device_name == "${{device}}",
  start: -24h
)
''',
                        "refresh": 2,
                        "includeAll": True,
                        "multi": True,
                        "current": {
                            "selected": True,
                            "text": "All",
                            "value": "$__all"
                        },
                        "allValue": ".*"
                    }
                ]
            }
        },
        "overwrite": True,
        "message": "Comprehensive Network Device Dashboard - Organized by metric categories"
    }

    r = requests.post(
        f"{grafana_url}/api/dashboards/db",
        headers=_headers(api_key),
        data=json.dumps(dashboard),
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def create_interface_summary_dashboard(grafana_url: str, api_key: str, flux_bucket: str = DEFAULT_BUCKET):
    """Create a high-level interface summary dashboard with key metrics"""
    datasource_uid = _resolve_influx_uid(grafana_url, api_key)

    dashboard = {
        "dashboard": {
            "id": None,
            "uid": "interface-metrics-dashboard",
            "title": "Interface Summary Dashboard",
            "tags": ["network", "interfaces", "summary"],
            "timezone": "browser",
            "schemaVersion": 30,
            "version": 0,
            "panels": [
                # Top Interfaces by Utilization
                {
                    "id": 1,
                    "title": "Top 10 Interfaces by Utilization",
                    "type": "bargauge",
                    "gridPos": {"h": 10, "w": 12, "x": 0, "y": 0},
                    "repeat": "interface",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
// Get interface speed
traffic = from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "snmp_data")
  |> filter(fn: (r) => r.device_name == "${{device}}")
  |> filter(fn: (r) => r.metric == "ifHCInOctets")
  |> filter(fn: (r) => r._field == "value")
  |> filter(fn: (r) => r.ifOperStatus == "1") // Only include interfaces that are up
  |> derivative(unit: 1s, nonNegative: true)
  |> map(fn: (r) => ({{ r with _value: r._value * 8.0 / float(v: r.ifHighSpeed) * 100.0, metric: "In Utilization" }}))

// Aggregate by interface and get max utilization
traffic
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
  |> group(columns: ["ifDescr", "device_name", "metric"])
  |> max()
  |> group()
  |> sort(columns: ["_value"], desc: true)
  |> limit(n: 10)
  |> map(fn: (r) => ({{ r with _value: r._value, _field: r.metric, ifDescr: r.ifDescr }}))
'''
        },
        {
            "refId": "B",
            "datasource": {"uid": datasource_uid, "type": "influxdb"},
            "query": f'''
// Get outbound traffic with speed from tag (already in bps)
traffic = from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "snmp_data")
  |> filter(fn: (r) => r.device_name == "${{device}}")
  |> filter(fn: (r) => r.metric == "ifHCOutOctets")
  |> filter(fn: (r) => r._field == "value")
  |> filter(fn: (r) => r.ifOperStatus == "1") // Only include interfaces that are up
  |> derivative(unit: 1s, nonNegative: true)
  |> map(fn: (r) => ({{ r with _value: r._value * 8.0 / float(v: r.ifHighSpeed) * 100.0, metric: "Out Utilization" }}))

// Aggregate by interface and get max utilization
traffic
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
  |> group(columns: ["ifDescr", "device_name", "metric"])
  |> max()
  |> group()
  |> sort(columns: ["_value"], desc: true)
  |> limit(n: 10)
  |> map(fn: (r) => ({{ r with _value: r._value, _field: r.metric, ifDescr: r.ifDescr }}))
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "percent",
                            "min": 0,
                            "max": 100,
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 70},
                                    {"color": "red", "value": 90}
                                ]
                            },
                            "displayName": "${__field.labels.ifDescr} - ${__field.labels.metric}"
                        }
                    },
                    "overrides": [
                        {
                            "matcher": {"id": "byFrameRefID", "options": "A"},
                            "properties": [
                                {"id": "color", "value": {"mode": "fixed", "fixedColor": "green"}}
                            ]
                        },
                        {
                            "matcher": {"id": "byFrameRefID", "options": "B"},
                            "properties": [
                                {"id": "color", "value": {"mode": "fixed", "fixedColor": "blue"}}
                            ]
                        }
                    ],
                    "options": {
                        "orientation": "horizontal",
                        "displayMode": "gradient",
                        "showUnfilled": True,
                        "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}
                    }
                },
                # Interface Health Matrix
                {
                    "id": 2,
                    "title": "Interface Health Matrix",
                    "type": "state-timeline",
                    "gridPos": {"h": 10, "w": 12, "x": 12, "y": 0},
                    "repeat": "interface",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "snmp_data")
  |> filter(fn: (r) => r.device_name == "${{device}}")
  |> filter(fn: (r) => r.metric == "ifOperStatus")
  |> filter(fn: (r) => r._field == "value")
  |> aggregateWindow(every: v.windowPeriod, fn: last, createEmpty: false)
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "mappings": [
                                {
                                    "type": "value",
                                    "options": {
                                        "1": {"text": "Up", "color": "green"},
                                        "2": {"text": "Down", "color": "red"},
                                        "3": {"text": "Testing", "color": "yellow"},
                                        "4": {"text": "Unknown", "color": "gray"},
                                        "5": {"text": "Dormant", "color": "orange"},
                                        "6": {"text": "NotPresent", "color": "gray"},
                                        "7": {"text": "LowerLayerDown", "color": "red"}
                                    }
                                }
                            ]
                        }
                    }
                },
                # Total Bandwidth Usage
                {
                    "id": 3,
                    "title": "Total Network Bandwidth (All Interfaces)",
                    "type": "BarGauge",
                    "gridPos": {"h": 8, "w": 24, "x": 0, "y": 10},
                    "repeat": "interface",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "snmp_data")
  |> filter(fn: (r) => r.device_name == "${{device}}")
  |> filter(fn: (r) => r.metric == "ifHCInOctets")
  |> filter(fn: (r) => r._field == "value")
  |> derivative(unit: 1s, nonNegative: true)
  |> map(fn: (r) => ({{ r with _value: (r._value * 8.0) / 1000000.0 }})) // Convert to bps
  |> aggregateWindow(every: v.windowPeriod, fn: sum, createEmpty: false)
  |> group()
  |> sum()
'''
                        },
                        {
                            "refId": "B",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "snmp_data")
  |> filter(fn: (r) => r.device_name == "${{device}}")
  |> filter(fn: (r) => r.metric == "ifHCOutOctets")
  |> filter(fn: (r) => r._field == "value")
  |> derivative(unit: 1s, nonNegative: true)
  |> map(fn: (r) => ({{ r with _value: (r._value * 8.0 * 1.0) / 1000000.0 }})) // Convert to bps and make negative for outbound
  |> aggregateWindow(every: v.windowPeriod, fn: sum, createEmpty: false)
  |> group()
  |> sum()
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "bps",
                            "custom": {
                                "drawStyle": "line",
                                "lineWidth": 2,
                                "fillOpacity": 20,
                                "gradientMode": "hue"
                            }
                        },
                        "overrides": [
                            {
                                "matcher": {"id": "byFrameRefID", "options": "A"},
                                "properties": [
                                    {"id": "displayName", "value": "Total Inbound"},
                                    {"id": "color", "value": {"mode": "fixed", "fixedColor": "green"}}
                                ]
                            },
                            {
                                "matcher": {"id": "byFrameRefID", "options": "B"},
                                "properties": [
                                    {"id": "displayName", "value": "Total Outbound"},
                                    {"id": "color", "value": {"mode": "fixed", "fixedColor": "blue"}}
                                ]
                            }
                        ]
                    },
                    "options": {
                        "tooltip": {"mode": "multi"},
                        "legend": {"displayMode": "list", "placement": "bottom", "calcs": ["mean", "max"]}
                    }
                },
                # Error Summary
                {
                    "id": 4,
                    "title": "Total Errors & Discards (All Interfaces)",
                    "type": "stat",
                    "gridPos": {"h": 6, "w": 24, "x": 0, "y": 18},
                    "repeat": "interface",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "snmp_data")
  |> filter(fn: (r) => r.device_name == "${{device}}")
  |> filter(fn: (r) => r.metric == "ifInErrors" or r.metric == "ifOutErrors")
  |> filter(fn: (r) => r._field == "value")
  |> group()
  |> sum()
  |> map(fn: (r) => ({{ r with _value: r._value }}))
'''
                        },
                        {
                            "refId": "B",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "snmp_data")
  |> filter(fn: (r) => r.device_name == "${{device}}")
  |> filter(fn: (r) => r.metric == "ifInDiscards" or r.metric == "ifOutDiscards")
  |> filter(fn: (r) => r._field == "value")
  |> group()
  |> sum()
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 100},
                                    {"color": "red", "value": 1000}
                                ]
                            },
                            "color": {"mode": "thresholds"}
                        },
                        "overrides": [
                            {
                                "matcher": {"id": "byFrameRefID", "options": "A"},
                                "properties": [
                                    {"id": "displayName", "value": "Total Errors"}
                                ]
                            },
                            {
                                "matcher": {"id": "byFrameRefID", "options": "B"},
                                "properties": [
                                    {"id": "displayName", "value": "Total Discards"}
                                ]
                            }
                        ]
                    },
                    "options": {
                        "graphMode": "area",
                        "textMode": "value_and_name",
                        "colorMode": "background"
                    }
                }
            ],
            "time": {
                "from": "now-6h",
                "to": "now"
            },
            "refresh": "1m",
            "templating": {
                "list": [
                    {
                        "name": "device",
                        "label": "Device",
                        "type": "query",
                        "datasource": {"uid": datasource_uid, "type": "influxdb"},
                        "query": f'''
import "influxdata/influxdb/schema"
schema.tagValues(
  bucket: "{flux_bucket}",
  tag: "device_name",
  predicate: (r) => r._measurement == "snmp_data",
  start: -24h
)
''',
                        "refresh": 1,
                        "includeAll": False,
                        "multi": False,
                        "current": {
                            "selected": False,
                            "text": "Select Device",
                            "value": ""
                        }
                    }
                ]
            }
        },
        "overwrite": True,
        "message": "Interface Summary Dashboard with aggregated metrics"
    }

    r = requests.post(
        f"{grafana_url}/api/dashboards/db",
        headers=_headers(api_key),
        data=json.dumps(dashboard),
        timeout=30,
    )
    r.raise_for_status()
    return r.json()
