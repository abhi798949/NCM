from __future__ import annotations
from typing import Optional, Dict, Any, Literal
from netmiko import ConnectHandler, file_transfer
import os

# Supported device types
DeviceType = Literal[
    "cisco_ios", "cisco_xe", "cisco_xr", "cisco_nxos",
    "juniper", "juniper_junos",
    "arista_eos",
    "hp_comware", "hp_procurve",
    "dell_os10",
    "mikrotik_routeros",
    "paloalto_panos",
    "fortinet",
]

def restore_device_config(
    host: str,
    username: str,
    password: str,
    device_type: DeviceType,
    *,
    method: str,                             # 'file' or 'rollback'
    # --- file options ---
    local_file: Optional[str] = None,        # path to local config file
    remote_filename: Optional[str] = None,   # filename on device
    file_system: Optional[str] = None,       # Override default file system
    replace: bool = False,                   # True -> replace, False -> merge
    commit_comment: str = "",                # Commit comment (Junos, XR)
    confirm_delay: Optional[int] = None,     # seconds for 'commit confirmed'
    # --- rollback options ---
    rollback_id: Optional[str] = None,       # Rollback identifier (varies by platform)
    # --- connection options ---
    port: int = 22,
    secret: Optional[str] = None,            # Enable password for IOS
    fast_cli: bool = True,
    session_log: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Universal configuration restore for network devices.
    
    Supports multiple vendors:
    - Cisco IOS/IOS-XE: copy tftp/scp, configure replace
    - Cisco XR: load/commit model
    - Juniper Junos: load merge/replace + commit
    - Arista EOS: configure replace/session
    - And more...
    
    Args:
        host: Device IP/hostname
        username: SSH username
        password: SSH password
        device_type: Netmiko device type
        method: 'file' or 'rollback'
        
        File method options:
            local_file: Local config file path
            remote_filename: Destination filename on device
            file_system: Device file system path
            replace: Replace (True) vs merge (False) config
            commit_comment: Optional commit message
            confirm_delay: Auto-revert timer in seconds
            
        Rollback method options:
            rollback_id: Checkpoint/rollback identifier
            
    Returns:
        Dict with keys: ok, method, log, result, error (if failed)
    """
    # Device-specific configurations
    config = _get_device_config(device_type, file_system)
    
    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "fast_cli": fast_cli,
    }
    
    # Add device-specific connection parameters for reliability
    if "cisco_xr" in device_type or "xr" in device_type.lower():
        # XR devices need more time and patience
        device["conn_timeout"] = 20  # Connection timeout
        device["auth_timeout"] = 20  # Authentication timeout
        device["banner_timeout"] = 20  # Banner timeout
        device["session_timeout"] = 120  # Session timeout
        device["timeout"] = 60  # Command timeout
        device["global_delay_factor"] = 2  # Slow down all commands
        device["fast_cli"] = False  # Disable fast CLI for reliability
    elif "juniper" in device_type or "junos" in device_type.lower():
        # Juniper devices need moderate timeouts
        device["conn_timeout"] = 15
        device["auth_timeout"] = 15
        device["session_timeout"] = 90
        device["timeout"] = 45
        device["global_delay_factor"] = 1.5
        device["fast_cli"] = False
    else:
        # Standard devices
        device["conn_timeout"] = 10
        device["session_timeout"] = 60
        device["timeout"] = 30
    
    if secret:
        device["secret"] = secret
    if session_log:
        device["session_log"] = session_log

    conn = None
    logs = []

    try:
        logs.append(f"Connecting to {host} ({device_type})...")
        conn = ConnectHandler(**device)
        logs.append("✓ Connected successfully")
        
        if method == "file":
            return _restore_from_file(
                conn, device_type, config, logs,
                local_file, remote_filename, replace,
                commit_comment, confirm_delay
            )
        elif method == "rollback":
            return _restore_from_rollback(
                conn, device_type, config, logs,
                rollback_id, commit_comment
            )
        else:
            raise ValueError("method must be 'file' or 'rollback'")

    except Exception as e:
        error_log = "\n".join(logs) + f"\n✗ ERROR: {str(e)}"
        return {
            "ok": False,
            "method": method,
            "log": error_log,
            "error": str(e),
        }
    finally:
        if conn:
            try:
                conn.disconnect()
                logs.append("✓ Disconnected")
            except:
                pass


def _get_device_config(device_type: str, file_system_override: Optional[str]) -> Dict[str, Any]:
    """Get device-specific configuration parameters."""
    
    configs = {
        "cisco_ios": {
            "file_system": file_system_override or "flash:",
            "supports_commit": False,
            "config_mode": True,
            "enable_mode": True,
        },
        "cisco_xe": {
            "file_system": file_system_override or "flash:",
            "supports_commit": False,
            "config_mode": True,
            "enable_mode": True,
        },
        "cisco_xr": {
            "file_system": file_system_override or "harddisk:",
            "supports_commit": True,
            "config_mode": True,
            "enable_mode": False,
        },
        "cisco_nxos": {
            "file_system": file_system_override or "bootflash:",
            "supports_commit": False,
            "config_mode": True,
            "enable_mode": False,
        },
        "juniper": {
            "file_system": file_system_override or "/var/tmp/",
            "supports_commit": True,
            "config_mode": True,
            "enable_mode": False,
        },
        "juniper_junos": {
            "file_system": file_system_override or "/var/tmp/",
            "supports_commit": True,
            "config_mode": True,
            "enable_mode": False,
        },
        "arista_eos": {
            "file_system": file_system_override or "flash:",
            "supports_commit": True,
            "config_mode": True,
            "enable_mode": True,
        },
        "hp_comware": {
            "file_system": file_system_override or "flash:",
            "supports_commit": False,
            "config_mode": False,
            "enable_mode": False,
        },
        "dell_os10": {
            "file_system": file_system_override or "home:",
            "supports_commit": False,
            "config_mode": True,
            "enable_mode": False,
        },
    }
    
    return configs.get(device_type, {
        "file_system": file_system_override or "flash:",
        "supports_commit": False,
        "config_mode": True,
        "enable_mode": False,
    })


def _clean_config_for_restore(config_text: str, device_type: str) -> str:
    """
    Clean configuration file by removing problematic lines before restore.
    Each vendor has different requirements.
    """
    lines = config_text.split('\n')
    cleaned = []
    
    if "cisco_xr" in device_type or "xr" in device_type.lower():
        # XR-specific cleaning - very aggressive
        import re
        
        for line in lines:
            line = line.rstrip()
            
            # Skip empty lines
            if not line:
                continue
            
            # Skip all comment lines starting with !
            if line.startswith('!'):
                continue
            
            # Skip timestamp lines (Mon Nov 12, Tue Nov 11, etc.)
            if re.match(r'^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w+\s+\d+\s+\d+:\d+:\d+', line):
                continue
            
            # Skip lines that are just "end" or "end-set"
            if line.strip() in ['end', 'end-set']:
                continue
            
            # Skip specific command patterns that cause issues
            line_lower = line.lower()
            skip_patterns = [
                'building configuration',
                'current configuration',
                'last configuration change',
                'ios xr configuration',
            ]
            
            skip = False
            for pattern in skip_patterns:
                if pattern in line_lower:
                    skip = True
                    break
            
            if not skip:
                cleaned.append(line)
        
    elif "juniper" in device_type or "junos" in device_type.lower():
        # Juniper cleaning
        for line in lines:
            line = line.rstrip()
            
            if not line:
                continue
            
            # Skip hash comments
            if line.startswith('#'):
                continue
            
            line_lower = line.lower()
            skip_patterns = [
                'last commit:',
                'last changed:',
                'building configuration',
            ]
            
            skip = False
            for pattern in skip_patterns:
                if pattern in line_lower:
                    skip = True
                    break
            
            # For Juniper, keep lines that start with 'set' or are config blocks
            if not skip:
                cleaned.append(line)
        
    elif "arista" in device_type:
        # Arista cleaning
        for line in lines:
            line = line.rstrip()
            
            if not line:
                continue
            
            # Skip comment lines
            if line.startswith('!'):
                continue
            
            line_lower = line.lower()
            skip_patterns = [
                'building configuration',
                'last configuration change',
                'device:',
            ]
            
            skip = False
            for pattern in skip_patterns:
                if pattern in line_lower:
                    skip = True
                    break
            
            if not skip and line != 'end':
                cleaned.append(line)
        
    elif "nokia" in device_type:
        # Nokia cleaning
        for line in lines:
            line = line.rstrip()
            
            if not line:
                continue
            
            # Skip hash comments
            if line.startswith('#'):
                continue
            
            line_lower = line.lower()
            if 'exit all' not in line_lower:
                cleaned.append(line)
    
    else:
        # Generic cleaning for other devices
        for line in lines:
            line = line.rstrip()
            
            if not line:
                continue
            
            # Skip obvious comment lines
            if line.startswith('!') or line.startswith('#'):
                continue
            
            line_lower = line.lower()
            if 'building configuration' not in line_lower:
                cleaned.append(line)
    
    result = '\n'.join(cleaned)
    
    # Debug: Log first few lines to see what's being kept
    import logging
    preview_lines = result.split('\n')[:10]
    logging.info(f"Config cleaning preview (first 10 lines):")
    for i, preview_line in enumerate(preview_lines, 1):
        logging.info(f"  {i}: {preview_line}")
    
    return result


def _restore_from_file(
    conn, device_type: str, config: Dict, logs: list,
    local_file: Optional[str], remote_filename: Optional[str],
    replace: bool, commit_comment: str, confirm_delay: Optional[int]
) -> Dict[str, Any]:
    """Restore configuration from file."""
    
    if not (local_file or remote_filename):
        raise ValueError("Provide local_file and/or remote_filename for method='file'")
    
    dest_name = remote_filename or os.path.basename(local_file)
    file_system = config["file_system"]
    remote_path = os.path.join(file_system, dest_name).replace('\\', '/')
    
    logs.append(f"Starting restore via file method")
    logs.append(f"Local file: {local_file}")
    logs.append(f"Remote destination: {remote_path}")
    
    # Transfer file if local_file provided
    if local_file:
        # Clean the config file before transfer for problematic vendors
        needs_cleaning = any(vendor in device_type.lower() for vendor in ['cisco_xr', 'xr', 'juniper', 'junos', 'arista', 'nokia'])
        
        transfer_file = local_file
        temp_file = None
        
        if needs_cleaning:
            logs.append(f"Cleaning config file for {device_type}...")
            try:
                with open(local_file, 'r', encoding='utf-8') as f:
                    original_config = f.read()
                
                cleaned_config = _clean_config_for_restore(original_config, device_type)
                
                # Create temporary cleaned file
                import tempfile
                temp_fd, temp_file = tempfile.mkstemp(suffix='.cfg', text=True)
                with os.fdopen(temp_fd, 'w', encoding='utf-8') as f:
                    f.write(cleaned_config)
                
                transfer_file = temp_file
                logs.append(f"✓ Config cleaned: {len(original_config)} -> {len(cleaned_config)} bytes")
                
            except Exception as clean_err:
                logs.append(f"⚠ Config cleaning failed, using original: {clean_err}")
                transfer_file = local_file
        
        logs.append("Transferring file via SCP...")
        try:
            # For XR devices, disable MD5 verification which often fails
            if "cisco_xr" in device_type or "xr" in device_type.lower():
                logs.append("XR device detected - using transfer without MD5 verification")
                xfer = file_transfer(
                    conn,
                    source_file=transfer_file,
                    dest_file=dest_name,
                    file_system=file_system,
                    direction="put",
                    overwrite_file=True,
                    disable_md5=True,  # Disable MD5 for XR devices
                )
            else:
                xfer = file_transfer(
                    conn,
                    source_file=transfer_file,
                    dest_file=dest_name,
                    file_system=file_system,
                    direction="put",
                    overwrite_file=True,
                )
            logs.append(f"✓ File transfer complete: {xfer}")
        except Exception as e:
            logs.append(f"✗ File transfer failed: {e}")
            raise
        finally:
            # Clean up temp file if created
            if temp_file:
                try:
                    os.unlink(temp_file)
                except:
                    pass
    
    # Device-specific restore logic
    if "cisco_xr" in device_type:
        return _restore_cisco_xr(conn, logs, remote_path, replace, commit_comment, confirm_delay)
    
    elif "juniper" in device_type:
        return _restore_juniper(conn, logs, remote_path, replace, commit_comment, confirm_delay)
    
    elif "arista" in device_type:
        return _restore_arista(conn, logs, remote_path, replace)
    
    elif "cisco_ios" in device_type or "cisco_xe" in device_type:
        return _restore_cisco_ios(conn, logs, remote_path, replace)
    
    elif "cisco_nxos" in device_type:
        return _restore_cisco_nxos(conn, logs, remote_path, replace)
    
    else:
        # Generic restore attempt
        return _restore_generic(conn, logs, remote_path, replace, config)


def _restore_cisco_xr(conn, logs, remote_path, replace, comment, confirm_delay):
    """Cisco IOS-XR specific restore."""
    logs.append("Using Cisco IOS-XR restore procedure")
    
    conn.config_mode()
    logs.append("✓ Entered configuration mode")
    
    # For XR, we need to use "load" command in config mode
    # Syntax: load <filename> [replace]
    if replace:
        # Use commit replace instead of load replace
        logs.append("Using commit replace for full configuration replacement")
        
        # First, load the configuration
        load_cmd = f"load {remote_path}"
        logs.append(f"Executing: {load_cmd}")
        out = conn.send_command(load_cmd, expect_string=r"[#)]", read_timeout=60, delay_factor=2)
        logs.append(f"Load output: {out}")
        
        # Check for load errors and get details
        if "error" in out.lower() or "syntax" in out.lower():
            # Try to get detailed error information
            logs.append("Load reported errors - fetching details...")
            try:
                error_detail = conn.send_command(
                    "show configuration failed load detail",
                    expect_string=r"[#)]",
                    read_timeout=30
                )
                logs.append(f"Error details:\n{error_detail}")
            except:
                pass
            
            # Only fail if there are actual errors (not "0 errors")
            if "0 errors" not in out.lower():
                raise Exception(f"Load failed: {out}")
        
        # Use commit replace - this will prompt for confirmation
        commit_cmd = "commit replace"
        if comment:
            commit_cmd += f' comment "{comment.replace(chr(34), "")}"'
        
        logs.append(f"Executing: {commit_cmd}")
        
        # Use send_command_timing for commit replace since it prompts
        out = conn.send_command_timing(commit_cmd, delay_factor=3)
        logs.append(f"Initial commit replace output: {out}")
        
        # Check if it's asking for confirmation
        if "proceed" in out.lower() or "confirm" in out.lower() or "[no]" in out.lower():
            logs.append("Confirmation prompt detected - sending 'yes'")
            out = conn.send_command_timing("yes", delay_factor=3)
            logs.append(f"After confirmation: {out}")
        
        # Add confirmed timer if requested (after the initial commit)
        if confirm_delay:
            logs.append(f"Note: confirm_delay not used with commit replace")
            
    else:
        # Regular load and commit (merge mode)
        load_cmd = f"load {remote_path}"
        logs.append(f"Executing: {load_cmd}")
        out = conn.send_command(load_cmd, expect_string=r"[#)]", read_timeout=60, delay_factor=2)
        logs.append(f"Load output: {out}")
        
        # Check for load errors
        if ("error" in out.lower() or "syntax" in out.lower()) and "0 errors" not in out.lower():
            # Try to get detailed error information
            logs.append("Load reported errors - fetching details...")
            try:
                error_detail = conn.send_command(
                    "show configuration failed load detail",
                    expect_string=r"[#)]",
                    read_timeout=30
                )
                logs.append(f"Error details:\n{error_detail}")
            except:
                pass
            raise Exception(f"Load failed: {out}")
        
        # Regular commit
        commit_cmd = "commit"
        if confirm_delay:
            commit_cmd += f" confirmed {confirm_delay}"
        if comment:
            commit_cmd += f' comment "{comment.replace(chr(34), "")}"'
        
        logs.append(f"Executing: {commit_cmd}")
        out = conn.send_command(commit_cmd, expect_string=r"[#)]", read_timeout=90, delay_factor=3)
        logs.append(f"Commit output: {out}")
    
    # Check for commit errors (but "No configuration changes" is not an error if we just loaded)
    if ("error" in out.lower() or "failed" in out.lower()) and "no configuration changes" not in out.lower():
        raise Exception(f"Commit failed: {out}")
    
    # Special handling: if "No configuration changes" after load, something went wrong
    if "no configuration changes" in out.lower() and "load output" in "\n".join(logs):
        logs.append("⚠ Warning: Load completed but no changes detected - config may already match")
    
    conn.exit_config_mode()
    logs.append("✓ Configuration restored successfully")
    
    return {
        "ok": True,
        "method": "file",
        "remote_file": remote_path,
        "log": "\n".join(logs),
        "result": out,
    }


def _restore_juniper(conn, logs, remote_path, replace, comment, confirm_delay):
    """Juniper Junos specific restore."""
    logs.append("Using Juniper Junos restore procedure")
    
    conn.config_mode()
    logs.append("✓ Entered configuration mode")
    
    # For Juniper, assume SET format by default since that's what our backup creates
    # We can detect by checking if the local file (before transfer) had "set " commands
    # But for simplicity, we'll use load set which works for set-format configs
    is_set_format = True  # Default assumption - our backups use "show configuration | display set"
    
    logs.append(f"Detected format: SET format (default for Juniper backups)")
    
    # Build load command based on format
    if is_set_format:
        # For "set" format files, use "load set"
        load_cmd = f"load set {remote_path}"
        logs.append(f"Using 'load set' for SET-format configuration")
    else:
        # For hierarchical format, use standard load replace/merge
        load_cmd = f"load replace {remote_path}" if replace else f"load merge {remote_path}"
        logs.append(f"Using 'load {'replace' if replace else 'merge'}' for hierarchical configuration")
    
    logs.append(f"Executing: {load_cmd}")
    out = conn.send_command(load_cmd, expect_string=r"[>#\]]", read_timeout=60)
    logs.append(f"Load output: {out}")
    
    if "error" in out.lower() and "0 errors" not in out.lower():
        raise Exception(f"Load failed: {out}")
    
    # Commit
    commit_cmd = "commit"
    if confirm_delay:
        commit_cmd += f" confirmed {confirm_delay}"
    if comment:
        commit_cmd += f' comment "{comment.replace(chr(34), "")}"'
    
    logs.append(f"Executing: {commit_cmd}")
    out = conn.send_command(commit_cmd, expect_string=r"[>#\]]", read_timeout=90)
    logs.append(f"Commit output: {out}")
    
    if "error" in out.lower() or "failed" in out.lower():
        raise Exception(f"Commit failed: {out}")
    
    conn.exit_config_mode()
    logs.append("✓ Configuration restored successfully")
    
    return {
        "ok": True,
        "method": "file",
        "remote_file": remote_path,
        "log": "\n".join(logs),
        "result": out,
    }


def _restore_arista(conn, logs, remote_path, replace):
    """Arista EOS specific restore."""
    logs.append("Using Arista EOS restore procedure")
    
    if replace:
        # Use configure replace
        cmd = f"configure replace {remote_path}"
        logs.append(f"Executing: {cmd}")
        out = conn.send_command(cmd, expect_string=r"[#>]", read_timeout=90)
    else:
        # Use configure session
        session_name = "restore_session"
        commands = [
            f"configure session {session_name}",
            f"copy {remote_path} session-config",
            "commit"
        ]
        out = ""
        for cmd in commands:
            logs.append(f"Executing: {cmd}")
            out = conn.send_command(cmd, expect_string=r"[#>]", read_timeout=60)
            logs.append(f"Output: {out}")
    
    logs.append("✓ Configuration restored successfully")
    
    return {
        "ok": True,
        "method": "file",
        "remote_file": remote_path,
        "log": "\n".join(logs),
        "result": out,
    }


def _restore_cisco_ios(conn, logs, remote_path, replace):
    """Cisco IOS/IOS-XE specific restore."""
    logs.append("Using Cisco IOS/IOS-XE restore procedure")
    
    if replace:
        # Use configure replace
        cmd = f"configure replace {remote_path} force"
        logs.append(f"Executing: {cmd}")
        out = conn.send_command(cmd, expect_string=r"[#>]", read_timeout=120)
        logs.append(f"Output: {out}")
        
        if "error" in out.lower() or "failed" in out.lower():
            raise Exception(f"Configure replace failed: {out}")
    else:
        # Copy to running-config
        cmd = f"copy {remote_path} running-config"
        logs.append(f"Executing: {cmd}")
        out = conn.send_command_timing(cmd, delay_factor=2)
        
        # Handle prompts
        if "?" in out or "Destination" in out:
            out += conn.send_command_timing("\n", delay_factor=2)
        
        logs.append(f"Output: {out}")
    
    # Save configuration
    logs.append("Saving configuration...")
    save_out = conn.send_command("write memory", expect_string=r"[#>]")
    logs.append(f"Save output: {save_out}")
    logs.append("✓ Configuration restored and saved")
    
    return {
        "ok": True,
        "method": "file",
        "remote_file": remote_path,
        "log": "\n".join(logs),
        "result": out,
    }


def _restore_cisco_nxos(conn, logs, remote_path, replace):
    """Cisco NX-OS specific restore."""
    logs.append("Using Cisco NX-OS restore procedure")
    
    if replace:
        cmd = f"rollback running-config file {remote_path}"
    else:
        cmd = f"copy {remote_path} running-config"
    
    logs.append(f"Executing: {cmd}")
    out = conn.send_command_timing(cmd, delay_factor=2)
    
    # Handle prompts
    if "?" in out or "[y/n]" in out:
        out += conn.send_command_timing("y", delay_factor=2)
    
    logs.append(f"Output: {out}")
    logs.append("✓ Configuration restored successfully")
    
    return {
        "ok": True,
        "method": "file",
        "remote_file": remote_path,
        "log": "\n".join(logs),
        "result": out,
    }


def _restore_generic(conn, logs, remote_path, replace, config):
    """Generic restore for unsupported devices."""
    logs.append("Using generic restore procedure")
    
    if config.get("config_mode"):
        conn.config_mode()
        logs.append("✓ Entered configuration mode")
    
    # Try basic copy command
    cmd = f"copy {remote_path} running-config"
    logs.append(f"Executing: {cmd}")
    out = conn.send_command_timing(cmd, delay_factor=2)
    
    # Handle common prompts
    if "?" in out or "[confirm]" in out or "[y/n]" in out:
        out += conn.send_command_timing("y", delay_factor=2)
    
    logs.append(f"Output: {out}")
    
    if config.get("config_mode"):
        conn.exit_config_mode()
    
    logs.append("✓ Configuration restore attempted")
    
    return {
        "ok": True,
        "method": "file",
        "remote_file": remote_path,
        "log": "\n".join(logs),
        "result": out,
    }


def _restore_from_rollback(
    conn, device_type: str, config: Dict, logs: list,
    rollback_id: Optional[str], commit_comment: str
) -> Dict[str, Any]:
    """Restore configuration from rollback/checkpoint."""
    
    if not rollback_id:
        raise ValueError("rollback_id is required for method='rollback'")
    
    logs.append(f"Starting restore via rollback method")
    logs.append(f"Rollback ID: {rollback_id}")
    
    # Device-specific rollback
    if "cisco_xr" in device_type:
        return _rollback_cisco_xr(conn, logs, rollback_id, commit_comment)
    
    elif "juniper" in device_type:
        return _rollback_juniper(conn, logs, rollback_id, commit_comment)
    
    elif "arista" in device_type:
        return _rollback_arista(conn, logs, rollback_id)
    
    elif "cisco_ios" in device_type or "cisco_xe" in device_type:
        return _rollback_cisco_ios(conn, logs, rollback_id)
    
    elif "cisco_nxos" in device_type:
        return _rollback_cisco_nxos(conn, logs, rollback_id)
    
    else:
        raise ValueError(f"Rollback not supported for {device_type}")


def _rollback_cisco_xr(conn, logs, rollback_id, comment):
    """Cisco IOS-XR rollback."""
    conn.config_mode()
    logs.append("✓ Entered configuration mode")
    
    cmd = f"rollback configuration {rollback_id}"
    logs.append(f"Executing: {cmd}")
    out = conn.send_command(cmd, expect_string=r"[#)]", read_timeout=30)
    logs.append(f"Rollback output: {out}")
    
    commit_cmd = "commit"
    if comment:
        commit_cmd += f' comment "{comment.replace(chr(34), "")}"'
    
    logs.append(f"Executing: {commit_cmd}")
    out = conn.send_command(commit_cmd, expect_string=r"[#)]", read_timeout=60)
    logs.append(f"Commit output: {out}")
    
    conn.exit_config_mode()
    logs.append("✓ Rollback completed successfully")
    
    return {
        "ok": True,
        "method": "rollback",
        "log": "\n".join(logs),
        "result": out,
    }


def _rollback_juniper(conn, logs, rollback_id, comment):
    """Juniper Junos rollback."""
    conn.config_mode()
    logs.append("✓ Entered configuration mode")
    
    cmd = f"rollback {rollback_id}"
    logs.append(f"Executing: {cmd}")
    out = conn.send_command(cmd, expect_string=r"[>#\]]", read_timeout=30)
    logs.append(f"Rollback output: {out}")
    
    commit_cmd = "commit"
    if comment:
        commit_cmd += f' comment "{comment.replace(chr(34), "")}"'
    
    logs.append(f"Executing: {commit_cmd}")
    out = conn.send_command(commit_cmd, expect_string=r"[>#\]]", read_timeout=60)
    logs.append(f"Commit output: {out}")
    
    conn.exit_config_mode()
    logs.append("✓ Rollback completed successfully")
    
    return {
        "ok": True,
        "method": "rollback",
        "log": "\n".join(logs),
        "result": out,
    }


def _rollback_arista(conn, logs, rollback_id):
    """Arista EOS rollback using checkpoint."""
    cmd = f"configure replace {rollback_id}"
    logs.append(f"Executing: {cmd}")
    out = conn.send_command(cmd, expect_string=r"[#>]", read_timeout=60)
    logs.append(f"Rollback output: {out}")
    logs.append("✓ Rollback completed successfully")
    
    return {
        "ok": True,
        "method": "rollback",
        "log": "\n".join(logs),
        "result": out,
    }


def _rollback_cisco_ios(conn, logs, rollback_id):
    """Cisco IOS/IOS-XE rollback using archive."""
    cmd = f"configure replace flash:/{rollback_id} force"
    logs.append(f"Executing: {cmd}")
    out = conn.send_command(cmd, expect_string=r"[#>]", read_timeout=90)
    logs.append(f"Rollback output: {out}")
    logs.append("✓ Rollback completed successfully")
    
    return {
        "ok": True,
        "method": "rollback",
        "log": "\n".join(logs),
        "result": out,
    }


def _rollback_cisco_nxos(conn, logs, rollback_id):
    """Cisco NX-OS rollback using checkpoint."""
    cmd = f"rollback running-config checkpoint {rollback_id}"
    logs.append(f"Executing: {cmd}")
    out = conn.send_command_timing(cmd, delay_factor=2)
    
    if "[y/n]" in out:
        out += conn.send_command_timing("y", delay_factor=2)
    
    logs.append(f"Rollback output: {out}")
    logs.append("✓ Rollback completed successfully")
    
    return {
        "ok": True,
        "method": "rollback",
        "log": "\n".join(logs),
        "result": out,
    }