"""
Tools Routes - Available security tools and their configurations
"""

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
import subprocess
import json
import os
from datetime import datetime

tools_bp = Blueprint('tools', __name__)

# Available tools configuration
AVAILABLE_TOOLS = {
    "nmap": {
        "name": "Nmap",
        "version": "7.94",
        "description": "Network discovery and security scanning",
        "category": "network",
        "commands": {
            "quick": "nmap -F {target}",
            "full": "nmap -p- -sV -sC -O {target}",
            "vuln": "nmap --script vuln {target}",
            "os": "nmap -O {target}",
            "udp": "nmap -sU --top-ports 100 {target}"
        },
        "options": [
            {"flag": "-sV", "description": "Version detection"},
            {"flag": "-sC", "description": "Default scripts"},
            {"flag": "-O", "description": "OS detection"},
            {"flag": "-p-", "description": "All ports"},
            {"flag": "--script", "description": "Script scanning"}
        ]
    },
    "gobuster": {
        "name": "Gobuster",
        "version": "3.6",
        "description": "Directory and DNS brute-forcing tool",
        "category": "web",
        "commands": {
            "dir": "gobuster dir -u {url} -w {wordlist}",
            "dns": "gobuster dns -d {domain} -w {wordlist}",
            "vhost": "gobuster vhost -u {url} -w {wordlist}"
        },
        "wordlists": [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/rockyou.txt"
        ]
    },
    "nikto": {
        "name": "Nikto",
        "version": "2.5.0",
        "description": "Web server vulnerability scanner",
        "category": "web",
        "commands": {
            "basic": "nikto -h {target}",
            "ssl": "nikto -h https://{target} -ssl",
            "evasion": "nikto -h {target} -evasion 1"
        }
    },
    "hydra": {
        "name": "Hydra",
        "version": "9.5",
        "description": "Password brute-forcing tool",
        "category": "auth",
        "commands": {
            "ssh": "hydra -l {user} -P {wordlist} ssh://{target}",
            "ftp": "hydra -L {userlist} -P {wordlist} ftp://{target}",
            "http": "hydra -l {user} -P {wordlist} http-post-form \"{url}:{params}\""
        }
    },
    "sqlmap": {
        "name": "SQLmap",
        "version": "1.7",
        "description": "SQL injection detection and exploitation",
        "category": "web",
        "commands": {
            "basic": "sqlmap -u {url} --batch",
            "db": "sqlmap -u {url} --dbs",
            "tables": "sqlmap -u {url} -D {database} --tables",
            "dump": "sqlmap -u {url} -D {database} -T {table} --dump"
        }
    },
    "metasploit": {
        "name": "Metasploit",
        "version": "6.3",
        "description": "Exploitation framework",
        "category": "exploit",
        "commands": {
            "console": "msfconsole",
            "search": "msfconsole -q -x 'search {module}; exit'",
            "resource": "msfconsole -r {script}"
        }
    },
    "whatweb": {
        "name": "WhatWeb",
        "version": "0.5.5",
        "description": "Web technology fingerprinting",
        "category": "web",
        "commands": {
            "basic": "whatweb {target}",
            "aggressive": "whatweb -a 3 {target}",
            "verbose": "whatweb -v {target}"
        }
    },
    "wpscan": {
        "name": "WPScan",
        "version": "3.8",
        "description": "WordPress vulnerability scanner",
        "category": "web",
        "commands": {
            "basic": "wpscan --url {target}",
            "enumerate": "wpscan --url {target} --enumerate u,vp",
            "api": "wpscan --url {target} --api-token {token}"
        }
    },
    "enum4linux": {
        "name": "Enum4linux",
        "version": "0.8.9",
        "description": "Windows/Linux enumeration tool",
        "category": "network",
        "commands": {
            "basic": "enum4linux {target}",
            "all": "enum4linux -a {target}",
            "users": "enum4linux -U {target}"
        }
    },
    "hydra": {
        "name": "Hydra",
        "version": "9.5",
        "description": "Password brute-forcing tool",
        "category": "auth",
        "commands": {
            "ssh": "hydra -l {user} -P {wordlist} ssh://{target}",
            "ftp": "hydra -L {userlist} -P {wordlist} ftp://{target}",
            "rdp": "hydra -l {user} -P {wordlist} rdp://{target}",
            "smb": "hydra -l {user} -P {wordlist} smb://{target}",
            "mysql": "hydra -l {user} -P {wordlist} mysql://{target}",
            "postgres": "hydra -l {user} -P {wordlist} postgresql://{target}"
        }
    },
    "aircrack": {
        "name": "Aircrack-ng",
        "version": "1.7",
        "description": "Wireless network security tool",
        "category": "wireless",
        "commands": {
            "monitor": "airmon-ng start {interface}",
            "capture": "airodump-ng {interface}",
            "crack": "aircrack-ng {capture_file} -w {wordlist}"
        }
    },
    "john": {
        "name": "John the Ripper",
        "version": "1.9",
        "description": "Password hash cracking tool",
        "category": "auth",
        "commands": {
            "basic": "john {hash_file}",
            "format": "john --format={format} {hash_file}",
            "wordlist": "john --wordlist={wordlist} {hash_file}"
        }
    },
    "burp": {
        "name": "Burp Suite",
        "version": "2023.12",
        "description": "Web vulnerability scanner and proxy",
        "category": "web",
        "commands": {
            "cli": "/opt/burpsuite/burpsuite --project-file={project}"
        }
    }
}


@tools_bp.route('/tools', methods=['GET'])
@login_required
def list_tools():
    """List all available security tools"""
    category = request.args.get('category', 'all')
    
    if category == 'all':
        tools = AVAILABLE_TOOLS
    else:
        tools = {name: config for name, config in AVAILABLE_TOOLS.items() 
                if config.get('category') == category}
    
    return jsonify({
        'total': len(tools),
        'category': category,
        'tools': tools
    })


@tools_bp.route('/tools/categories', methods=['GET'])
@login_required
def get_tool_categories():
    """Get tool categories"""
    categories = {}
    for tool_name, tool_config in AVAILABLE_TOOLS.items():
        category = tool_config.get('category', 'other')
        if category not in categories:
            categories[category] = []
        categories[category].append(tool_name)
    
    return jsonify({
        'categories': categories,
        'counts': {cat: len(tools) for cat, tools in categories.items()}
    })


@tools_bp.route('/tools/<tool_name>', methods=['GET'])
@login_required
def get_tool_info(tool_name):
    """Get detailed information about a specific tool"""
    if tool_name not in AVAILABLE_TOOLS:
        return jsonify({'error': f'Tool "{tool_name}" not found'}), 404
    
    tool_info = AVAILABLE_TOOLS[tool_name].copy()
    
    # Check if tool is installed
    tool_info['installed'] = check_tool_installed(tool_name)
    tool_info['path'] = get_tool_path(tool_name) if tool_info['installed'] else None
    
    return jsonify(tool_info)


@tools_bp.route('/tools/<tool_name>/run', methods=['POST'])
@login_required
def run_tool(tool_name):
    """Execute a security tool (pentest only)"""
    if current_user.role != 'pentest':
        return jsonify({'error': 'Only pentesters can run security tools'}), 403
    
    if tool_name not in AVAILABLE_TOOLS:
        return jsonify({'error': f'Tool "{tool_name}" not found'}), 404
    
    data = request.json
    command_type = data.get('command', 'basic')
    target = data.get('target')
    options = data.get('options', {})
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    tool_config = AVAILABLE_TOOLS[tool_name]
    
    if command_type not in tool_config.get('commands', {}):
        return jsonify({'error': f'Command type "{command_type}" not available for {tool_name}'}), 400
    
    # Build command
    command_template = tool_config['commands'][command_type]
    command = command_template.format(target=target, **options)
    
    # Execute command
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        return jsonify({
            'success': True,
            'tool': tool_name,
            'command': command,
            'target': target,
            'output': result.stdout,
            'error': result.stderr,
            'return_code': result.returncode,
            'executed_at': datetime.now().isoformat()
        })
    
    except subprocess.TimeoutExpired:
        return jsonify({
            'success': False,
            'error': f'Command timed out after 300 seconds'
        }), 408
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@tools_bp.route('/tools/wordlists', methods=['GET'])
@login_required
def get_wordlists():
    """Get available wordlists"""
    wordlists = []
    
    # Common wordlist locations
    wordlist_paths = [
        '/usr/share/wordlists/rockyou.txt',
        '/usr/share/wordlists/dirb/common.txt',
        '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
        '/usr/share/wordlists/fasttrack.txt',
        '/usr/share/wordlists/metasploit/unix_passwords.txt'
    ]
    
    for path in wordlist_paths:
        if os.path.exists(path):
            size = os.path.getsize(path) / (1024 * 1024)  # Size in MB
            wordlists.append({
                'path': path,
                'name': os.path.basename(path),
                'size_mb': round(size, 2),
                'lines': count_lines(path) if size < 10 else 'N/A'
            })
    
    return jsonify({
        'wordlists': wordlists,
        'total': len(wordlists)
    })


@tools_bp.route('/tools/install/<tool_name>', methods=['POST'])
@login_required
def install_tool(tool_name):
    """Install a security tool (admin only)"""
    if current_user.role != 'pentest':
        return jsonify({'error': 'Only pentesters can install tools'}), 403
    
    # Installation commands for common tools
    install_commands = {
        'gobuster': 'apt-get update && apt-get install -y gobuster',
        'nikto': 'apt-get update && apt-get install -y nikto',
        'hydra': 'apt-get update && apt-get install -y hydra',
        'sqlmap': 'apt-get update && apt-get install -y sqlmap',
        'whatweb': 'apt-get update && apt-get install -y whatweb',
        'wpscan': 'gem install wpscan',
        'enum4linux': 'apt-get update && apt-get install -y enum4linux'
    }
    
    if tool_name not in install_commands:
        return jsonify({'error': f'No installation instruction for {tool_name}'}), 400
    
    try:
        result = subprocess.run(
            install_commands[tool_name],
            shell=True,
            capture_output=True,
            text=True,
            timeout=600
        )
        
        return jsonify({
            'success': result.returncode == 0,
            'tool': tool_name,
            'output': result.stdout,
            'error': result.stderr
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@tools_bp.route('/tools/scan', methods=['POST'])
@login_required
def multi_tool_scan():
    """Run multiple tools against a target (pentest only)"""
    if current_user.role != 'pentest':
        return jsonify({'error': 'Only pentesters can run multi-tool scans'}), 403
    
    data = request.json
    target = data.get('target')
    tools = data.get('tools', [])  # List of tool names to run
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    results = {}
    
    for tool_name in tools:
        if tool_name in AVAILABLE_TOOLS:
            tool_config = AVAILABLE_TOOLS[tool_name]
            command_type = list(tool_config.get('commands', {}).keys())[0]
            
            try:
                command = tool_config['commands'][command_type].format(target=target)
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=180
                )
                
                results[tool_name] = {
                    'success': result.returncode == 0,
                    'output': result.stdout[:5000],  # Limit output
                    'error': result.stderr[:500]
                }
            
            except Exception as e:
                results[tool_name] = {
                    'success': False,
                    'error': str(e)
                }
    
    return jsonify({
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'results': results
    })


def check_tool_installed(tool_name: str) -> bool:
    """Check if a tool is installed on the system"""
    try:
        result = subprocess.run(
            f'which {tool_name}',
            shell=True,
            capture_output=True,
            text=True
        )
        return result.returncode == 0 and result.stdout.strip() != ''
    except:
        return False


def get_tool_path(tool_name: str) -> str:
    """Get the path of an installed tool"""
    try:
        result = subprocess.run(
            f'which {tool_name}',
            shell=True,
            capture_output=True,
            text=True
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except:
        return None


def count_lines(filepath: str) -> int:
    """Count lines in a file (for large files, return estimate)"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return sum(1 for _ in f)
    except:
        return 0


@tools_bp.route('/tools/validate', methods=['POST'])
@login_required
def validate_tool_command():
    """Validate a custom tool command before execution"""
    data = request.json
    command = data.get('command')
    
    # Check for dangerous commands
    dangerous_patterns = [
        'rm -rf', 'dd if=', 'mkfs', ':(){', 'fork bomb',
        '> /dev/sda', 'mkfs.ext4', 'format', 'del /f'
    ]
    
    for pattern in dangerous_patterns:
        if pattern in command.lower():
            return jsonify({
                'valid': False,
                'reason': f'Dangerous pattern detected: {pattern}'
            }), 400
    
    # Check if command starts with allowed prefix
    allowed_prefixes = ['nmap', 'gobuster', 'nikto', 'hydra', 'sqlmap', 'whatweb', 'wpscan']
    
    command_prefix = command.split()[0].lower()
    if command_prefix not in allowed_prefixes:
        return jsonify({
            'valid': False,
            'reason': f'Tool "{command_prefix}" is not in allowed list'
        }), 400
    
    return jsonify({'valid': True, 'reason': 'Command appears safe'})


@tools_bp.route('/tools/suggest', methods=['POST'])
@login_required
def suggest_tools():
    """Suggest tools based on target type"""
    data = request.json
    target = data.get('target')
    scan_results = data.get('scan_results', {})
    
    suggestions = []
    
    # Analyze scan results to suggest tools
    open_ports = scan_results.get('open_ports', [])
    
    if 80 in open_ports or 443 in open_ports or 8080 in open_ports:
        suggestions.append({
            'tool': 'nikto',
            'reason': 'Web server detected - web vulnerability scan recommended'
        })
        suggestions.append({
            'tool': 'gobuster',
            'reason': 'Web server detected - directory enumeration recommended'
        })
        suggestions.append({
            'tool': 'whatweb',
            'reason': 'Web server detected - technology fingerprinting'
        })
    
    if 22 in open_ports:
        suggestions.append({
            'tool': 'hydra',
            'reason': 'SSH port open - password brute-forcing possible'
        })
    
    if 3306 in open_ports or 5432 in open_ports:
        suggestions.append({
            'tool': 'sqlmap',
            'reason': 'Database port open - SQL injection testing'
        })
    
    if 445 in open_ports or 139 in open_ports:
        suggestions.append({
            'tool': 'enum4linux',
            'reason': 'SMB port open - Windows/Linux enumeration'
        })
    
    return jsonify({
        'target': target,
        'suggestions': suggestions,
        'total_suggestions': len(suggestions)
    })