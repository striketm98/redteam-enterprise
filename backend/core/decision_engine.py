"""
Decision Engine - AI-powered decision making for penetration testing
"""

from typing import Dict, List, Any
from datetime import datetime


class DecisionEngine:
    """Intelligent decision engine for suggesting next steps"""
    
    def __init__(self):
        self.decision_history = []
        self.context = {
            "foothold": False,
            "ports": [],
            "creds": [],
            "services": {},
            "priv_level": "none",
            "targets": [],
            "scan_results": {}
        }
    
    def update_context(self, new_context: Dict[str, Any]):
        """Update the current context with new information"""
        self.context.update(new_context)
        self.decision_history.append({
            'timestamp': datetime.now().isoformat(),
            'action': 'context_update',
            'context': self.context.copy()
        })
    
    def decide(self, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Make intelligent decision based on current context"""
        if context:
            self.update_context(context)
        
        decision = {
            "action": "",
            "priority": 0,
            "reasoning": "",
            "commands": [],
            "timestamp": datetime.now().isoformat()
        }
        
        # Phase 1: Initial enumeration phase
        if not self.context.get("foothold", False):
            if 80 in self.context.get("ports", []) or 443 in self.context.get("ports", []):
                decision["action"] = "web_attack"
                decision["priority"] = 90
                decision["reasoning"] = "Web services present - highest probability for initial access"
                decision["commands"] = [
                    "nmap -sV -p 80,443 --script=http-enum {target}",
                    "gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt",
                    "nikto -h http://{target}"
                ]
                return decision
            
            if 445 in self.context.get("ports", []):
                decision["action"] = "smb_enumeration"
                decision["priority"] = 85
                decision["reasoning"] = "SMB service available - potential for credential harvesting"
                decision["commands"] = [
                    "enum4linux -a {target}",
                    "smbclient -L //{target} -N",
                    "nmap -p 445 --script smb-vuln* {target}"
                ]
                return decision
            
            if 22 in self.context.get("ports", []):
                decision["action"] = "ssh_bruteforce"
                decision["priority"] = 70
                decision["reasoning"] = "SSH available - will attempt credential reuse"
                decision["commands"] = self._get_ssh_commands()
                return decision
        
        # Phase 2: Credential reuse phase
        if self.context.get("creds") and not self.context.get("foothold"):
            decision["action"] = "credential_reuse"
            decision["priority"] = 95
            decision["reasoning"] = f"Found {len(self.context['creds'])} credentials - high probability of lateral movement"
            decision["commands"] = self._get_reuse_commands()
            return decision
        
        # Phase 3: Privilege escalation phase
        if self.context.get("foothold") and self.context.get("priv_level") != "root":
            decision["action"] = "privesc"
            decision["priority"] = 100
            decision["reasoning"] = "Foothold established - escalate privileges"
            decision["commands"] = [
                "linpeas.sh",
                "sudo -l",
                "find / -perm -4000 2>/dev/null",
                "ps aux | grep root",
                "uname -a"
            ]
            return decision
        
        # Phase 4: Lateral movement
        if self.context.get("priv_level") == "root" and len(self.context.get("targets", [])) > 1:
            decision["action"] = "lateral_movement"
            decision["priority"] = 80
            decision["reasoning"] = "Root access achieved - move laterally"
            decision["commands"] = self._get_lateral_commands()
            return decision
        
        # Default: Re-enumerate
        decision["action"] = "reconnaissance"
        decision["priority"] = 50
        decision["reasoning"] = "No clear path - perform deeper enumeration"
        decision["commands"] = [
            "nmap -sC -sV -p- {target}",
            "nikto -h http://{target}",
            "whatweb http://{target}"
        ]
        
        self.decision_history.append(decision)
        return decision
    
    def _get_ssh_commands(self) -> List[str]:
        """Generate SSH attack commands"""
        cmds = []
        for cred in self.context.get("creds", []):
            cmds.append(f"sshpass -p '{cred.get('pass', '')}' ssh {cred.get('user', 'root')}@{self.context.get('target', 'target')}")
        return cmds
    
    def _get_reuse_commands(self) -> List[str]:
        """Generate credential reuse commands"""
        cmds = []
        target = self.context.get('target', 'target')
        for cred in self.context.get("creds", []):
            cmds.append(f"crackmapexec smb {target} -u {cred.get('user', '')} -p '{cred.get('pass', '')}'")
            cmds.append(f"crackmapexec winrm {target} -u {cred.get('user', '')} -p '{cred.get('pass', '')}'")
            cmds.append(f"evil-winrm -i {target} -u {cred.get('user', '')} -p '{cred.get('pass', '')}'")
        return cmds
    
    def _get_lateral_commands(self) -> List[str]:
        """Generate lateral movement commands"""
        target = self.context.get('target', 'target')
        user = self.context.get('current_user', 'administrator')
        password = self.context.get('current_password', '')
        return [
            f"crackmapexec smb {target} -u {user} -p '{password}' --exec whoami",
            f"scp privesc.sh {user}@{target}:/tmp/",
            f"ssh {user}@{target} 'bash /tmp/privesc.sh'"
        ]
    
    def get_decision_history(self) -> List[Dict]:
        """Return decision history for reporting"""
        return self.decision_history
    
    def get_next_step(self) -> Dict:
        """Get the next recommended step"""
        return self.decide()


# Singleton instance
decision_engine = DecisionEngine()