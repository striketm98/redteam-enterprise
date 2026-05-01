"""
Credential Engine - Password management and reuse detection
"""

import re
import hashlib
from typing import List, Dict, Set
from collections import defaultdict
from datetime import datetime


class CredentialEngine:
    """Credential management and intelligence engine"""
    
    def __init__(self):
        self.credentials = []
        self.credential_history = []
        self.password_patterns = {
            "weak": r"^(password|admin|123456|qwerty|abc123|12345|12345678|welcome)$",
            "default": r"^(root|admin|user|test|guest|default|changeme)$",
            "company": r"^[A-Za-z]+202[0-9][!@#]?$",
            "seasonal": r"^(Winter|Spring|Summer|Fall)202[0-9]$",
            "keyboard": r"^(qwerty|asdfgh|zxcvbn|1qaz2wsx)$",
            "date": r"^\d{2,4}[-/]\d{2}[-/]\d{2,4}$"
        }
        self.discovered_creds = defaultdict(list)
        self.password_cache = set()
    
    def add_credential(self, username: str, password: str, source: str = "manual", context: str = "") -> Dict:
        """Add discovered credential to database"""
        cred_hash = hashlib.md5(f"{username}:{password}".encode()).hexdigest()
        
        # Check for duplicates
        if cred_hash in self.password_cache:
            return None
        
        cred = {
            "id": len(self.credentials) + 1,
            "user": username,
            "pass": password,
            "hash": cred_hash,
            "source": source,
            "context": context,
            "strength": self.assess_strength(password),
            "reused": False,
            "discovered_at": datetime.now().isoformat()
        }
        
        self.credentials.append(cred)
        self.discovered_creds[username].append(password)
        self.password_cache.add(cred_hash)
        
        self.credential_history.append({
            'action': 'add',
            'credential': cred,
            'timestamp': datetime.now().isoformat()
        })
        
        return cred
    
    def assess_strength(self, password: str) -> str:
        """Assess password strength with detailed scoring"""
        score = 0
        
        # Length check
        if len(password) >= 12:
            score += 3
        elif len(password) >= 8:
            score += 2
        elif len(password) >= 6:
            score += 1
        
        # Complexity checks
        if any(c.isupper() for c in password):
            score += 1
        if any(c.islower() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 2
        
        # Pattern detection (penalties)
        if any(re.match(pattern, password, re.IGNORECASE) for pattern in self.password_patterns.values()):
            score -= 2
        
        # Determine strength
        if score >= 7:
            return "Strong"
        elif score >= 4:
            return "Medium"
        else:
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
                "probability": self._calculate_success_probability(cred),
                "timestamp": datetime.now().isoformat()
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
            "ftp": f"ftp -n {target} <<< 'user {user} {password}'",
            "http": f"curl -u {user}:{password} http://{target}",
            "rdp": f"xfreerdp /v:{target} /u:{user} /p:'{password}'"
        }
        return commands.get(service, f"Unknown service: {service}")
    
    def _calculate_success_probability(self, cred: Dict) -> float:
        """Calculate probability of credential success"""
        base_prob = 0.3
        
        if cred["strength"] == "Weak":
            base_prob += 0.3
        if cred["strength"] == "Medium":
            base_prob += 0.15
        if cred["user"] in ["admin", "root", "administrator", "Administrator"]:
            base_prob += 0.2
        if cred.get("reused", False):
            base_prob += 0.2
        if len(cred["pass"]) < 8:
            base_prob += 0.1
            
        return min(base_prob, 0.95)
    
    def find_password_patterns(self, text: str) -> List[str]:
        """Extract potential passwords from text"""
        found = []
        for pattern_name, pattern in self.password_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                for match in matches:
                    found.append({
                        'pattern': pattern_name,
                        'value': match,
                        'confidence': self._calculate_pattern_confidence(pattern_name)
                    })
        return found
    
    def _calculate_pattern_confidence(self, pattern_name: str) -> float:
        """Calculate confidence for pattern match"""
        confidence = {
            "weak": 0.8,
            "default": 0.9,
            "company": 0.6,
            "seasonal": 0.5,
            "keyboard": 0.7,
            "date": 0.4
        }
        return confidence.get(pattern_name, 0.5)
    
    def analyze_password_policy(self, password_list: List[str]) -> Dict:
        """Analyze password policy from discovered passwords"""
        if not password_list:
            return {'error': 'No passwords to analyze'}
        
        analysis = {
            "total": len(password_list),
            "average_length": sum(len(p) for p in password_list) / len(password_list),
            "has_numbers": sum(1 for p in password_list if any(c.isdigit() for c in p)),
            "has_special": sum(1 for p in password_list if any(c in "!@#$%^&*" for c in p)),
            "has_uppercase": sum(1 for p in password_list if any(c.isupper() for c in p)),
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
        if analysis["has_uppercase"] / analysis["total"] < 0.5:
            analysis["recommendations"].append("Require uppercase letters in passwords")
        
        analysis["strength_distribution"] = {
            "weak": len([p for p in password_list if self.assess_strength(p) == "Weak"]),
            "medium": len([p for p in password_list if self.assess_strength(p) == "Medium"]),
            "strong": len([p for p in password_list if self.assess_strength(p) == "Strong"])
        }
        
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
            "reuse_candidates": [c for c in self.credentials if "admin" in c["user"].lower()],
            "password_lengths": {
                "short": len([c for c in self.credentials if len(c["pass"]) < 8]),
                "medium": len([c for c in self.credentials if 8 <= len(c["pass"]) < 12]),
                "long": len([c for c in self.credentials if len(c["pass"]) >= 12])
            }
        }
    
    def _get_top_users(self, limit: int = 5) -> List[Dict]:
        """Get most common usernames"""
        user_counts = defaultdict(int)
        for cred in self.credentials:
            user_counts[cred["user"]] += 1
        
        top_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        return [{"user": user, "count": count} for user, count in top_users]
    
    def find_similar_passwords(self, password: str) -> List[Dict]:
        """Find similar passwords in the database"""
        similar = []
        for cred in self.credentials:
            # Levenshtein-like similarity check
            if abs(len(cred["pass"]) - len(password)) <= 2:
                if any(char in cred["pass"] for char in password[:3]):
                    similar.append({
                        'user': cred["user"],
                        'password': cred["pass"][:3] + "***",
                        'similarity': self._calculate_similarity(password, cred["pass"])
                    })
        
        return sorted(similar, key=lambda x: x['similarity'], reverse=True)[:5]
    
    def _calculate_similarity(self, pwd1: str, pwd2: str) -> float:
        """Calculate similarity between two passwords"""
        if not pwd1 or not pwd2:
            return 0.0
        
        common = sum(1 for c in set(pwd1) if c in set(pwd2))
        total = len(set(pwd1) | set(pwd2))
        return common / total if total > 0 else 0.0


# Singleton instance
cred_engine = CredentialEngine()