import re
import logging
from typing import List, Dict, Tuple
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ExploitMatcher:
    def __init__(self):
        self.exploit_db = {
            # Web exploits
            "struts2": {
                "pattern": r"struts2|struts 2|S2-\d+",
                "cves": ["CVE-2017-5638", "CVE-2018-11776"],
                "exploits": ["exploit/multi/http/struts2_content_type_ognl"],
                "risk": "Critical"
            },
            "drupal": {
                "pattern": r"drupal|Drupal \d+",
                "cves": ["CVE-2018-7600", "CVE-2019-6340"],
                "exploits": ["exploit/multi/http/drupal_drupageddon"],
                "risk": "High"
            },
            
            # SMB exploits
            "eternalblue": {
                "pattern": r"SMBv1|Windows (7|2008|Vista)",
                "cves": ["CVE-2017-0144"],
                "exploits": ["exploit/windows/smb/ms17_010_eternalblue"],
                "risk": "Critical"
            },
            "smbghost": {
                "pattern": r"SMBv3", 
                "cves": ["CVE-2020-0796"],
                "exploits": ["exploit/windows/smb/cve_2020_0796_smbghost"],
                "risk": "Critical"
            },
            
            # SSH exploits
            "ssh_weak": {
                "pattern": r"SSH-\d+\.\d+",
                "cves": [],
                "exploits": ["ssh_bruteforce", "ssh_pubkey"],
                "risk": "Medium"
            },
            
            # Linux privilege escalation
            "dirtycow": {
                "pattern": r"Linux (2\.6\.22|3\.|4\.[0-8])\.",
                "cves": ["CVE-2016-5195"],
                "exploits": ["exploit/linux/local/dirtycow"],
                "risk": "High"
            }
        }
        
        self.match_history = []
    
    def match_exploits(self, service: str, version: str, banner: str) -> List[Dict]:
        """Match exploits based on service information"""
        matches = []
        
        for exploit_name, exploit_info in self.exploit_db.items():
            if re.search(exploit_info["pattern"], f"{service} {version} {banner}", re.IGNORECASE):
                match = {
                    "exploit": exploit_name,
                    "cves": exploit_info["cves"],
                    "risk": exploit_info["risk"],
                    "recommended": exploit_info["exploits"],
                    "confidence": self._calculate_confidence(exploit_name, version),
                    "timestamp": datetime.now().isoformat()
                }
                matches.append(match)
                logger.info(f"Exploit match found: {exploit_name}")
        
        return sorted(matches, key=lambda x: (
            x["risk"] == "Critical",
            x["risk"] == "High",
            x["confidence"]
        ), reverse=True)
    
    def _calculate_confidence(self, exploit_name: str, version: str) -> float:
        """Calculate confidence in exploit match"""
        confidence_map = {
            "eternalblue": 0.95,
            "smbghost": 0.9,
            "dirtycow": 0.85,
            "struts2": 0.8,
            "drupal": 0.75,
            "ssh_weak": 0.5
        }
        
        base_confidence = confidence_map.get(exploit_name, 0.5)
        
        # Adjust based on version specificity
        if version and version != "unknown":
            base_confidence += 0.1
            
        return min(base_confidence, 0.98)
    
    def get_exploit_details(self, exploit_name: str) -> Dict:
        """Get detailed information about specific exploit"""
        if exploit_name in self.exploit_db:
            return {
                "name": exploit_name,
                **self.exploit_db[exploit_name],
                "steps": self._get_exploitation_steps(exploit_name)
            }
        return {"error": "Exploit not found"}
    
    def _get_exploitation_steps(self, exploit_name: str) -> List[str]:
        """Get exploitation steps for specific exploit"""
        steps_map = {
            "eternalblue": [
                "1. Verify SMBv1 is enabled",
                "2. Check if port 445 is open and accessible",
                "3. Run msfconsole and use eternalblue module",
                "4. Set RHOSTS, LHOST, and LPORT",
                "5. Execute exploit and gain SYSTEM access"
            ],
            "struts2": [
                "1. Identify Struts2 version and framework",
                "2. Test for vulnerability using OGNL injection",
                "3. Use metasploit module for automatic exploitation",
                "4. Execute command injection to gain RCE"
            ],
            "dirtycow": [
                "1. Verify kernel version vulnerability",
                "2. Download dirtycow exploit to target",
                "3. Compile gcc -pthread dirtycow.c -o dirtycow",
                "4. Run ./dirtycow and wait for root shell"
            ]
        }
        return steps_map.get(exploit_name, ["Manual exploitation required - research accordingly"])
    
    def suggest_mitigations(self, exploit_name: str) -> List[str]:
        """Suggest mitigations for discovered exploits"""
        mitigation_map = {
            "eternalblue": [
                "Apply MS17-010 security patch immediately",
                "Disable SMBv1 on all systems",
                "Block SMB ports (445, 139) at firewall"
            ],
            "smbghost": [
                "Install Windows update KB4551762",
                "Disable SMBv3 compression",
                "Set registry key: HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
            ],
            "dirtycow": [
                "Update Linux kernel to latest version",
                "Apply kernel patches for CVE-2016-5195",
                "Use kernel same-page merging (KSM) mitigation"
            ]
        }
        return mitigation_map.get(exploit_name, ["Update to latest version", "Apply security patches"])