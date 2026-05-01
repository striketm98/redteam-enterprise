"""
Network Topology Templates
Pre-configured multi-container network scenarios for penetration testing practice
"""

NETWORK_TOPOLOGIES = {
    # ============================================
    # BEGINNER LEVEL TOPOLOGIES
    # ============================================
    
    "single_web": {
        "name": "Single Web Server",
        "description": "A single vulnerable web server - perfect for beginners",
        "difficulty": "Beginner",
        "estimated_time": "30-60 minutes",
        "learning_objectives": [
            "Web application enumeration",
            "Directory brute-forcing",
            "SQL injection basics",
            "XSS detection"
        ],
        "services": [
            {
                "name": "dvwa",
                "config": {
                    "ports": {"8080": "80"},
                    "env": {"MYSQL_ROOT_PASSWORD": "root"}
                }
            }
        ],
        "network": "single_web_net",
        "tags": ["web", "beginner", "sql", "xss"]
    },
    
    "web_with_db": {
        "name": "Web Server with Database Backend",
        "description": "Web application connected to vulnerable MySQL database",
        "difficulty": "Beginner",
        "estimated_time": "45-90 minutes",
        "learning_objectives": [
            "Web to database pivot techniques",
            "SQL injection to data extraction",
            "Database privilege escalation"
        ],
        "services": [
            {
                "name": "dvwa",
                "config": {
                    "ports": {"8080": "80"},
                    "env": {"DB_HOST": "mysql_db"}
                }
            },
            {
                "name": "mysql_vuln",
                "config": {
                    "ports": {"3306": "3306"},
                    "env": {"MYSQL_ROOT_PASSWORD": ""}
                }
            }
        ],
        "connections": [
            {"source": "dvwa", "target": "mysql_vuln"}
        ],
        "network": "web_db_net",
        "tags": ["web", "database", "pivot"]
    },
    
    "network_services": {
        "name": "Multiple Network Services",
        "description": "Server with multiple exposed services (SSH, FTP, SMB)",
        "difficulty": "Beginner",
        "estimated_time": "60-90 minutes",
        "learning_objectives": [
            "Service enumeration",
            "Weak credential testing",
            "Lateral movement basics"
        ],
        "services": [
            {
                "name": "metasploitable2",
                "config": {
                    "ports": {
                        "21": "21",    # FTP
                        "22": "22",    # SSH
                        "80": "80",    # HTTP
                        "445": "445",  # SMB
                        "3306": "3306" # MySQL
                    }
                }
            }
        ],
        "network": "network_services_net",
        "tags": ["network", "ssh", "ftp", "smb"]
    },
    
    # ============================================
    # INTERMEDIATE LEVEL TOPOLOGIES
    # ============================================
    
    "two_tier_app": {
        "name": "Two-Tier Application",
        "description": "Frontend web application with backend API server",
        "difficulty": "Intermediate",
        "estimated_time": "90-120 minutes",
        "learning_objectives": [
            "API enumeration and testing",
            "JWT token manipulation",
            "Chained vulnerabilities"
        ],
        "services": [
            {
                "name": "juice_shop",
                "config": {
                    "ports": {"3000": "3000"},
                    "env": {"API_URL": "http://api_server:5000"}
                }
            },
            {
                "name": "webgoat",
                "config": {
                    "ports": {"8080": "8080"},
                    "env": {"SPRING_PROFILES_ACTIVE": "dev"}
                }
            }
        ],
        "connections": [
            {"source": "juice_shop", "target": "webgoat"}
        ],
        "network": "two_tier_net",
        "tags": ["web", "api", "jwt", "intermediate"]
    },
    
    "corporate_dmz": {
        "name": "Corporate DMZ",
        "description": "DMZ with web server, internal database, and jump host",
        "difficulty": "Intermediate",
        "estimated_time": "120-180 minutes",
        "learning_objectives": [
            "Multi-stage exploitation",
            "Pivoting through jump hosts",
            "Internal network enumeration"
        ],
        "services": [
            {
                "name": "dvwa",
                "config": {
                    "ports": {"8080": "80"},
                    "env": {"INTERNAL_DB": "mysql_db"}
                }
            },
            {
                "name": "mysql_vuln",
                "config": {
                    "ports": {"3306": "3306"},
                    "env": {"MYSQL_ROOT_PASSWORD": "secret"}
                }
            },
            {
                "name": "ssh_weak",
                "config": {
                    "ports": {"2222": "22"}
                }
            }
        ],
        "connections": [
            {"source": "dvwa", "target": "mysql_vuln"},
            {"source": "dvwa", "target": "ssh_weak"}
        ],
        "network": "corporate_dmz_net",
        "tags": ["dmz", "pivot", "corporate", "intermediate"]
    },
    
    "active_directory_basics": {
        "name": "Active Directory Basics",
        "description": "Basic AD environment with domain controller and member server",
        "difficulty": "Intermediate",
        "estimated_time": "150-200 minutes",
        "learning_objectives": [
            "AD enumeration",
            "Kerberoasting",
            "SMB relay attacks",
            "BloodHound usage"
        ],
        "services": [
            {
                "name": "ad_light",
                "config": {
                    "ports": {
                        "389": "389",   # LDAP
                        "636": "636",   # LDAPS
                        "445": "445",   # SMB
                        "88": "88"      # Kerberos
                    },
                    "env": {
                        "DOMAIN": "lab.local",
                        "ADMIN_PASSWORD": "P@ssw0rd123"
                    }
                }
            },
            {
                "name": "metasploitable2",
                "config": {
                    "ports": {"22": "22", "445": "445"}
                }
            }
        ],
        "connections": [
            {"source": "ad_light", "target": "metasploitable2"}
        ],
        "network": "ad_basics_net",
        "tags": ["ad", "windows", "kerberos", "ldap"]
    },
    
    # ============================================
    # ADVANCED LEVEL TOPOLOGIES
    # ============================================
    
    "three_tier_enterprise": {
        "name": "Three-Tier Enterprise Application",
        "description": "Complete enterprise architecture: Web → App → Database",
        "difficulty": "Advanced",
        "estimated_time": "180-240 minutes",
        "learning_objectives": [
            "Web to app server pivoting",
            "Database extraction",
            "Chain multiple exploits",
            "Post-exploitation techniques"
        ],
        "services": [
            {
                "name": "webgoat",
                "config": {
                    "ports": {"8080": "8080"},
                    "env": {"APP_SERVER": "app_server:9090"}
                }
            },
            {
                "name": "juice_shop",
                "config": {
                    "ports": {"3000": "3000"},
                    "env": {"BACKEND_DB": "mysql_db:3306"}
                }
            },
            {
                "name": "mysql_vuln",
                "config": {
                    "ports": {"3306": "3306"}
                }
            },
            {
                "name": "postgres_weak",
                "config": {
                    "ports": {"5432": "5432"}
                }
            }
        ],
        "connections": [
            {"source": "webgoat", "target": "juice_shop"},
            {"source": "juice_shop", "target": "mysql_vuln"},
            {"source": "webgoat", "target": "postgres_weak"}
        ],
        "network": "enterprise_net",
        "tags": ["enterprise", "advanced", "pivot", "chained"]
    },
    
    "complete_corporate": {
        "name": "Complete Corporate Network",
        "description": "Realistic corporate network with multiple segments",
        "difficulty": "Advanced",
        "estimated_time": "240-360 minutes",
        "learning_objectives": [
            "Network segmentation bypass",
            "Cross-segment lateral movement",
            "Domain privilege escalation",
            "Full domain compromise"
        ],
        "services": [
            # DMZ Services
            {
                "name": "dvwa",
                "config": {
                    "ports": {"8080": "80"},
                    "env": {"DMZ_MODE": "true"}
                }
            },
            {
                "name": "webgoat",
                "config": {
                    "ports": {"9090": "8080"}
                }
            },
            
            # Internal Servers
            {
                "name": "ad_light",
                "config": {
                    "ports": {
                        "389": "389",
                        "445": "445",
                        "88": "88",
                        "135": "135"
                    },
                    "env": {"DOMAIN": "corp.local"}
                }
            },
            {
                "name": "metasploitable2",
                "config": {
                    "ports": {
                        "21": "21",
                        "22": "22",
                        "445": "445",
                        "3306": "3306"
                    }
                }
            },
            {
                "name": "ssh_weak",
                "config": {
                    "ports": {"2222": "22"}
                }
            },
            
            # Database Tier
            {
                "name": "mysql_vuln",
                "config": {
                    "ports": {"3306": "3306"},
                    "env": {"MYSQL_ROOT_PASSWORD": "root"}
                }
            },
            {
                "name": "postgres_weak",
                "config": {
                    "ports": {"5432": "5432"}
                }
            }
        ],
        "connections": [
            {"source": "dvwa", "target": "ad_light"},
            {"source": "webgoat", "target": "metasploitable2"},
            {"source": "metasploitable2", "target": "mysql_vuln"},
            {"source": "ad_light", "target": "ssh_weak"},
            {"source": "ssh_weak", "target": "postgres_weak"}
        ],
        "network": "corporate_net",
        "tags": ["corporate", "advanced", "ad", "enterprise"]
    },
    
    "microservices_demo": {
        "name": "Microservices Architecture",
        "description": "Microservices-based application with multiple containers",
        "difficulty": "Advanced",
        "estimated_time": "180-240 minutes",
        "learning_objectives": [
            "Container escape techniques",
            "Service mesh exploitation",
            "API gateway attacks",
            "Secret management"
        ],
        "services": [
            {
                "name": "webgoat",
                "config": {
                    "ports": {"8080": "8080"},
                    "env": {"SERVICE_MODE": "gateway"}
                }
            },
            {
                "name": "juice_shop",
                "config": {
                    "ports": {"3000": "3000"},
                    "env": {"SERVICE_TYPE": "auth"}
                }
            },
            {
                "name": "dvwa",
                "config": {
                    "ports": {"8888": "80"},
                    "env": {"SERVICE_TYPE": "api"}
                }
            }
        ],
        "connections": [
            {"source": "webgoat", "target": "juice_shop"},
            {"source": "juice_shop", "target": "dvwa"}
        ],
        "network": "microservices_net",
        "tags": ["docker", "microservices", "advanced", "container"]
    },
    
    # ============================================
    # EXPERT LEVEL TOPOLOGIES
    # ============================================
    
    "multi_forest_ad": {
        "name": "Multi-Forest Active Directory",
        "description": "Complex AD environment with multiple forests and trusts",
        "difficulty": "Expert",
        "estimated_time": "360-480 minutes",
        "learning_objectives": [
            "Cross-forest attacks",
            "Trust relationship exploitation",
            "SID History abuse",
            "Golden Ticket across forests"
        ],
        "services": [
            {
                "name": "ad_light",
                "config": {
                    "ports": {"389": "389", "445": "445", "88": "88"},
                    "env": {
                        "DOMAIN": "forest-a.local",
                        "TRUST_TYPE": "external"
                    }
                }
            },
            {
                "name": "ad_full",
                "config": {
                    "ports": {"389": "389", "445": "445", "88": "88"},
                    "env": {
                        "DOMAIN": "forest-b.local",
                        "TRUST_TYPE": "incoming"
                    }
                }
            },
            {
                "name": "metasploitable3",
                "config": {
                    "ports": {"22": "22", "445": "445", "3389": "3389"},
                    "env": {"DOMAIN": "forest-a.local"}
                }
            }
        ],
        "connections": [
            {"source": "ad_light", "target": "ad_full", "type": "trust"},
            {"source": "ad_light", "target": "metasploitable3"}
        ],
        "network": "multi_ad_net",
        "tags": ["ad", "expert", "forest", "trust"]
    },
    
    "red_team_vs_blue": {
        "name": "Red Team vs Blue Team Lab",
        "description": "Full enterprise environment with monitoring and defense",
        "difficulty": "Expert",
        "estimated_time": "480-600 minutes",
        "learning_objectives": [
            "Evasion techniques",
            "Lateral movement without detection",
            "Persistent access",
            "Data exfiltration"
        ],
        "services": [
            # Attack Surface
            {
                "name": "dvwa",
                "config": {"ports": {"80": "80"}}
            },
            {
                "name": "juice_shop",
                "config": {"ports": {"3000": "3000"}}
            },
            
            # Internal Network
            {
                "name": "ad_light",
                "config": {"ports": {"389": "389", "445": "445"}}
            },
            {
                "name": "metasploitable2",
                "config": {"ports": {"22": "22", "445": "445"}}
            },
            {
                "name": "metasploitable3",
                "config": {"ports": {"22": "22", "3389": "3389"}}
            },
            
            # Data Tier
            {
                "name": "mysql_vuln",
                "config": {"ports": {"3306": "3306"}}
            },
            {
                "name": "postgres_weak",
                "config": {"ports": {"5432": "5432"}}
            }
        ],
        "connections": [
            {"source": "dvwa", "target": "ad_light"},
            {"source": "juice_shop", "target": "metasploitable2"},
            {"source": "ad_light", "target": "metasploitable3"},
            {"source": "metasploitable2", "target": "mysql_vuln"},
            {"source": "metasploitable3", "target": "postgres_weak"}
        ],
        "network": "rt_bt_net",
        "tags": ["expert", "rtbt", "complete", "enterprise"]
    },
    
    "cloud_native": {
        "name": "Cloud-Native Environment",
        "description": "Kubernetes-style containerized application environment",
        "difficulty": "Expert",
        "estimated_time": "300-420 minutes",
        "learning_objectives": [
            "Container escape",
            "K8s API abuse",
            "Service account exploitation",
            "Secret extraction"
        ],
        "services": [
            {
                "name": "webgoat",
                "config": {"ports": {"8080": "8080"}}
            },
            {
                "name": "juice_shop",
                "config": {"ports": {"3000": "3000"}}
            },
            {
                "name": "dvwa",
                "config": {"ports": {"8888": "80"}}
            },
            {
                "name": "mysql_vuln",
                "config": {"ports": {"3306": "3306"}}
            }
        ],
        "connections": [
            {"source": "webgoat", "target": "juice_shop"},
            {"source": "juice_shop", "target": "dvwa"},
            {"source": "dvwa", "target": "mysql_vuln"}
        ],
        "network": "cloud_native_net",
        "tags": ["expert", "container", "k8s", "cloud"]
    }
}

# ============================================
# ADDITIONAL CONFIGURATION
# ============================================

# Topology difficulty levels
DIFFICULTY_LEVELS = {
    "Beginner": "Basic concepts - perfect for first-time users",
    "Intermediate": "Requires understanding of common vulnerabilities",
    "Advanced": "Needs experience with pivoting and chained exploits",
    "Expert": "Full red team simulation requiring advanced techniques"
}

# Default network settings
DEFAULT_TOPOLOGY_SETTINGS = {
    "network_driver": "bridge",
    "enable_dns": True,
    "isolate_networks": True,
    "log_level": "INFO",
    "auto_cleanup": False,
    "cleanup_timeout": 3600  # 1 hour
}

def get_topology_by_difficulty(difficulty: str) -> dict:
    """Get all topologies matching a difficulty level"""
    return {
        name: config for name, config in NETWORK_TOPOLOGIES.items()
        if config.get("difficulty") == difficulty
    }

def get_topology_by_tag(tag: str)