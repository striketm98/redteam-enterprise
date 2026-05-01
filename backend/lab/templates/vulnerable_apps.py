"""
Vulnerable Applications Templates
Pre-configured vulnerable Docker images for practice
"""

VULNERABLE_IMAGES = {
    "web_applications": {
        "dvwa": {
            "image": "vulnerables/web-dvwa",
            "description": "Damn Vulnerable Web Application",
            "vulnerabilities": ["SQL Injection", "XSS", "CSRF", "File Inclusion", "Command Injection"]
        },
        "juice_shop": {
            "image": "bkimminich/juice-shop",
            "description": "OWASP Juice Shop - Modern web vulnerabilities",
            "vulnerabilities": ["JWT", "XSS", "SQLi", "Broken Authentication", "API Security"]
        },
        "webgoat": {
            "image": "webgoat/goatandwolf",
            "description": "WebGoat - Web application security training",
            "vulnerabilities": ["A1-A10 OWASP Top 10"]
        },
        "bodgeit": {
            "image": "psiinon/bodgeit",
            "description": "Bodgeit Store - J2EE vulnerable app",
            "vulnerabilities": ["SQLi", "XSS", "Command Injection", "CSRF"]
        },
        "hackazon": {
            "image": "owasp/hackazon",
            "description": "Hackazon - Vulnerable e-commerce site",
            "vulnerabilities": ["SQLi", "XSS", "IDOR", "Business Logic Flaws"]
        }
    },
    
    "network_services": {
        "metasploitable2": {
            "image": "tleemcjr/metasploitable2",
            "description": "Metasploitable 2 - Multiple network services",
            "services": ["FTP", "SSH", "Telnet", "SMB", "MySQL", "PostgreSQL", "Apache"]
        },
        "metasploitable3": {
            "image": "rapid7/metasploitable3",
            "description": "Metasploitable 3 - Windows/Linux vulnerable images",
            "services": ["RDP", "WinRM", "SMB", "IIS", "Tomcat"]
        },
        "vuln_ssh": {
            "image": "vulnerables/ssh-weak",
            "description": "SSH server with weak credentials",
            "services": ["SSH"]
        },
        "vuln_ftp": {
            "image": "gofish/ftp-server",
            "description": "FTP server with anonymous access",
            "services": ["FTP"]
        }
    },
    
    "database": {
        "mysql_weak": {
            "image": "mysql:5.5",
            "description": "MySQL with default credentials",
            "databases": ["MySQL 5.5"],
            "credentials": {"root": ""}
        },
        "postgres_weak": {
            "image": "postgres:9.6",
            "description": "PostgreSQL with weak configuration",
            "databases": ["PostgreSQL 9.6"],
            "credentials": {"postgres": "postgres"}
        },
        "mongodb_weak": {
            "image": "mongo:3.6",
            "description": "MongoDB with no authentication",
            "databases": ["MongoDB 3.6"]
        }
    },
    
    "active_directory": {
        "ad_light": {
            "image": "outflanknl/ad-light",
            "description": "Lightweight AD environment",
            "services": ["LDAP", "SMB", "Kerberos"],
            "domain": "lab.local"
        },
        "ad_full": {
            "image": "crccheck/hello-world",
            "description": "Full AD environment (requires more resources)",
            "services": ["DC", "DNS", "SMB"],
            "domain": "company.local"
        }
    }
}