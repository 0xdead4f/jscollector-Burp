# -*- coding: utf-8 -*-
"""
JSCollector - Pattern Manager
Manages built-in and custom regex patterns for JS analysis.
"""

import os
import re
import json


class PatternManager:
    """Manages built-in and custom regex patterns for JS analysis."""
    
    def __init__(self, config_path=None):
        """Initialize the pattern manager.
        
        Args:
            config_path: Path to patterns.json config file. If None, uses default location.
        """
        if config_path is None:
            ext_dir = os.path.dirname(os.path.abspath(__file__))
            config_path = os.path.join(ext_dir, "config", "patterns.json")
        
        self.config_path = config_path
        self.config = self._load_config()
        
        # Built-in patterns
        self._init_builtin_patterns()
    
    def _init_builtin_patterns(self):
        """Initialize built-in patterns."""
        
        # ==================== ENDPOINT PATTERNS ====================
        self.builtin_endpoints = [
            # API endpoints
            (r'["\']((https?:)?//["\'][^"\']+/api/[a-zA-Z0-9/_-]+)["\']', "API URL"),
            (r'["\'](/api/v?\d*/[a-zA-Z0-9/_-]{2,})["\']', "API Path"),
            (r'["\'](/v\d+/[a-zA-Z0-9/_-]{2,})["\']', "Versioned Path"),
            (r'["\'](/rest/[a-zA-Z0-9/_-]{2,})["\']', "REST Path"),
            (r'["\'](/graphql[a-zA-Z0-9/_-]*)["\']', "GraphQL"),
            
            # OAuth/Auth endpoints
            (r'["\'](/oauth[0-9]*/[a-zA-Z0-9/_-]+)["\']', "OAuth"),
            (r'["\'](/auth[a-zA-Z0-9/_-]*)["\']', "Auth"),
            (r'["\'](/login[a-zA-Z0-9/_-]*)["\']', "Login"),
            (r'["\'](/logout[a-zA-Z0-9/_-]*)["\']', "Logout"),
            (r'["\'](/token[a-zA-Z0-9/_-]*)["\']', "Token"),
            
            # Sensitive paths
            (r'["\'](/admin[a-zA-Z0-9/_-]*)["\']', "Admin"),
            (r'["\'](/dashboard[a-zA-Z0-9/_-]*)["\']', "Dashboard"),
            (r'["\'](/internal[a-zA-Z0-9/_-]*)["\']', "Internal"),
            (r'["\'](/debug[a-zA-Z0-9/_-]*)["\']', "Debug"),
            (r'["\'](/config[a-zA-Z0-9/_-]*)["\']', "Config"),
            (r'["\'](/backup[a-zA-Z0-9/_-]*)["\']', "Backup"),
            (r'["\'](/private[a-zA-Z0-9/_-]*)["\']', "Private"),
            (r'["\'](/upload[a-zA-Z0-9/_-]*)["\']', "Upload"),
            (r'["\'](/download[a-zA-Z0-9/_-]*)["\']', "Download"),
            
            # Well-known paths
            (r'["\'](/\.well-known/[a-zA-Z0-9/_-]+)["\']', "Well-Known"),
            (r'["\'](/idp/[a-zA-Z0-9/_-]+)["\']', "IDP"),
        ]
        
        # ==================== URL PATTERNS ====================
        self.builtin_urls = [
            (r'["\'](https?://[^\s"\'<>]{10,})["\']', "HTTP URL"),
            (r'["\'](wss?://[^\s"\'<>]{10,})["\']', "WebSocket"),
            (r'["\'](sftp://[^\s"\'<>]{10,})["\']', "SFTP"),
            # Cloud storage
            (r'(https?://[a-zA-Z0-9.-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com[^\s"\'<>]*)', "AWS S3"),
            (r'(https?://[a-zA-Z0-9.-]+\.blob\.core\.windows\.net[^\s"\'<>]*)', "Azure Blob"),
            (r'(https?://storage\.googleapis\.com/[^\s"\'<>]*)', "GCP Storage"),
        ]
        
        # ==================== SECRET PATTERNS ====================
        self.builtin_secrets = [
            (r'(AKIA[0-9A-Z]{16})', "AWS Access Key"),
            (r'(AIza[0-9A-Za-z\-_]{35})', "Google API Key"),
            (r'(sk_live_[0-9a-zA-Z]{24,})', "Stripe Live Key"),
            (r'(ghp_[0-9a-zA-Z]{36})', "GitHub PAT"),
            (r'(gho_[0-9a-zA-Z]{36})', "GitHub OAuth"),
            (r'(ghu_[0-9a-zA-Z]{36})', "GitHub User Token"),
            (r'(ghs_[0-9a-zA-Z]{36})', "GitHub Server Token"),
            (r'(xox[baprs]-[0-9a-zA-Z\-]{10,48})', "Slack Token"),
            (r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)', "JWT"),
            (r'(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)', "Private Key"),
            (r'(mongodb(?:\+srv)?://[^\s"\'<>]+)', "MongoDB URI"),
            (r'(postgres(?:ql)?://[^\s"\'<>]+)', "PostgreSQL URI"),
            (r'(mysql://[a-z0-9._%+\-]+:[^\s:@]+@[^\s"\'<>]+)', "MySQL URI"),
            (r'(?i)algolia.{0,32}([a-z0-9]{32})\b', "Algolia API Key"),
            (r'(?i)cloudflare.{0,32}(?:secret|private|access|key|token).{0,32}([a-z0-9_-]{38,42})\b', "Cloudflare API Token"),
            (r'\b(ya29\.[a-z0-9_-]{30,})\b', "Google OAuth2 Token"),
            (r'(?i)(?:facebook|fb).{0,32}(?:api|app|secret|key).{0,32}([a-z0-9]{32})\b', "Facebook Secret"),
            (r'(EAACEdEose0cBA[A-Z0-9]{20,})\b', "Facebook Access Token"),
            (r'\b(sgp_[A-Z0-9_-]{60,70})\b', "Segment Public Token"),
            (r'(sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})', "OpenAI API Key"),
            (r'(sq0csp-[0-9A-Za-z\-_]{43})', "Square OAuth Secret"),
            (r'(sqOatp-[0-9A-Za-z\-_]{22})', "Square Access Token"),
            (r'(AC[a-z0-9]{32})', "Twilio Account SID"),
            (r'(SK[a-z0-9]{32})', "Twilio API Key SID"),
        ]
        
        # ==================== EMAIL PATTERN ====================
        self.email_pattern = r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})'
        
        # ==================== FILE PATTERNS ====================
        self.file_pattern = (
            r'["\']([a-zA-Z0-9_/.-]+\.(?:'
            r'sql|csv|xlsx|xls|json|xml|yaml|yml|'  # Data files
            r'txt|log|conf|config|cfg|ini|env|'      # Config/logs
            r'bak|backup|old|orig|copy|'              # Backups
            r'key|pem|crt|cer|p12|pfx|'               # Certificates
            r'doc|docx|pdf|'                          # Documents
            r'zip|tar|gz|rar|7z|'                     # Archives
            r'sh|bat|ps1|py|rb|pl'                    # Scripts
            r'))["\']'
        )
        
        # ==================== NOISE FILTERS ====================
        self.noise_domains = {
            'www.w3.org', 'schemas.openxmlformats.org', 'schemas.microsoft.com',
            'purl.org', 'purl.oclc.org', 'openoffice.org', 'docs.oasis-open.org',
            'sheetjs.openxmlformats.org', 'ns.adobe.com', 'www.xml.org',
            'example.com', 'test.com', 'localhost', '127.0.0.1',
            'fusioncharts.com', 'jspdf.default.namespaceuri',
            'npmjs.org', 'registry.npmjs.org',
            'github.com/indutny', 'github.com/crypto-browserify',
            'jqwidgets.com', 'ag-grid.com',
        }
        
        self.noise_patterns = [
            r'^\.\./|^\./',  # Module imports
            r'^[a-z]{2}(-[a-z]{2})?\.js$',  # Locale files
            r'^[a-z]{2}(-[a-z]{2})?$',  # Just locale
            r'-xform$',  # Excel xform
            r'^sha\d*$|^aes$|^des$|^md5$',  # Crypto modules
            r'^/[A-Z][a-z]+\s|^/[A-Z][a-z]+$',  # PDF internals
            r'^\d+ \d+ R$',  # PDF object refs
            r'^xl/|^docProps/|^_rels/|^META-INF/',  # Office internals
            r'\.xml$|^worksheets/|^theme/',  # XML files
            r'^webpack|^zone\.js$|^readable-stream/',  # Build artifacts
            r'^process/|^stream/|^buffer$|^events$|^util$|^path$',  # Node modules
            r'^\+|^\$\{|^#|^\?ref=',  # Generic noise
            r'^/[a-zA-Z]$',  # Single letter paths
            r'^http://$|_ngcontent',  # Empty/Angular internals
        ]
        
        self.noise_strings = {
            'http://', 'https://', '/a', '/P', '/R', '/V', '/W',
            'zone.js', 'bn.js', 'hash.js', 'md5.js', 'sha.js', 'des.js',
            'asn1.js', 'declare.js', 'elliptic.js',
        }
        
        # Compile patterns
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile all regex patterns."""
        # Compile built-in patterns
        self.compiled_endpoints = [
            (re.compile(p, re.IGNORECASE), name) for p, name in self.builtin_endpoints
        ]
        self.compiled_urls = [
            (re.compile(p), name) for p, name in self.builtin_urls
        ]
        self.compiled_secrets = [
            (re.compile(p), name) for p, name in self.builtin_secrets
        ]
        self.compiled_email = re.compile(self.email_pattern)
        self.compiled_file = re.compile(self.file_pattern, re.IGNORECASE)
        self.compiled_noise = [re.compile(p) for p in self.noise_patterns]
        
        # Compile custom patterns
        self._compile_custom_patterns()
    
    def _compile_custom_patterns(self):
        """Compile custom patterns from config."""
        self.custom_compiled = {
            "endpoints": [],
            "urls": [],
            "secrets": [],
        }
        
        for pattern in self.config.get("custom_endpoints", []):
            try:
                compiled = re.compile(pattern["regex"], re.IGNORECASE)
                self.custom_compiled["endpoints"].append((compiled, pattern.get("name", "Custom")))
            except re.error:
                pass
        
        for pattern in self.config.get("custom_urls", []):
            try:
                compiled = re.compile(pattern["regex"])
                self.custom_compiled["urls"].append((compiled, pattern.get("name", "Custom")))
            except re.error:
                pass
        
        for pattern in self.config.get("custom_secrets", []):
            try:
                compiled = re.compile(pattern["regex"])
                self.custom_compiled["secrets"].append((compiled, pattern.get("name", "Custom")))
            except re.error:
                pass
        
        # Compile custom categories
        self.custom_categories_compiled = {}
        for cat_key, cat_data in self.config.get("custom_categories", {}).items():
            patterns = []
            for pattern in cat_data.get("patterns", []):
                try:
                    compiled = re.compile(pattern["regex"], re.IGNORECASE)
                    patterns.append((compiled, pattern.get("name", "Custom")))
                except re.error:
                    pass
            if patterns:
                self.custom_categories_compiled[cat_key] = {
                    "display_name": cat_data.get("display_name", cat_key),
                    "patterns": patterns
                }
    
    def _load_config(self):
        """Load config from JSON file."""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            except (IOError, ValueError):
                pass
        
        # Return default config
        return {
            "version": "1.0",
            "custom_categories": {},
            "custom_secrets": [],
            "custom_endpoints": [],
            "custom_urls": [],
            "settings": {
                "passive_mode": True,
                "scope_only": False,
                "collect_js": True,
                "collect_html": False
            }
        }
    
    def save_config(self):
        """Save current config to JSON file."""
        try:
            config_dir = os.path.dirname(self.config_path)
            if not os.path.exists(config_dir):
                os.makedirs(config_dir)
            
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except IOError:
            return False
    
    def get_settings(self):
        """Get current settings."""
        return self.config.get("settings", {})
    
    def update_settings(self, settings):
        """Update settings."""
        self.config["settings"] = settings
        self.save_config()
    
    def get_all_categories(self):
        """Get all categories (built-in + custom)."""
        categories = ["endpoints", "urls", "secrets", "emails", "files"]
        for cat_key in self.custom_categories_compiled:
            if cat_key not in categories:
                categories.append(cat_key)
        return categories
    
    def get_category_display_name(self, category):
        """Get display name for a category."""
        builtin_names = {
            "endpoints": "Endpoints",
            "urls": "URLs",
            "secrets": "Secrets",
            "emails": "Emails",
            "files": "Files"
        }
        if category in builtin_names:
            return builtin_names[category]
        
        cat_data = self.custom_categories_compiled.get(category, {})
        return cat_data.get("display_name", category.title())
    
    def add_custom_pattern(self, category, regex, name):
        """Add a custom pattern.
        
        Args:
            category: Category name (endpoints, urls, secrets, or custom category)
            regex: Regex pattern string
            name: Display name for the pattern
            
        Returns:
            Tuple of (success, error_message)
        """
        # Validate regex
        try:
            re.compile(regex)
        except re.error as e:
            return False, "Invalid regex: " + str(e)
        
        pattern_entry = {"regex": regex, "name": name}
        
        if category == "endpoints":
            self.config["custom_endpoints"].append(pattern_entry)
        elif category == "urls":
            self.config["custom_urls"].append(pattern_entry)
        elif category == "secrets":
            self.config["custom_secrets"].append(pattern_entry)
        else:
            # Custom category
            if category not in self.config["custom_categories"]:
                self.config["custom_categories"][category] = {
                    "display_name": category.title(),
                    "patterns": []
                }
            self.config["custom_categories"][category]["patterns"].append(pattern_entry)
        
        self.save_config()
        self._compile_custom_patterns()
        return True, None
    
    def add_custom_category(self, key, display_name):
        """Add a new custom category.
        
        Args:
            key: Machine-readable key for the category
            display_name: Human-readable display name
            
        Returns:
            Tuple of (success, error_message)
        """
        if key in self.get_all_categories():
            return False, "Category already exists"
        
        self.config["custom_categories"][key] = {
            "display_name": display_name,
            "patterns": []
        }
        self.save_config()
        self._compile_custom_patterns()
        return True, None
    
    def remove_custom_pattern(self, category, index):
        """Remove a custom pattern by index.
        
        Args:
            category: Category name
            index: Index of pattern to remove
            
        Returns:
            Tuple of (success, error_message)
        """
        try:
            if category == "endpoints":
                del self.config["custom_endpoints"][index]
            elif category == "urls":
                del self.config["custom_urls"][index]
            elif category == "secrets":
                del self.config["custom_secrets"][index]
            else:
                # Custom category
                if category in self.config["custom_categories"]:
                    del self.config["custom_categories"][category]["patterns"][index]
            
            self.save_config()
            self._compile_custom_patterns()
            return True, None
        except (IndexError, KeyError) as e:
            return False, "Pattern not found: " + str(e)
    
    def get_patterns_for_category(self, category):
        """Get all patterns for a category (built-in + custom).
        
        Returns list of (compiled_pattern, name) tuples.
        """
        if category == "endpoints":
            return self.compiled_endpoints + self.custom_compiled.get("endpoints", [])
        elif category == "urls":
            return self.compiled_urls + self.custom_compiled.get("urls", [])
        elif category == "secrets":
            return self.compiled_secrets + self.custom_compiled.get("secrets", [])
        elif category == "emails":
            return [(self.compiled_email, "Email")]
        elif category == "files":
            return [(self.compiled_file, "File")]
        elif category in self.custom_categories_compiled:
            return self.custom_categories_compiled[category]["patterns"]
        return []
    
    def get_custom_patterns_list(self, category):
        """Get list of custom patterns for a category (for UI display).
        
        Returns list of dicts with 'regex' and 'name' keys.
        """
        if category == "endpoints":
            return self.config.get("custom_endpoints", [])
        elif category == "urls":
            return self.config.get("custom_urls", [])
        elif category == "secrets":
            return self.config.get("custom_secrets", [])
        elif category in self.config.get("custom_categories", {}):
            return self.config["custom_categories"][category].get("patterns", [])
        return []
    
    def is_noise(self, value):
        """Check if a value matches noise patterns."""
        if not value:
            return True
        
        if value in self.noise_strings:
            return True
        
        for pattern in self.compiled_noise:
            if pattern.search(value):
                return True
        
        return False
    
    def is_noise_domain(self, url):
        """Check if a URL contains a noise domain."""
        if not url:
            return True
        
        url_lower = url.lower()
        for domain in self.noise_domains:
            if domain in url_lower:
                return True
        
        return False
