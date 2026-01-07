# -*- coding: utf-8 -*-
"""
JSCollector - Burp Suite Extension
Passively collects Secrets & Paths/URLs from JavaScript files proxied through Burp.
Supports user-configurable custom regex patterns and categories.
"""

from burp import IBurpExtender, IContextMenuFactory, ITab, IProxyListener

from javax.swing import JMenuItem
from java.awt.event import ActionListener
from java.util import ArrayList
from java.io import PrintWriter

import sys
import os
import re
import inspect

# Add extension directory to path
try:
    _frame = inspect.currentframe()
    if _frame and hasattr(_frame, 'f_code'):
        ext_dir = os.path.dirname(os.path.abspath(_frame.f_code.co_filename))
    else:
        ext_dir = os.getcwd()
except:
    ext_dir = os.getcwd()

if ext_dir and ext_dir not in sys.path:
    sys.path.insert(0, ext_dir)

from ui.results_panel import ResultsPanel
from pattern_manager import PatternManager


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IProxyListener):
    """JSCollector - Passive JS analysis with custom pattern support."""
    
    EXTENSION_NAME = "JSCollector"
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName(self.EXTENSION_NAME)
        
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        
        # Initialize pattern manager
        self.pattern_manager = PatternManager()
        
        # Results storage
        self.all_findings = []
        self.seen_values = set()
        
        # Initialize UI
        self.panel = ResultsPanel(callbacks, self)
        
        # Register listeners
        callbacks.registerContextMenuFactory(self)
        callbacks.registerProxyListener(self)
        callbacks.addSuiteTab(self)
        
        self._log("JSCollector loaded - Passively collecting from proxied JS")
        self._log("Right-click JS responses for manual analysis")
        
        settings = self.pattern_manager.get_settings()
        if settings.get("passive_mode", True):
            self._log("Passive mode: ENABLED")
        else:
            self._log("Passive mode: DISABLED")
    
    def _log(self, msg):
        self._stdout.println("[JSCollector] " + str(msg))
    
    def getTabCaption(self):
        return self.EXTENSION_NAME
    
    def getUiComponent(self):
        return self.panel
    
    # ==================== PROXY LISTENER (Passive Collection) ====================
    
    def processProxyMessage(self, messageIsRequest, message):
        """Called for every request/response passing through proxy."""
        # Only process responses
        if messageIsRequest:
            return
        
        # Check if passive mode is enabled
        settings = self.pattern_manager.get_settings()
        if not settings.get("passive_mode", True):
            return
        
        try:
            # Get the response
            message_info = message.getMessageInfo()
            response = message_info.getResponse()
            if not response:
                return
            
            # Get request info for URL and scope check
            req_info = self._helpers.analyzeRequest(message_info)
            url_obj = req_info.getUrl()
            url_str = str(url_obj).lower()
            
            # Check scope if scope_only is enabled (using proper URL object)
            if settings.get("scope_only", False):
                if not self._callbacks.isInScope(url_obj):
                    return
            
            # Check content type based on settings
            resp_info = self._helpers.analyzeResponse(response)
            headers = resp_info.getHeaders()
            
            collect_js = settings.get("collect_js", True)
            collect_html = settings.get("collect_html", False)
            
            is_js = False
            is_html = False
            
            for header in headers:
                header_lower = str(header).lower()
                if 'content-type:' in header_lower:
                    if 'javascript' in header_lower or 'application/json' in header_lower:
                        is_js = True
                    elif 'text/html' in header_lower:
                        is_html = True
                    break
            
            # Also check URL extension for JS
            if not is_js and (url_str.endswith('.js') or '.js?' in url_str):
                is_js = True
            
            # Also check URL extension for HTML
            if not is_html and (url_str.endswith('.html') or url_str.endswith('.htm') or '.html?' in url_str or '.htm?' in url_str):
                is_html = True
            
            # Determine if we should process this response
            should_process = False
            if collect_js and is_js:
                should_process = True
            if collect_html and is_html:
                should_process = True
            
            if not should_process:
                return
            
            # Analyze the response
            self.analyze_response(message_info, passive=True)
            
        except Exception as e:
            self._log("Proxy error: " + str(e))
    
    # ==================== CONTEXT MENU (Manual Analysis) ====================
    
    def createMenuItems(self, invocation):
        menu = ArrayList()
        try:
            messages = invocation.getSelectedMessages()
            if messages and len(messages) > 0:
                item = JMenuItem("Analyze JS with JSCollector")
                item.addActionListener(AnalyzeAction(self, invocation))
                menu.add(item)
        except Exception as e:
            self._log("Menu error: " + str(e))
        return menu
    
    # ==================== ANALYSIS ====================
    
    def analyze_response(self, message_info, passive=False):
        """Analyze a response for secrets, endpoints, and URLs."""
        response = message_info.getResponse()
        if not response:
            return
        
        # Get source URL (full path)
        try:
            req_info = self._helpers.analyzeRequest(message_info)
            url = str(req_info.getUrl())
        except:
            url = "Unknown"
        
        # Get response body
        resp_info = self._helpers.analyzeResponse(response)
        body_offset = resp_info.getBodyOffset()
        body = self._helpers.bytesToString(response[body_offset:])
        
        if len(body) < 50:
            return
        
        # Short name for logging
        source_name = url.split('/')[-1].split('?')[0] if '/' in url else url
        if len(source_name) > 40:
            source_name = source_name[:40] + "..."
        
        prefix = "[Passive] " if passive else ""
        self._log(prefix + "Analyzing: " + source_name)
        
        new_findings = []
        
        # Get all categories from pattern manager
        categories = self.pattern_manager.get_all_categories()
        
        for category in categories:
            patterns = self.pattern_manager.get_patterns_for_category(category)
            
            for pattern, pattern_name in patterns:
                for match in pattern.finditer(body):
                    # Get the first captured group or the whole match
                    value = match.group(1).strip() if match.lastindex else match.group(0).strip()
                    
                    # Validate based on category
                    if category == "endpoints":
                        if not self._is_valid_endpoint(value):
                            continue
                    elif category == "urls":
                        if not self._is_valid_url(value):
                            continue
                    elif category == "secrets":
                        if not self._is_valid_secret(value):
                            continue
                        # Mask secrets
                        value = self._mask_secret(value)
                    elif category == "emails":
                        if not self._is_valid_email(value):
                            continue
                    elif category == "files":
                        if not self._is_valid_file(value):
                            continue
                    
                    finding = self._add_finding(category, value, url, pattern_name, message_info)
                    if finding:
                        new_findings.append(finding)
        
        # Update UI
        if new_findings:
            self._log("Found %d new items" % len(new_findings))
            self.panel.add_findings(new_findings, url)
        elif not passive:
            self._log("No new findings")
    
    def _mask_secret(self, value):
        """Mask a secret value for display."""
        if len(value) > 20:
            return value[:10] + "..." + value[-4:]
        return value
    
    def _add_finding(self, category, value, source, pattern_name="", message_info=None):
        """Add a finding if not duplicate."""
        key = category + ":" + value
        if key in self.seen_values:
            return None
        
        self.seen_values.add(key)
        finding = {
            "category": category,
            "value": value,
            "source": source,
            "pattern": pattern_name,
            "message_info": message_info,
        }
        self.all_findings.append(finding)
        return finding
    
    # ==================== VALIDATION ====================
    
    def _is_valid_endpoint(self, value):
        """Validate endpoint - reject noise."""
        if not value or len(value) < 3:
            return False
        
        if self.pattern_manager.is_noise(value):
            return False
        
        # Must start with /
        if not value.startswith('/'):
            return False
        
        # Skip if just single segments
        parts = value.split('/')
        if len(parts) < 2 or all(len(p) < 2 for p in parts if p):
            return False
        
        return True
    
    def _is_valid_url(self, value):
        """Validate URL - reject noise."""
        if not value or len(value) < 15:
            return False
        
        if self.pattern_manager.is_noise_domain(value):
            return False
        
        val_lower = value.lower()
        
        # Skip placeholders
        if '{' in value or 'undefined' in val_lower or 'null' in val_lower:
            return False
        
        # Skip data URIs
        if val_lower.startswith('data:'):
            return False
        
        # Skip static files
        static_exts = ['.css', '.png', '.jpg', '.gif', '.svg', '.woff', '.ttf', '.ico']
        if any(val_lower.endswith(ext) for ext in static_exts):
            return False
        
        return True
    
    def _is_valid_secret(self, value):
        """Validate secrets."""
        if not value or len(value) < 10:
            return False
        
        val_lower = value.lower()
        noise_words = ['example', 'placeholder', 'your', 'xxxx', 'test', 'sample', 'dummy']
        if any(x in val_lower for x in noise_words):
            return False
        
        return True
    
    def _is_valid_email(self, value):
        """Validate emails."""
        if not value or '@' not in value:
            return False
        
        domain = value.split('@')[-1].lower()
        noise_domains = ['example.com', 'test.com', 'domain.com', 'placeholder.com', 'email.com']
        if domain in noise_domains:
            return False
        
        val_lower = value.lower()
        noise_words = ['example', 'test', 'placeholder', 'noreply', 'no-reply']
        if any(x in val_lower for x in noise_words):
            return False
        
        return True
    
    def _is_valid_file(self, value):
        """Validate file references."""
        if not value or len(value) < 3:
            return False
        
        val_lower = value.lower()
        
        # Skip common build files
        noise_files = [
            'package.json', 'tsconfig.json', 'webpack', 'babel',
            'eslint', 'prettier', 'node_modules', '.min.',
            'polyfill', 'vendor', 'chunk', 'bundle', '.map'
        ]
        if any(x in val_lower for x in noise_files):
            return False
        
        # Skip small locale JSON files
        if val_lower.endswith('.json') and len(value.split('/')[-1]) <= 7:
            return False
        
        return True
    
    # ==================== PUBLIC API ====================
    
    def clear_results(self):
        """Clear all findings."""
        self.all_findings = []
        self.seen_values = set()
    
    def get_all_findings(self):
        """Get all findings."""
        return self.all_findings
    
    def get_pattern_manager(self):
        """Get the pattern manager instance."""
        return self.pattern_manager


class AnalyzeAction(ActionListener):
    """Action listener for manual JS analysis."""
    
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation
    
    def actionPerformed(self, event):
        messages = self.invocation.getSelectedMessages()
        for msg in messages:
            self.extender.analyze_response(msg, passive=False)
