# -*- coding: utf-8 -*-
"""
JSCollector - Results Panel
Features: Search filter, Copy button, Source filtering, Settings access
"""

from javax.swing import (
    JPanel, JScrollPane, JTabbedPane, JButton, JLabel,
    JTable, JComboBox, JTextField, BorderFactory, SwingUtilities,
    JCheckBox, JDialog, JSplitPane
)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, FlowLayout, Font, Dimension, Toolkit
from java.awt.datatransfer import StringSelection
from java.awt.event import ActionListener, KeyListener, KeyEvent, MouseAdapter
import json


class ResultsPanel(JPanel):
    """Results panel with search filter and copy functionality."""
    
    def __init__(self, callbacks, extender):
        JPanel.__init__(self)
        self.callbacks = callbacks
        self.extender = extender
        
        # Findings by category
        self.findings = {
            "endpoints": [],
            "urls": [],
            "secrets": [],
            "emails": [],
            "files": [],
        }
        
        # Unique sources
        self.sources = set()
        
        self._init_ui()
    
    def _init_ui(self):
        """Build the UI."""
        self.setLayout(BorderLayout(5, 5))
        
        # ===== HEADER =====
        header = JPanel(BorderLayout(5, 0))
        header.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        
        # Left side - Title and stats
        left_panel = JPanel(FlowLayout(FlowLayout.LEFT, 5, 0))
        title_label = JLabel("JSCollector")
        title_label.setFont(Font("SansSerif", Font.BOLD, 12))
        left_panel.add(title_label)
        
        self.stats_label = JLabel("| E:0 | U:0 | S:0 | M:0 | F:0")
        self.stats_label.setFont(Font("SansSerif", Font.PLAIN, 11))
        left_panel.add(self.stats_label)
        
        # Passive mode indicator
        self.mode_label = JLabel("[Passive]")
        self.mode_label.setFont(Font("SansSerif", Font.ITALIC, 11))
        left_panel.add(self.mode_label)
        
        header.add(left_panel, BorderLayout.WEST)
        
        # Right side - Controls
        controls = JPanel(FlowLayout(FlowLayout.RIGHT, 5, 0))
        
        # Search box
        controls.add(JLabel("Search:"))
        self.search_field = JTextField(15)
        self.search_field.addKeyListener(SearchKeyListener(self))
        controls.add(self.search_field)
        
        # Source filter
        controls.add(JLabel("Source:"))
        self.source_filter = JComboBox(["All"])
        self.source_filter.setPreferredSize(Dimension(150, 25))
        self.source_filter.addActionListener(FilterAction(self))
        controls.add(self.source_filter)
        
        # Copy button
        copy_btn = JButton("Copy")
        copy_btn.addActionListener(CopyAction(self))
        controls.add(copy_btn)
        
        # Copy All button
        copy_all_btn = JButton("Copy All")
        copy_all_btn.addActionListener(CopyAllAction(self))
        controls.add(copy_all_btn)
        
        # Clear button
        clear_btn = JButton("Clear")
        clear_btn.addActionListener(ClearAction(self))
        controls.add(clear_btn)
        
        # Export button
        export_btn = JButton("Export")
        export_btn.addActionListener(ExportAction(self))
        controls.add(export_btn)
        
        # In Scope Only checkbox
        self.scope_checkbox = JCheckBox("In Scope Only")
        self.scope_checkbox.setFont(Font("SansSerif", Font.PLAIN, 11))
        self.scope_checkbox.addActionListener(ScopeToggleAction(self))
        controls.add(self.scope_checkbox)
        
        # Settings button
        settings_btn = JButton("Settings")
        settings_btn.addActionListener(SettingsAction(self))
        controls.add(settings_btn)
        controls.add(settings_btn)
        
        header.add(controls, BorderLayout.EAST)
        self.add(header, BorderLayout.NORTH)
        
        # ===== TABS WITH TABLES =====
        self.tabs = JTabbedPane()
        
        self.tables = {}
        self.models = {}
        
        # Built-in categories
        self.categories = [
            ("Endpoints", "endpoints"),
            ("URLs", "urls"),
            ("Secrets", "secrets"),
            ("Emails", "emails"),
            ("Files", "files"),
        ]
        
        for title, key in self.categories:
            self._add_category_tab(title, key)
        
        self.add(self.tabs, BorderLayout.CENTER)
    
    def _add_category_tab(self, title, key):
        """Add a tab for a category."""
        panel = JPanel(BorderLayout())
        
        # 2 columns: Value, Source
        columns = ["Value", "Source"]
        model = NonEditableTableModel(columns, 0)
        self.models[key] = model
        
        table = JTable(model)
        table.setAutoCreateRowSorter(True)
        table.setFont(Font("Monospaced", Font.PLAIN, 12))
        
        # Set column widths (wider Source for full URLs)
        table.getColumnModel().getColumn(0).setPreferredWidth(400)
        table.getColumnModel().getColumn(1).setPreferredWidth(400)
        
        # Add double-click listener for Request/Response popup
        table.addMouseListener(TableClickListener(self, key))
        
        self.tables[key] = table
        
        scroll = JScrollPane(table)
        panel.add(scroll, BorderLayout.CENTER)
        
        self.tabs.addTab(title + " (0)", panel)
        
        # Initialize findings storage
        if key not in self.findings:
            self.findings[key] = []
    
    def add_findings(self, new_findings, source_name):
        """Add new findings."""
        if source_name and source_name not in self.sources:
            self.sources.add(source_name)
            self.source_filter.addItem(source_name)
        
        for finding in new_findings:
            category = finding.get("category", "")
            
            # Add tab for custom category if needed
            if category not in self.findings:
                self.findings[category] = []
                self._add_category_tab(category.title(), category)
                self.categories.append((category.title(), category))
            
            self.findings[category].append({
                "value": finding.get("value", ""),
                "source": finding.get("source", source_name),
                "message_info": finding.get("message_info"),
            })
        
        self._refresh_tables()
    
    def _refresh_tables(self):
        """Refresh tables with current filters."""
        selected_source = str(self.source_filter.getSelectedItem())
        search_text = self.search_field.getText().lower().strip()
        
        for i, (title, key) in enumerate(self.categories):
            if key not in self.models:
                continue
            
            model = self.models[key]
            model.setRowCount(0)
            
            count = 0
            for item in self.findings.get(key, []):
                # Source filter
                if selected_source != "All" and item.get("source") != selected_source:
                    continue
                
                # Search filter
                if search_text:
                    value_lower = item.get("value", "").lower()
                    if search_text not in value_lower:
                        continue
                
                model.addRow([
                    item.get("value", ""),
                    item.get("source", ""),
                ])
                count += 1
            
            self.tabs.setTitleAt(i, "%s (%d)" % (title, count))
        
        self._update_stats()
    
    def _update_stats(self):
        """Update stats label."""
        e = len(self.findings.get("endpoints", []))
        u = len(self.findings.get("urls", []))
        s = len(self.findings.get("secrets", []))
        m = len(self.findings.get("emails", []))
        f = len(self.findings.get("files", []))
        self.stats_label.setText("| E:%d | U:%d | S:%d | M:%d | F:%d" % (e, u, s, m, f))
        
        # Update passive mode indicator and scope checkbox
        try:
            settings = self.extender.get_pattern_manager().get_settings()
            if settings.get("passive_mode", True):
                self.mode_label.setText("[Passive]")
            else:
                self.mode_label.setText("[Manual]")
            
            # Sync scope checkbox with settings
            self.scope_checkbox.setSelected(settings.get("scope_only", False))
        except:
            pass
    
    def _get_current_table(self):
        """Get the currently visible table."""
        idx = self.tabs.getSelectedIndex()
        if 0 <= idx < len(self.categories):
            key = self.categories[idx][1]
            return self.tables.get(key)
        return None
    
    def _get_current_key(self):
        """Get the current category key."""
        idx = self.tabs.getSelectedIndex()
        if 0 <= idx < len(self.categories):
            return self.categories[idx][1]
        return None
    
    def copy_selected(self):
        """Copy selected row's value to clipboard."""
        table = self._get_current_table()
        if not table:
            return
        
        row = table.getSelectedRow()
        if row >= 0:
            model_row = table.convertRowIndexToModel(row)
            value = table.getModel().getValueAt(model_row, 0)
            self._copy_to_clipboard(str(value))
    
    def copy_all_visible(self):
        """Copy all visible values in current tab to clipboard."""
        table = self._get_current_table()
        if not table:
            return
        
        model = table.getModel()
        values = []
        for i in range(model.getRowCount()):
            values.append(str(model.getValueAt(i, 0)))
        
        if values:
            self._copy_to_clipboard("\n".join(values))
    
    def _copy_to_clipboard(self, text):
        """Copy text to system clipboard."""
        try:
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(StringSelection(text), None)
        except:
            pass
    
    def clear_all(self):
        """Clear all results."""
        for key in self.findings:
            self.findings[key] = []
        self.sources = set()
        
        self.source_filter.removeAllItems()
        self.source_filter.addItem("All")
        self.search_field.setText("")
        
        self.extender.clear_results()
        self._refresh_tables()
    
    def export_all(self):
        """Export to JSON."""
        from javax.swing import JFileChooser
        from java.io import File
        
        chooser = JFileChooser()
        chooser.setSelectedFile(File("jscollector_findings.json"))
        
        if chooser.showSaveDialog(self) == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            
            export = {}
            for key in self.findings:
                export[key] = [f["value"] for f in self.findings.get(key, [])]
            
            fp = open(path, 'w')
            try:
                json.dump(export, fp, indent=2)
            finally:
                fp.close()
    
    def open_settings(self):
        """Open the settings dialog."""
        from ui.pattern_config_dialog import PatternConfigDialog
        
        try:
            pattern_manager = self.extender.get_pattern_manager()
            dialog = PatternConfigDialog(SwingUtilities.getWindowAncestor(self), pattern_manager)
            dialog.setVisible(True)
            
            # Refresh mode label after settings change
            self._update_stats()
        except Exception as e:
            from javax.swing import JOptionPane
            JOptionPane.showMessageDialog(self, "Error opening settings: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
    
    def toggle_scope(self):
        """Toggle scope-only filtering."""
        try:
            pattern_manager = self.extender.get_pattern_manager()
            settings = pattern_manager.get_settings()
            settings["scope_only"] = self.scope_checkbox.isSelected()
            pattern_manager.update_settings(settings)
        except Exception as e:
            from javax.swing import JOptionPane
            JOptionPane.showMessageDialog(self, "Error updating settings: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
    
    def show_request_response(self, category_key, row_index):
        """Show Request/Response popup for a finding."""
        try:
            findings_list = self.findings.get(category_key, [])
            if row_index < 0 or row_index >= len(findings_list):
                return
            
            finding = findings_list[row_index]
            message_info = finding.get("message_info")
            
            if not message_info:
                from javax.swing import JOptionPane
                JOptionPane.showMessageDialog(self, "Request/Response data not available for this finding.", "Info", JOptionPane.INFORMATION_MESSAGE)
                return
            
            # Create and show the dialog
            dialog = RequestResponseDialog(
                SwingUtilities.getWindowAncestor(self),
                self.callbacks,
                message_info,
                finding.get("source", "Unknown")
            )
            dialog.setVisible(True)
        except Exception as e:
            from javax.swing import JOptionPane
            JOptionPane.showMessageDialog(self, "Error showing request/response: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)


class NonEditableTableModel(DefaultTableModel):
    def __init__(self, columns, rows):
        DefaultTableModel.__init__(self, columns, rows)
    
    def isCellEditable(self, row, column):
        return False


class SearchKeyListener(KeyListener):
    """Filters on each keystroke."""
    def __init__(self, panel):
        self.panel = panel
    def keyPressed(self, event):
        pass
    def keyReleased(self, event):
        self.panel._refresh_tables()
    def keyTyped(self, event):
        pass


class FilterAction(ActionListener):
    def __init__(self, panel):
        self.panel = panel
    def actionPerformed(self, event):
        self.panel._refresh_tables()


class CopyAction(ActionListener):
    """Copy selected row."""
    def __init__(self, panel):
        self.panel = panel
    def actionPerformed(self, event):
        self.panel.copy_selected()


class CopyAllAction(ActionListener):
    """Copy all visible rows."""
    def __init__(self, panel):
        self.panel = panel
    def actionPerformed(self, event):
        self.panel.copy_all_visible()


class ClearAction(ActionListener):
    def __init__(self, panel):
        self.panel = panel
    def actionPerformed(self, event):
        self.panel.clear_all()


class ExportAction(ActionListener):
    def __init__(self, panel):
        self.panel = panel
    def actionPerformed(self, event):
        self.panel.export_all()


class SettingsAction(ActionListener):
    def __init__(self, panel):
        self.panel = panel
    def actionPerformed(self, event):
        self.panel.open_settings()


class ScopeToggleAction(ActionListener):
    """Toggle scope-only filtering."""
    def __init__(self, panel):
        self.panel = panel
    def actionPerformed(self, event):
        self.panel.toggle_scope()


class TableClickListener(MouseAdapter):
    """Listener for double-click on table rows to show Request/Response."""
    def __init__(self, panel, category_key):
        self.panel = panel
        self.category_key = category_key
    
    def mouseClicked(self, event):
        if event.getClickCount() == 2:
            table = event.getSource()
            row = table.getSelectedRow()
            if row >= 0:
                # Convert view row to model row
                model_row = table.convertRowIndexToModel(row)
                self.panel.show_request_response(self.category_key, model_row)


class RequestResponseDialog(JDialog):
    """Dialog showing Request and Response tabs using Burp's message editors."""
    
    def __init__(self, parent, callbacks, message_info, title):
        JDialog.__init__(self, parent, "Request/Response - " + title[:80], True)
        self.callbacks = callbacks
        self.message_info = message_info
        
        self.setSize(900, 600)
        self.setLocationRelativeTo(parent)
        
        self._init_ui()
    
    def _init_ui(self):
        """Build the UI with Request/Response tabs."""
        main_panel = JPanel(BorderLayout())
        
        # Create tabbed pane
        tabs = JTabbedPane()
        
        # Request tab
        request_editor = self.callbacks.createMessageEditor(None, False)
        request = self.message_info.getRequest()
        if request:
            request_editor.setMessage(request, True)
        tabs.addTab("Request", request_editor.getComponent())
        
        # Response tab
        response_editor = self.callbacks.createMessageEditor(None, False)
        response = self.message_info.getResponse()
        if response:
            response_editor.setMessage(response, False)
        tabs.addTab("Response", response_editor.getComponent())
        
        main_panel.add(tabs, BorderLayout.CENTER)
        
        # Close button
        button_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        close_btn = JButton("Close")
        close_btn.addActionListener(DialogCloseAction(self))
        button_panel.add(close_btn)
        main_panel.add(button_panel, BorderLayout.SOUTH)
        
        self.getContentPane().add(main_panel)


class DialogCloseAction(ActionListener):
    """Close action for dialog."""
    def __init__(self, dialog):
        self.dialog = dialog
    def actionPerformed(self, event):
        self.dialog.dispose()
