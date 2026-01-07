# -*- coding: utf-8 -*-
"""
JSCollector - Pattern Configuration Dialog
UI for managing custom regex patterns and categories.
"""

from javax.swing import (
    JDialog, JPanel, JScrollPane, JTabbedPane, JButton, JLabel,
    JTable, JComboBox, JTextField, JTextArea, BorderFactory,
    JOptionPane, BoxLayout, Box
)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, FlowLayout, GridBagLayout, GridBagConstraints, Insets, Font, Dimension
from java.awt.event import ActionListener


class PatternConfigDialog(JDialog):
    """Dialog for managing custom patterns and categories."""
    
    def __init__(self, parent, pattern_manager):
        JDialog.__init__(self, parent, "JSCollector Settings", True)
        self.pattern_manager = pattern_manager
        
        self.setSize(700, 500)
        self.setLocationRelativeTo(parent)
        
        self._init_ui()
        self._refresh_tables()
    
    def _init_ui(self):
        """Build the UI."""
        main_panel = JPanel(BorderLayout(10, 10))
        main_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # ===== TABS =====
        self.tabs = JTabbedPane()
        
        # Patterns tab
        self.tabs.addTab("Custom Patterns", self._create_patterns_panel())
        
        # Categories tab
        self.tabs.addTab("Custom Categories", self._create_categories_panel())
        
        # Settings tab
        self.tabs.addTab("Settings", self._create_settings_panel())
        
        main_panel.add(self.tabs, BorderLayout.CENTER)
        
        # ===== BUTTONS =====
        button_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        
        close_btn = JButton("Close")
        close_btn.addActionListener(CloseAction(self))
        button_panel.add(close_btn)
        
        main_panel.add(button_panel, BorderLayout.SOUTH)
        
        self.getContentPane().add(main_panel)
    
    def _create_patterns_panel(self):
        """Create the patterns management panel."""
        panel = JPanel(BorderLayout(5, 5))
        
        # Category selector and add form at top
        top_panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.fill = GridBagConstraints.HORIZONTAL
        
        # Row 1: Category selector
        gbc.gridx = 0
        gbc.gridy = 0
        top_panel.add(JLabel("Category:"), gbc)
        
        gbc.gridx = 1
        gbc.weightx = 1.0
        self.category_combo = JComboBox(["endpoints", "urls", "secrets"])
        self.category_combo.addActionListener(CategoryChangeAction(self))
        top_panel.add(self.category_combo, gbc)
        
        # Row 2: Regex input
        gbc.gridx = 0
        gbc.gridy = 1
        gbc.weightx = 0
        top_panel.add(JLabel("Regex:"), gbc)
        
        gbc.gridx = 1
        gbc.weightx = 1.0
        self.regex_field = JTextField(40)
        top_panel.add(self.regex_field, gbc)
        
        # Row 3: Name input
        gbc.gridx = 0
        gbc.gridy = 2
        gbc.weightx = 0
        top_panel.add(JLabel("Name:"), gbc)
        
        gbc.gridx = 1
        gbc.weightx = 1.0
        self.name_field = JTextField(40)
        top_panel.add(self.name_field, gbc)
        
        # Row 4: Add button
        gbc.gridx = 1
        gbc.gridy = 3
        gbc.weightx = 0
        gbc.anchor = GridBagConstraints.EAST
        add_btn = JButton("Add Pattern")
        add_btn.addActionListener(AddPatternAction(self))
        top_panel.add(add_btn, gbc)
        
        panel.add(top_panel, BorderLayout.NORTH)
        
        # Table for existing patterns
        columns = ["Name", "Regex"]
        self.patterns_model = NonEditableTableModel(columns, 0)
        self.patterns_table = JTable(self.patterns_model)
        self.patterns_table.setFont(Font("Monospaced", Font.PLAIN, 11))
        self.patterns_table.getColumnModel().getColumn(0).setPreferredWidth(150)
        self.patterns_table.getColumnModel().getColumn(1).setPreferredWidth(400)
        
        scroll = JScrollPane(self.patterns_table)
        panel.add(scroll, BorderLayout.CENTER)
        
        # Remove button
        remove_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        remove_btn = JButton("Remove Selected")
        remove_btn.addActionListener(RemovePatternAction(self))
        remove_panel.add(remove_btn)
        panel.add(remove_panel, BorderLayout.SOUTH)
        
        return panel
    
    def _create_categories_panel(self):
        """Create the categories management panel."""
        panel = JPanel(BorderLayout(5, 5))
        
        # Add form
        top_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        top_panel.add(JLabel("Key:"))
        self.cat_key_field = JTextField(15)
        top_panel.add(self.cat_key_field)
        
        top_panel.add(JLabel("Display Name:"))
        self.cat_name_field = JTextField(20)
        top_panel.add(self.cat_name_field)
        
        add_cat_btn = JButton("Add Category")
        add_cat_btn.addActionListener(AddCategoryAction(self))
        top_panel.add(add_cat_btn)
        
        panel.add(top_panel, BorderLayout.NORTH)
        
        # Table for existing categories
        columns = ["Key", "Display Name", "Patterns"]
        self.categories_model = NonEditableTableModel(columns, 0)
        self.categories_table = JTable(self.categories_model)
        
        scroll = JScrollPane(self.categories_table)
        panel.add(scroll, BorderLayout.CENTER)
        
        # Info label
        info = JLabel("Note: Custom categories appear as new tabs in the results panel.")
        info.setFont(Font("SansSerif", Font.ITALIC, 11))
        panel.add(info, BorderLayout.SOUTH)
        
        return panel
    
    def _create_settings_panel(self):
        """Create the settings panel."""
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20))
        
        # Passive mode toggle
        settings = self.pattern_manager.get_settings()
        
        passive_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        passive_panel.add(JLabel("Passive Mode:"))
        self.passive_combo = JComboBox(["Enabled", "Disabled"])
        self.passive_combo.setSelectedIndex(0 if settings.get("passive_mode", True) else 1)
        passive_panel.add(self.passive_combo)
        passive_panel.add(JLabel("(Auto-analyze responses passing through proxy)"))
        panel.add(passive_panel)
        
        panel.add(Box.createVerticalStrut(10))
        
        # Scope only toggle
        scope_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        scope_panel.add(JLabel("Scope Only:"))
        self.scope_combo = JComboBox(["Disabled", "Enabled"])
        self.scope_combo.setSelectedIndex(1 if settings.get("scope_only", False) else 0)
        scope_panel.add(self.scope_combo)
        scope_panel.add(JLabel("(Only analyze targets in Burp scope)"))
        panel.add(scope_panel)
        
        panel.add(Box.createVerticalStrut(15))
        
        # Content type collection section header
        header_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        header_label = JLabel("Collect From:")
        header_label.setFont(Font("SansSerif", Font.BOLD, 12))
        header_panel.add(header_label)
        panel.add(header_panel)
        
        panel.add(Box.createVerticalStrut(5))
        
        # Collect from JS files checkbox
        js_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        from javax.swing import JCheckBox
        self.collect_js_checkbox = JCheckBox("JavaScript files (script files, .js)")
        self.collect_js_checkbox.setSelected(settings.get("collect_js", True))
        js_panel.add(self.collect_js_checkbox)
        panel.add(js_panel)
        
        # Collect from HTML files checkbox
        html_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.collect_html_checkbox = JCheckBox("HTML files (inline scripts in HTML)")
        self.collect_html_checkbox.setSelected(settings.get("collect_html", False))
        html_panel.add(self.collect_html_checkbox)
        panel.add(html_panel)
        
        panel.add(Box.createVerticalStrut(20))
        
        # Save button
        save_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        save_btn = JButton("Save Settings")
        save_btn.addActionListener(SaveSettingsAction(self))
        save_panel.add(save_btn)
        panel.add(save_panel)
        
        # Spacer
        panel.add(Box.createVerticalGlue())
        
        return panel
    
    def _refresh_tables(self):
        """Refresh pattern and category tables."""
        # Refresh patterns table
        self.patterns_model.setRowCount(0)
        category = str(self.category_combo.getSelectedItem())
        patterns = self.pattern_manager.get_custom_patterns_list(category)
        for p in patterns:
            self.patterns_model.addRow([p.get("name", ""), p.get("regex", "")])
        
        # Update category combo with custom categories
        current = str(self.category_combo.getSelectedItem())
        self.category_combo.removeAllItems()
        for cat in ["endpoints", "urls", "secrets"]:
            self.category_combo.addItem(cat)
        for cat_key in self.pattern_manager.config.get("custom_categories", {}).keys():
            self.category_combo.addItem(cat_key)
        
        # Restore selection
        for i in range(self.category_combo.getItemCount()):
            if str(self.category_combo.getItemAt(i)) == current:
                self.category_combo.setSelectedIndex(i)
                break
        
        # Refresh categories table
        self.categories_model.setRowCount(0)
        for key, data in self.pattern_manager.config.get("custom_categories", {}).items():
            pattern_count = len(data.get("patterns", []))
            self.categories_model.addRow([key, data.get("display_name", key), str(pattern_count)])
    
    def add_pattern(self):
        """Add a new pattern."""
        category = str(self.category_combo.getSelectedItem())
        regex = self.regex_field.getText().strip()
        name = self.name_field.getText().strip()
        
        if not regex:
            JOptionPane.showMessageDialog(self, "Regex is required", "Error", JOptionPane.ERROR_MESSAGE)
            return
        
        if not name:
            name = "Custom Pattern"
        
        success, error = self.pattern_manager.add_custom_pattern(category, regex, name)
        
        if success:
            self.regex_field.setText("")
            self.name_field.setText("")
            self._refresh_tables()
            JOptionPane.showMessageDialog(self, "Pattern added successfully", "Success", JOptionPane.INFORMATION_MESSAGE)
        else:
            JOptionPane.showMessageDialog(self, error, "Error", JOptionPane.ERROR_MESSAGE)
    
    def remove_pattern(self):
        """Remove selected pattern."""
        row = self.patterns_table.getSelectedRow()
        if row < 0:
            JOptionPane.showMessageDialog(self, "Select a pattern to remove", "Error", JOptionPane.ERROR_MESSAGE)
            return
        
        category = str(self.category_combo.getSelectedItem())
        success, error = self.pattern_manager.remove_custom_pattern(category, row)
        
        if success:
            self._refresh_tables()
        else:
            JOptionPane.showMessageDialog(self, error, "Error", JOptionPane.ERROR_MESSAGE)
    
    def add_category(self):
        """Add a new custom category."""
        key = self.cat_key_field.getText().strip().lower().replace(" ", "_")
        name = self.cat_name_field.getText().strip()
        
        if not key:
            JOptionPane.showMessageDialog(self, "Category key is required", "Error", JOptionPane.ERROR_MESSAGE)
            return
        
        if not name:
            name = key.title()
        
        success, error = self.pattern_manager.add_custom_category(key, name)
        
        if success:
            self.cat_key_field.setText("")
            self.cat_name_field.setText("")
            self._refresh_tables()
            JOptionPane.showMessageDialog(self, "Category added. Restart extension to see new tab.", "Success", JOptionPane.INFORMATION_MESSAGE)
        else:
            JOptionPane.showMessageDialog(self, error, "Error", JOptionPane.ERROR_MESSAGE)
    
    def save_settings(self):
        """Save settings."""
        settings = {
            "passive_mode": self.passive_combo.getSelectedIndex() == 0,
            "scope_only": self.scope_combo.getSelectedIndex() == 1,
            "collect_js": self.collect_js_checkbox.isSelected(),
            "collect_html": self.collect_html_checkbox.isSelected()
        }
        self.pattern_manager.update_settings(settings)
        JOptionPane.showMessageDialog(self, "Settings saved", "Success", JOptionPane.INFORMATION_MESSAGE)


class NonEditableTableModel(DefaultTableModel):
    def __init__(self, columns, rows):
        DefaultTableModel.__init__(self, columns, rows)
    
    def isCellEditable(self, row, column):
        return False


class CloseAction(ActionListener):
    def __init__(self, dialog):
        self.dialog = dialog
    def actionPerformed(self, event):
        self.dialog.dispose()


class CategoryChangeAction(ActionListener):
    def __init__(self, dialog):
        self.dialog = dialog
    def actionPerformed(self, event):
        self.dialog._refresh_tables()


class AddPatternAction(ActionListener):
    def __init__(self, dialog):
        self.dialog = dialog
    def actionPerformed(self, event):
        self.dialog.add_pattern()


class RemovePatternAction(ActionListener):
    def __init__(self, dialog):
        self.dialog = dialog
    def actionPerformed(self, event):
        self.dialog.remove_pattern()


class AddCategoryAction(ActionListener):
    def __init__(self, dialog):
        self.dialog = dialog
    def actionPerformed(self, event):
        self.dialog.add_category()


class SaveSettingsAction(ActionListener):
    def __init__(self, dialog):
        self.dialog = dialog
    def actionPerformed(self, event):
        self.dialog.save_settings()
