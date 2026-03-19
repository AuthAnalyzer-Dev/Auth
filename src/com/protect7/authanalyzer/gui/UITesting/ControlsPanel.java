package com.protect7.authanalyzer.gui.UITesting;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionListener;
import java.util.List;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

import com.protect7.authanalyzer.gui.util.PlaceholderTextArea;

class ControlsPanel extends JPanel {

    private static final int TEXT_AREA_COLUMNS = 48;

    private final JTextField targetUrlField = new JTextField("https://v.ruc.edu.cn/servcenter/front/form/detail/10980/1441/type/3", 22);
    private final PlaceholderTextArea headersToReplaceText = new PlaceholderTextArea(3, TEXT_AREA_COLUMNS);

    private final JButton crawlClickBtn = new JButton("抓取并点击页面链接");
    private final JButton clearLogBtn = new JButton("清空日志");
    private final JButton clearTableBtn = new JButton("清空表格");

    private final JCheckBox discoverFromJsCheck = new JCheckBox("从 JS 提取", true);
    private final JCheckBox discoverFromSwaggerCheck = new JCheckBox("从 Swagger 探测", true);
    private final JButton discoverBtn = new JButton("发现隐藏 API");

    private final JComboBox<String> sessionChooser = new JComboBox<>();

    private final JPanel originalSectionPanel;
    private final JPanel targetUrlSectionPanel;
    private final JPanel apiDiscoveryPanel;
    private final JPanel buttonsPanel;

    ControlsPanel() {
        this(false);
    }

    ControlsPanel(boolean mergedMode) {
        setLayout(new BorderLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        originalSectionPanel = new JPanel(new GridBagLayout());
        JLabel headerToReplaceLabel = new JLabel("Header(s) to Replace");
        headersToReplaceText.setAlignmentX(Component.LEFT_ALIGNMENT);
        headersToReplaceText.setPlaceholder("Cookie: access_token=xxx\nCookie: session=xxx\nCookie: name=value");
        headersToReplaceText.setToolTipText(
                "<html>支持任意 Cookie，每行一个 Header 或分号分隔。如：<br>Cookie: access_token=xxx<br>Cookie: session=xxx; tiup_uid=yyy</html>");
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2; gbc.weightx = 1; gbc.weighty = 0;
        originalSectionPanel.add(headerToReplaceLabel, gbc);
        gbc.gridy = 1; gbc.weighty = 1;
        originalSectionPanel.add(headersToReplaceText, gbc);

        targetUrlSectionPanel = new JPanel(new GridBagLayout());
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 1; gbc.weightx = 1; gbc.weighty = 0;
        targetUrlSectionPanel.add(new JLabel("Target URL:"), gbc);
        gbc.gridy = 1; gbc.weighty = 1;
        targetUrlSectionPanel.add(targetUrlField, gbc);

        apiDiscoveryPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        apiDiscoveryPanel.add(new JLabel("API 发现:"));
        apiDiscoveryPanel.add(discoverFromJsCheck);
        apiDiscoveryPanel.add(discoverFromSwaggerCheck);
        apiDiscoveryPanel.add(discoverBtn);

        buttonsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 6));
        sessionChooser.setPrototypeDisplayValue("Session (user1)");
        buttonsPanel.add(crawlClickBtn);
        buttonsPanel.add(clearLogBtn);
        buttonsPanel.add(clearTableBtn);
        buttonsPanel.add(new JLabel("Session:"));
        buttonsPanel.add(sessionChooser);

        if (!mergedMode) {
            JPanel form = new JPanel();
            form.setLayout(new BoxLayout(form, BoxLayout.Y_AXIS));
            form.add(originalSectionPanel);
            form.add(Box.createVerticalStrut(6));
            form.add(targetUrlSectionPanel);
            form.add(Box.createVerticalStrut(6));
            form.add(apiDiscoveryPanel);
            add(form, BorderLayout.CENTER);
            add(buttonsPanel, BorderLayout.SOUTH);
        }
        setPreferredSize(new Dimension(460, 0));
    }

    JPanel getOriginalSectionPanel() { return originalSectionPanel; }
    JPanel getTargetUrlSectionPanel() { return targetUrlSectionPanel; }
    JPanel getApiDiscoveryPanel() { return apiDiscoveryPanel; }
    JPanel getButtonsPanel() { return buttonsPanel; }

    boolean isDiscoverFromJsSelected() { return discoverFromJsCheck.isSelected(); }
    boolean isDiscoverFromSwaggerSelected() { return discoverFromSwaggerCheck.isSelected(); }

    /* --- 对外API（主面板来读/写/监听） --- */
    String getTargetUrl() { return targetUrlField.getText(); }
    String getHeadersToReplaceText() { return headersToReplaceText.getText(); }
    void setHeadersToReplaceText(String text) { headersToReplaceText.setText(text != null ? text : ""); }

    void setSessions(List<String> names) {
        sessionChooser.removeAllItems();
        if (names == null || names.isEmpty()) {
            sessionChooser.addItem("(no sessions)");
            sessionChooser.setEnabled(false);
            return;
        }
        for (String n : names) sessionChooser.addItem(n);
        sessionChooser.setEnabled(true);
    }

    int getSelectedSessionIndex() { return sessionChooser.getSelectedIndex(); }
    String getSelectedSessionName() {
        Object o = sessionChooser.getSelectedItem();
        return o == null ? "(no session)" : o.toString();
    }

    void onCrawl(ActionListener l)           { crawlClickBtn.addActionListener(l); }
    void onDiscover(ActionListener l)         { discoverBtn.addActionListener(l); }
    /** 程序化触发抓取（如 Run2 后自动执行） */
    void triggerCrawl()                     { crawlClickBtn.doClick(); }
    void onClearTable(ActionListener l)      { clearTableBtn.addActionListener(l); }
    void onSessionChanged(ActionListener l)  { sessionChooser.addActionListener(l); }
    void onClearLog(ActionListener l)        { clearLogBtn.addActionListener(l); }
}
