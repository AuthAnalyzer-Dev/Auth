package com.protect7.authanalyzer.gui.UITesting;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;
import java.util.List;

class ControlsPanel extends JPanel {

    private final JTextField baseUrlField = new JTextField("https://v.ruc.edu.cn/", 28);
    private final JTextField targetUrlField = new JTextField("https://v.ruc.edu.cn/servcenter/front/form/detail/10980/1441/type/3", 28);
    private final JTextField tiupUidField = new JTextField("", 28);
    private final JTextField sessionField = new JTextField("", 28);

    private final JButton startAutomationBtn = new JButton("启动自动化任务");
    private final JButton startDriverBtn = new JButton("启动代理 Driver");
    private final JButton crawlClickBtn = new JButton("抓取并点击页面链接");
    private final JButton clearLogBtn = new JButton("清空日志");

    private final JComboBox<String> sessionChooser = new JComboBox<>();

    ControlsPanel() {
        setLayout(new BorderLayout());

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5,5,5,5);

        int y = 0;
        gbc.gridx=0; gbc.gridy=y; gbc.weightx=0; form.add(new JLabel("Base URL:"), gbc);
        gbc.gridx=1; gbc.gridy=y++; gbc.weightx=1; form.add(baseUrlField, gbc);

        gbc.gridx=0; gbc.gridy=y; gbc.weightx=0; form.add(new JLabel("Target URL:"), gbc);
        gbc.gridx=1; gbc.gridy=y++; gbc.weightx=1; form.add(targetUrlField, gbc);

        gbc.gridx=0; gbc.gridy=y; gbc.weightx=0; form.add(new JLabel("tiup_uid Cookie:"), gbc);
        gbc.gridx=1; gbc.gridy=y++; gbc.weightx=1; form.add(tiupUidField, gbc);

        gbc.gridx=0; gbc.gridy=y; gbc.weightx=0; form.add(new JLabel("session Cookie:"), gbc);
        gbc.gridx=1; gbc.gridy=y++; gbc.weightx=1; form.add(sessionField, gbc);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 6));
        crawlClickBtn.setEnabled(false);
        sessionChooser.setPrototypeDisplayValue("Session (user1)");

        buttons.add(startAutomationBtn);
        buttons.add(startDriverBtn);
        buttons.add(crawlClickBtn);
        buttons.add(new JLabel("Session:"));
        buttons.add(sessionChooser);
        buttons.add(clearLogBtn);

        add(form, BorderLayout.CENTER);
        add(buttons, BorderLayout.SOUTH);
        setPreferredSize(new Dimension(520, 0));
    }

    /* --- 对外API（主面板来读/写/监听） --- */
    String getBaseUrl()   { return baseUrlField.getText(); }
    String getTargetUrl() { return targetUrlField.getText(); }
    String getTiupUid()   { return tiupUidField.getText(); }
    String getSessionStr(){ return sessionField.getText(); }

    void setDriverButtonText(String txt) { startDriverBtn.setText(txt); }
    void setCrawlEnabled(boolean b) { crawlClickBtn.setEnabled(b); }

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

    void onStartAutomation(ActionListener l) { startAutomationBtn.addActionListener(l); }
    void onToggleDriver(ActionListener l)    { startDriverBtn.addActionListener(l); }
    void onCrawl(ActionListener l)           { crawlClickBtn.addActionListener(l); }
    void onSessionChanged(ActionListener l)  { sessionChooser.addActionListener(l); }
    void onClearLog(ActionListener l)        { clearLogBtn.addActionListener(l); }
}
