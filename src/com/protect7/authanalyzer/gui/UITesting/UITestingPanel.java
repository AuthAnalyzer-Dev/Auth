package com.protect7.authanalyzer.gui.UITesting;

import com.protect7.authanalyzer.uitesting.runner.UITestRunner;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;

public class UITestingPanel extends JPanel {
    private JTextField baseUrlField;
    private JTextField targetUrlField;
    private JTextField tiupUidField;
    private JTextField sessionField;
    private JButton startButton;
    private final PrintWriter stdout;
    private final PrintWriter stderr;

    // 无参构造：从 Burp 的 callbacks 获取输出流，然后委托给双参构造
    public UITestingPanel() {
        this(resolveStdout(), resolveStderr());
    }

    // 你原来的双参构造：真正完成依赖注入
    public UITestingPanel(PrintWriter stdout, PrintWriter stderr) {
        this.stdout = stdout;
        this.stderr = stderr;
        initUI();
    }

    // 统一把UI初始化的代码放这里，两个构造都能复用
    private void initUI() {
        setLayout(new BorderLayout());

        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        gbc.gridx = 0; gbc.gridy = 0; formPanel.add(new JLabel("Base URL:"), gbc);
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0;
        baseUrlField = new JTextField("https://v.ruc.edu.cn/", 30);
        formPanel.add(baseUrlField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0.0; formPanel.add(new JLabel("Target URL:"), gbc);
        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1.0;
        targetUrlField = new JTextField("https://v.ruc.edu.cn/servcenter/front/form/detail/10980/1441/type/3", 30);
        formPanel.add(targetUrlField, gbc);

        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0.0; formPanel.add(new JLabel("tiup_uid Cookie:"), gbc);
        gbc.gridx = 1; gbc.gridy = 2; gbc.weightx = 1.0;
        tiupUidField = new JTextField("66a8cd9c90f4d1021d8c0885", 30);
        formPanel.add(tiupUidField, gbc);

        gbc.gridx = 0; gbc.gridy = 3; gbc.weightx = 0.0; formPanel.add(new JLabel("session Cookie:"), gbc);
        gbc.gridx = 1; gbc.gridy = 3; gbc.weightx = 1.0;
        sessionField = new JTextField("ebcf93eb41704623907f650aff71bd14.f508b4f2c00344af9bfeda2d8588c930", 30);
        formPanel.add(sessionField, gbc);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        startButton = new JButton("启动自动化任务");
        startButton.addActionListener(new ActionListener() {
            @Override public void actionPerformed(ActionEvent e) { startAutomation(); }
        });
        buttonPanel.add(startButton);

        add(formPanel, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    private static PrintWriter resolveStdout() {
        burp.IBurpExtenderCallbacks cb = burp.BurpExtender.callbacks;
        return (cb != null) ? new PrintWriter(cb.getStdout(), true)
                : new PrintWriter(System.out, true);
    }

    private static PrintWriter resolveStderr() {
        burp.IBurpExtenderCallbacks cb = burp.BurpExtender.callbacks;
        return (cb != null) ? new PrintWriter(cb.getStderr(), true)
                : new PrintWriter(System.err, true);
    }

    private void startAutomation() {
        startButton.setEnabled(false);
        new Thread(() -> {
            try {
                stdout.println("开始执行自动化任务...");
                String baseUrl = baseUrlField.getText();
                String targetUrl = targetUrlField.getText();
                String tiupUid = tiupUidField.getText();
                String session = sessionField.getText();

                UITestRunner.run(baseUrl, targetUrl, tiupUid, session, stdout, stderr);

                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(this, "自动化任务完成！", "任务完成", JOptionPane.INFORMATION_MESSAGE);
                    startButton.setEnabled(true);
                });
            } catch (Exception ex) {
                stderr.println("执行自动化任务时出错: " + ex.getMessage());
                ex.printStackTrace(stderr);
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(this, "执行自动化任务时出错: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                    startButton.setEnabled(true);
                });
            }
        }).start();
    }
}
