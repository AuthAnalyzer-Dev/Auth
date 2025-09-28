package com.protect7.authanalyzer.gui.UITesting;

import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.gui.util.RequestTableModel;
import com.protect7.authanalyzer.uitesting.runner.ProxyDriverManager;
import com.protect7.authanalyzer.uitesting.runner.UITestRunner;
import com.protect7.authanalyzer.util.CurrentConfig;
import burp.BurpExtender;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.PrintWriter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

/**
 * UITestingPanel with integrated proxy-driver support.
 *
 * Usage notes:
 *  - Make sure Burp is running and listening on 127.0.0.1:8080 (or change the host/port below).
 *  - If Burp's Intercept is ON it will pause every request. For automated crawling, set Intercept OFF or add a rule to auto-forward.
 */
public class UITestingPanel extends JPanel {
    private JTextField baseUrlField;
    private JTextField targetUrlField;
    private JTextField tiupUidField;
    private JTextField sessionField;
    private JButton startAutomationButton;
    private JButton startDriverButton;
    private JButton crawlClickButton;
    private final PrintWriter stdout;
    private final PrintWriter stderr;

    private final JTextArea requestLogArea = new JTextArea();

    // proxy config (change if needed)
    private static final String PROXY_HOST = "127.0.0.1";
    private static final int PROXY_PORT = 8080;

    // model-binding supports
    private javax.swing.Timer modelBinderTimer;   // 明确使用 Swing 的 Timer
    private RequestTableModel attachedModel;
    private TableModelListener tableListener;

    public UITestingPanel() {
        this(resolveStdout(), resolveStderr());
    }

    public UITestingPanel(PrintWriter stdout, PrintWriter stderr) {
        this.stdout = stdout;
        this.stderr = stderr;
        initUI();
        startModelBinding();
    }

    private void initUI() {
        setLayout(new BorderLayout());

        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5,5,5,5);

        gbc.gridx=0; gbc.gridy=0; formPanel.add(new JLabel("Base URL:"), gbc);
        gbc.gridx=1; gbc.gridy=0; gbc.weightx=1.0;
        baseUrlField = new JTextField("https://v.ruc.edu.cn/", 30);
        formPanel.add(baseUrlField, gbc);

        gbc.gridx=0; gbc.gridy=1; gbc.weightx=0.0; formPanel.add(new JLabel("Target URL:"), gbc);
        gbc.gridx=1; gbc.gridy=1; gbc.weightx=1.0;
        targetUrlField = new JTextField("https://v.ruc.edu.cn/servcenter/front/form/detail/10980/1441/type/3", 30);
        formPanel.add(targetUrlField, gbc);

        gbc.gridx=0; gbc.gridy=2; gbc.weightx=0.0; formPanel.add(new JLabel("tiup_uid Cookie:"), gbc);
        gbc.gridx=1; gbc.gridy=2; gbc.weightx=1.0;
        tiupUidField = new JTextField("", 30);
        formPanel.add(tiupUidField, gbc);

        gbc.gridx=0; gbc.gridy=3; gbc.weightx=0.0; formPanel.add(new JLabel("session Cookie:"), gbc);
        gbc.gridx=1; gbc.gridy=3; gbc.weightx=1.0;
        sessionField = new JTextField("", 30);
        formPanel.add(sessionField, gbc);

        // Buttons (automation + driver + crawl)
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        startAutomationButton = new JButton("启动自动化任务");
        startAutomationButton.addActionListener(this::onStartAutomation);

        startDriverButton = new JButton("启动代理 Driver");
        startDriverButton.addActionListener(this::onToggleDriver);

        crawlClickButton = new JButton("抓取并点击页面链接");
        crawlClickButton.addActionListener(this::onCrawlAndClick);
        crawlClickButton.setEnabled(false); // 初始不可用，等 driver 启动

        JButton clearBtn = new JButton("清空日志");
        clearBtn.addActionListener(e -> requestLogArea.setText(""));

        buttonPanel.add(startAutomationButton);
        buttonPanel.add(startDriverButton);
        buttonPanel.add(crawlClickButton);
        buttonPanel.add(clearBtn);

        JPanel leftContainer = new JPanel(new BorderLayout());
        leftContainer.add(formPanel, BorderLayout.CENTER);
        leftContainer.add(buttonPanel, BorderLayout.SOUTH);
        leftContainer.setPreferredSize(new Dimension(440,0));

        requestLogArea.setEditable(false);
        requestLogArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane logScroll = new JScrollPane(requestLogArea,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        add(leftContainer, BorderLayout.WEST);
        add(logScroll, BorderLayout.CENTER);
    }

    private static PrintWriter resolveStdout() {
        burp.IBurpExtenderCallbacks cb = burp.BurpExtender.callbacks;
        return (cb != null) ? new PrintWriter(cb.getStdout(), true) : new PrintWriter(System.out, true);
    }

    private static PrintWriter resolveStderr() {
        burp.IBurpExtenderCallbacks cb = burp.BurpExtender.callbacks;
        return (cb != null) ? new PrintWriter(cb.getStderr(), true) : new PrintWriter(System.err, true);
    }

    // original automation button (keeps original behavior)
    private void onStartAutomation(ActionEvent e) {
        startAutomationButton.setEnabled(false);
        new Thread(() -> {
            try {
                stdout.println("开始执行自动化任务...");
                UITestRunner.run(baseUrlField.getText(), targetUrlField.getText(),
                        tiupUidField.getText(), sessionField.getText(), stdout, stderr);
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(this, "自动化任务完成！", "任务完成", JOptionPane.INFORMATION_MESSAGE);
                    startAutomationButton.setEnabled(true);
                });
            } catch (Exception ex) {
                stderr.println("执行自动化任务时出错: " + ex.getMessage());
                ex.printStackTrace(stderr);
                SwingUtilities.invokeLater(() -> startAutomationButton.setEnabled(true));
            }
        }, "UITestRunner-Thread").start();
    }

    // 启动/停止 driver（通过 ProxyDriverManager）
    private void onToggleDriver(ActionEvent e) {
        new Thread(() -> {
            try {
                SwingUtilities.invokeLater(() -> startDriverButton.setEnabled(false));
                WebDriver current = ProxyDriverManager.getDriver();
                if (current == null) {
                    stdout.println("[Driver] Starting ChromeDriver with proxy " + PROXY_HOST + ":" + PROXY_PORT);
                    ProxyDriverManager.startDriver(true, PROXY_HOST, PROXY_PORT, false);
                    SwingUtilities.invokeLater(() -> {
                        startDriverButton.setText("停止代理 Driver");
                        crawlClickButton.setEnabled(true);
                    });
                    stdout.println("[Driver] Started");
                } else {
                    stdout.println("[Driver] Stopping ChromeDriver...");
                    ProxyDriverManager.stopDriver();
                    SwingUtilities.invokeLater(() -> {
                        startDriverButton.setText("启动代理 Driver");
                        crawlClickButton.setEnabled(false);
                    });
                    stdout.println("[Driver] Stopped");
                }
            } catch (Exception ex) {
                stderr.println("Driver 切换时出错: " + ex.getMessage());
                ex.printStackTrace(stderr);
            } finally {
                SwingUtilities.invokeLater(() -> startDriverButton.setEnabled(true));
            }
        }, "Driver-Toggle-Thread").start();
    }

    /**
     * 抓取当前页面上的所有链接并依次点击（所有请求走代理）
     * 要求：Driver 已经启动并且当前已打开目标页面（由用户或其它逻辑打开）
     */
    private void onCrawlAndClick(ActionEvent e) {
        new Thread(() -> {
            WebDriver driver = ProxyDriverManager.getDriver();
            if (driver == null) {
                stdout.println("Driver 未启动，请先点击 '启动代理 Driver'");
                return;
            }
            try {
                stdout.println("[Crawl] 开始抓取并点击链接...");
                Thread.sleep(500);

                List<WebElement> anchors = driver.findElements(By.xpath("//a"));
                stdout.println("[Crawl] 找到 " + anchors.size() + " 个 <a> 元素（将过滤）");

                LinkedHashMap<String, WebElement> clickable = new LinkedHashMap<>();
                for (WebElement a : anchors) {
                    try {
                        String text = a.getText();
                        String href = a.getAttribute("href");
                        if ((text == null || text.trim().isEmpty()) && (href == null || href.trim().isEmpty())) {
                            continue;
                        }
                        String key = (text != null && !text.trim().isEmpty()) ? text.trim() : href.trim();
                        if (!clickable.containsKey(key)) {
                            clickable.put(key, a);
                        }
                    } catch (Throwable ignored) {}
                }

                stdout.println("[Crawl] 过滤后 " + clickable.size() + " 个候选链接");

                String targetPage = targetUrlField.getText();
                if (targetPage == null || targetPage.trim().isEmpty()) {
                    targetPage = driver.getCurrentUrl();
                }

                Set<String> visited = new HashSet<>();
                for (Map.Entry<String, WebElement> ent : clickable.entrySet()) {
                    String key = ent.getKey();
                    if (visited.contains(key)) continue;
                    visited.add(key);

                    try {
                        stdout.println("[Crawl] 点击: " + key);
                        WebElement element = ent.getValue();

                        try {
                            element.click();
                        } catch (Exception clickEx) {
                            WebElement fallback = null;
                            String txt = element.getText();
                            if (txt != null && !txt.trim().isEmpty()) {
                                String esc = txt.replace("\"", "\\\"");
                                List<WebElement> found = driver.findElements(
                                        By.xpath("//a[contains(normalize-space(.), \"" + esc + "\")]"));
                                if (!found.isEmpty()) fallback = found.get(0);
                            }
                            if (fallback != null) {
                                fallback.click();
                            } else {
                                try {
                                    ((org.openqa.selenium.JavascriptExecutor) driver)
                                            .executeScript("arguments[0].click();", element);
                                } catch (Throwable jsEx) {
                                    stdout.println("[Crawl] 无法点击元素: " + key + " - " + jsEx.getMessage());
                                }
                            }
                        }

                        Thread.sleep(800);

                        if (targetPage != null && !targetPage.isEmpty()) {
                            driver.get(targetPage);
                            Thread.sleep(600);
                        }
                    } catch (Throwable itemEx) {
                        stderr.println("[Crawl] 点击失败: " + key + " -> " + itemEx.getMessage());
                    }
                }

                stdout.println("[Crawl] 完成，返回目标页面");
                if (targetPage != null && !targetPage.isEmpty()) driver.get(targetPage);
                stdout.println("[Crawl] 任务结束");

            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                stderr.println("[Crawl] 被中断");
            } catch (Throwable ex) {
                stderr.println("[Crawl] 出错: " + ex.getMessage());
                ex.printStackTrace(stderr);
            }
        }, "Crawl-Click-Thread").start();
    }

    // ===== 懒绑定到 RequestTableModel =====
    private void startModelBinding() {
        if (modelBinderTimer != null && modelBinderTimer.isRunning()) return;

        tableListener = e -> {
            if (e.getType() == TableModelEvent.INSERT || e.getType() == TableModelEvent.UPDATE) {
                int first = Math.max(0, e.getFirstRow());
                int last  = Math.max(first, e.getLastRow());
                for (int row = first; row <= last; row++) {
                    final int r = row;
                    SwingUtilities.invokeLater(() -> {
                        try {
                            if (attachedModel == null) return;
                            OriginalRequestResponse orr = attachedModel.getOriginalRequestResponse(r);
                            if (orr != null) appendOriginalRequestResponseToLog(orr);
                        } catch (Exception ex) {
                            stderr.println("读取行失败: " + ex.getMessage());
                        }
                    });
                }
            }
            if (e.getType() == TableModelEvent.UPDATE && e.getFirstRow() == 0 && e.getLastRow() == Integer.MAX_VALUE) {
                SwingUtilities.invokeLater(this::drainExistingRows);
            }
        };

        modelBinderTimer = new javax.swing.Timer(500, evt -> {
            try {
                RequestTableModel tm = CurrentConfig.getCurrentConfig().getTableModel();
                if (tm == null) return;

                if (tm != attachedModel) {
                    if (attachedModel != null && tableListener != null) {
                        attachedModel.removeTableModelListener(tableListener);
                    }
                    attachedModel = tm;
                    attachedModel.addTableModelListener(tableListener);
                    stdout.println("[UITestingPanel] Attached to RequestTableModel@" + System.identityHashCode(tm));
                    drainExistingRows();
                }
            } catch (Exception ex) {
                stderr.println("绑定 TableModel 失败: " + ex.getMessage());
            }
        });
        modelBinderTimer.setRepeats(true);
        modelBinderTimer.start();
    }

    private void stopModelBinding() {
        if (modelBinderTimer != null) modelBinderTimer.stop();
        if (attachedModel != null && tableListener != null) {
            try { attachedModel.removeTableModelListener(tableListener); } catch (Exception ignored) {}
        }
    }

    @Override public void addNotify() {
        super.addNotify();
        startModelBinding();
    }
    @Override public void removeNotify() {
        stopModelBinding();
        super.removeNotify();
    }

    private void drainExistingRows() {
        if (attachedModel == null) return;
        int rows = attachedModel.getRowCount();
        for (int r = 0; r < rows; r++) {
            OriginalRequestResponse orr = attachedModel.getOriginalRequestResponse(r);
            if (orr != null) appendOriginalRequestResponseToLog(orr);
        }
        requestLogArea.setCaretPosition(requestLogArea.getDocument().getLength());
    }

    private void appendOriginalRequestResponseToLog(OriginalRequestResponse orr) {
        if (orr == null) return;
        try {
            StringBuilder sb = new StringBuilder(512);
            sb.append("=== Original ID: ").append(orr.getId()).append(" ===\n");
            sb.append("Method: ").append(orr.getMethod()).append("\n");
            sb.append("Host: ").append(orr.getHost()).append("\n");
            sb.append("URL: ").append(orr.getUrl()).append("\n");
            sb.append("StatusCode: ").append(orr.getStatusCode()).append("\n");
            sb.append("Response Length: ").append(orr.getResponseContentLength()).append("\n");
            sb.append("--- Raw Request Start ---\n");

            try {
                burp.IHttpRequestResponse rr = orr.getRequestResponse();
                if (rr != null && rr.getRequest() != null) {
                    String reqText = BurpExtender.callbacks.getHelpers().bytesToString(rr.getRequest());
                    sb.append(reqText);
                } else {
                    sb.append("[no request bytes]\n");
                }
            } catch (Throwable t) {
                sb.append("[failed to read raw request: ").append(t.getMessage()).append("]\n");
            }

            sb.append("\n--- Raw Request End ---\n\n");

            requestLogArea.append(sb.toString());
            requestLogArea.setCaretPosition(requestLogArea.getDocument().getLength());
        } catch (Exception e) {
            stderr.println("appendOriginalRequestResponseToLog 出错: " + e.getMessage());
        }
    }
}
