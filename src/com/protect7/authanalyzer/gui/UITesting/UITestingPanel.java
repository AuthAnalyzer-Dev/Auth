package com.protect7.authanalyzer.gui.UITesting;

import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.util.RequestTableModel;
import com.protect7.authanalyzer.uitesting.runner.ProxyDriverManager;
import com.protect7.authanalyzer.uitesting.runner.UITestRunner;
import com.protect7.authanalyzer.util.CurrentConfig;
import burp.BurpExtender;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class UITestingPanel extends JPanel {

    private final PrintWriter stdout;
    private final PrintWriter stderr;

    private final ControlsPanel controls = new ControlsPanel();
    private final RequestTablePanel tablePanel = new RequestTablePanel();
    private final DetailPanel details = new DetailPanel();

    private javax.swing.Timer modelBinderTimer;       // Swing Timer
    private RequestTableModel attachedModel;
    private TableModelListener tableListener;

    // proxy config
    private static final String PROXY_HOST = "127.0.0.1";
    private static final int PROXY_PORT = 8080;

    public UITestingPanel() {
        this(resolveStdout(), resolveStderr());
    }

    public UITestingPanel(PrintWriter stdout, PrintWriter stderr) {
        this.stdout = stdout;
        this.stderr = stderr;
        initUI();
        wireEvents();
        startModelBinding();
    }

    private void initUI() {
        setLayout(new BorderLayout());

        JSplitPane center = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                tablePanel, details);
        center.setResizeWeight(0.55);

        add(controls, BorderLayout.WEST);
        add(center, BorderLayout.CENTER);
    }

    private void wireEvents() {
        controls.onStartAutomation(this::onStartAutomation);
        controls.onToggleDriver(this::onToggleDriver);
        controls.onCrawl(this::onCrawlClick);
        controls.onSessionChanged(e -> {
            details.setSessionTabTitle(controls.getSelectedSessionName());
            refreshSelectedRowDetails();
        });
        controls.onClearLog(e -> details.appendLog("[Log cleared]"));

        tablePanel.addSelectionListener(new ListSelectionListener() {
            @Override public void valueChanged(ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) refreshSelectedRowDetails();
            }
        });
    }

    /* ================= 主动作 ================= */

    private void onStartAutomation(ActionEvent e) {
        ((JButton)e.getSource()).setEnabled(false);
        new Thread(() -> {
            try {
                log("[Run] 自动化任务开始");
                UITestRunner.run(controls.getBaseUrl(), controls.getTargetUrl(),
                        controls.getTiupUid(), controls.getSessionStr(), stdout, stderr);
                SwingUtilities.invokeLater(() ->
                        JOptionPane.showMessageDialog(this, "自动化任务完成！", "任务完成", JOptionPane.INFORMATION_MESSAGE));
            } catch (Exception ex) {
                log("[Run] 出错: " + ex.getMessage());
                ex.printStackTrace(stderr);
            } finally {
                SwingUtilities.invokeLater(() -> ((JButton)e.getSource()).setEnabled(true));
            }
        }, "UITestRunner-Thread").start();
    }

    private void onToggleDriver(ActionEvent e) {
        JButton btn = (JButton)e.getSource();
        btn.setEnabled(false);
        new Thread(() -> {
            try {
                if (ProxyDriverManager.getDriver() == null) {
                    log("[Driver] Starting with proxy " + PROXY_HOST + ":" + PROXY_PORT);
                    ProxyDriverManager.startDriver(true, PROXY_HOST, PROXY_PORT, false);
                    SwingUtilities.invokeLater(() -> {
                        controls.setDriverButtonText("停止代理 Driver");
                        controls.setCrawlEnabled(true);
                    });
                    log("[Driver] Started");
                } else {
                    log("[Driver] Stopping...");
                    ProxyDriverManager.stopDriver();
                    SwingUtilities.invokeLater(() -> {
                        controls.setDriverButtonText("启动代理 Driver");
                        controls.setCrawlEnabled(false);
                    });
                    log("[Driver] Stopped");
                }
            } catch (Exception ex) {
                log("[Driver] Error: " + ex.getMessage());
                ex.printStackTrace(stderr);
            } finally {
                SwingUtilities.invokeLater(() -> btn.setEnabled(true));
            }
        }, "Driver-Toggle-Thread").start();
    }

    private void onCrawlClick(ActionEvent e) {
        new Thread(() -> {
            WebDriver driver = ProxyDriverManager.getDriver();
            if (driver == null) { log("Driver 未启动"); return; }
            try {
                log("[Crawl] 抓取并点击...");
                Thread.sleep(300);

                List<WebElement> anchors = driver.findElements(By.xpath("//a"));
                log("[Crawl] <a> 数量: " + anchors.size());

                LinkedHashMap<String, WebElement> clickable = new LinkedHashMap<String, WebElement>();
                for (WebElement a : anchors) {
                    try {
                        String text = a.getText();
                        String href = a.getAttribute("href");
                        boolean textEmpty = (text == null || text.trim().isEmpty());
                        boolean hrefEmpty = (href == null || href.trim().isEmpty());
                        if (textEmpty && hrefEmpty) continue;
                        String key = (!textEmpty) ? text.trim() : href.trim();
                        if (!clickable.containsKey(key)) clickable.put(key, a);
                    } catch (Throwable ignore) {}
                }
                log("[Crawl] 候选: " + clickable.size());

                String targetPage = controls.getTargetUrl();
                if (targetPage == null || targetPage.trim().isEmpty()) targetPage = driver.getCurrentUrl();

                Set<String> visited = new HashSet<String>();
                for (Map.Entry<String, WebElement> ent : clickable.entrySet()) {
                    String key = ent.getKey();
                    if (!visited.add(key)) continue;
                    try {
                        log("[Crawl] 点击: " + key);
                        WebElement el = ent.getValue();
                        try { el.click(); }
                        catch (Exception clickEx) {
                            try {
                                ((JavascriptExecutor) driver).executeScript("arguments[0].click();", el);
                            } catch (Throwable jsEx) {
                                log("[Crawl] JS 点击失败: " + jsEx.getMessage());
                            }
                        }
                        Thread.sleep(600);
                        if (targetPage != null && !targetPage.isEmpty()) {
                            driver.get(targetPage);
                            Thread.sleep(400);
                        }
                    } catch (Throwable t) {
                        log("[Crawl] 点击失败: " + key + " -> " + t.getMessage());
                    }
                }
                log("[Crawl] 完成");
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                log("[Crawl] 中断");
            } catch (Throwable ex) {
                log("[Crawl] 出错: " + ex.getMessage());
                ex.printStackTrace(stderr);
            }
        }, "Crawl-Click-Thread").start();
    }

    /* ================= 绑定模型/刷新视图 ================= */

    private void startModelBinding() {
        if (modelBinderTimer != null && modelBinderTimer.isRunning()) return;

        tableListener = new TableModelListener() {
            @Override public void tableChanged(TableModelEvent e) {
                if (e.getType() == TableModelEvent.INSERT || e.getType() == TableModelEvent.UPDATE) {
                    SwingUtilities.invokeLater(new Runnable() {
                        @Override public void run() {
                            tablePanel.autoSelectLastRowIfNone();
                        }
                    });
                }
            }
        };

        modelBinderTimer = new javax.swing.Timer(500, ev -> {
            try {
                RequestTableModel tm = CurrentConfig.getCurrentConfig().getTableModel();
                if (tm == null) return;

                if (tm != attachedModel) {
                    if (attachedModel != null && tableListener != null) {
                        attachedModel.removeTableModelListener(tableListener);
                    }
                    attachedModel = tm;
                    attachedModel.addTableModelListener(tableListener);

                    tablePanel.bindModel(attachedModel);
                    log("[UITestingPanel] attached model @" + System.identityHashCode(tm));

                    // 刷新 Session 列表和标题
                    refreshSessions();
                    details.setSessionTabTitle(controls.getSelectedSessionName());
                    refreshSelectedRowDetails();
                }
            } catch (Exception ex) {
                log("绑定 TableModel 失败: " + ex.getMessage());
            }
        });
        modelBinderTimer.setRepeats(true);
        modelBinderTimer.start();
    }

    private void refreshSessions() {
        List<Session> ss = CurrentConfig.getCurrentConfig().getSessions();
        List<String> names = new ArrayList<String>();
        if (ss != null) {
            for (Session s : ss) {
                names.add(s.getName());
            }
        }
        controls.setSessions(names);
    }

    private void refreshSelectedRowDetails() {
        OriginalRequestResponse orr = tablePanel.getSelectedORR();
        details.showOriginal(orr);

        AnalyzerRequestResponse arr = null;
        int idx = controls.getSelectedSessionIndex();
        List<Session> sessions = CurrentConfig.getCurrentConfig().getSessions();
        if (orr != null && sessions != null && idx >= 0 && idx < sessions.size()) {
            Session s = sessions.get(idx);
            if (s != null) {
                arr = s.getRequestResponseMap().get(orr.getId());
            }
        }
        details.showSession(arr);
    }

    /* ================= 小工具 ================= */

    private void log(String msg) {
        stdout.println(msg);
        SwingUtilities.invokeLater(() -> details.appendLog(msg));
    }

    private static PrintWriter resolveStdout() {
        burp.IBurpExtenderCallbacks cb = burp.BurpExtender.callbacks;
        return (cb != null) ? new PrintWriter(cb.getStdout(), true) : new PrintWriter(System.out, true);
    }
    private static PrintWriter resolveStderr() {
        burp.IBurpExtenderCallbacks cb = burp.BurpExtender.callbacks;
        return (cb != null) ? new PrintWriter(cb.getStderr(), true) : new PrintWriter(System.err, true);
    }
}
