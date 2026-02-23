package com.protect7.authanalyzer.gui.UITesting;

import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.util.RequestTableModel;
import com.protect7.authanalyzer.uitesting.runner.ProxyDriverManager;
import com.protect7.authanalyzer.util.CurrentConfig;
import burp.BurpExtender;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
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

    private void onCrawlClick(ActionEvent e) {
        new Thread(() -> {
            try {
                WebDriver driver = ProxyDriverManager.getOrStartDriver(true, PROXY_HOST, PROXY_PORT, false);
                String targetPage = controls.getTargetUrl();
                if (targetPage == null || targetPage.trim().isEmpty()) {
                    log("[Crawl] 请先配置 Target URL");
                    return;
                }

                log("[Crawl] 导航至目标页面并设置 Cookie...");
                driver.get(targetPage);
                Thread.sleep(500);

                String tiupUid = controls.getTiupUid();
                String session = controls.getSessionStr();
                if (tiupUid != null && !tiupUid.trim().isEmpty() || session != null && !session.trim().isEmpty()) {
                    String domain = getDomainFromUrl(targetPage);
                    if (domain != null) {
                        try {
                            if (tiupUid != null && !tiupUid.trim().isEmpty()) {
                                driver.manage().addCookie(new Cookie.Builder("tiup_uid", tiupUid.trim())
                                        .domain(domain).path("/").build());
                                log("[Crawl] 已设置 tiup_uid Cookie");
                            }
                            if (session != null && !session.trim().isEmpty()) {
                                driver.manage().addCookie(new Cookie.Builder("session", session.trim())
                                        .domain(domain).path("/").build());
                                log("[Crawl] 已设置 session Cookie");
                            }
                            driver.get(targetPage);
                            Thread.sleep(500);
                        } catch (Exception cex) {
                            log("[Crawl] 设置 Cookie 失败: " + cex.getMessage());
                        }
                    }
                }

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

                Set<String> visited = new HashSet<>();
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

    private static String getDomainFromUrl(String url) {
        if (url == null) return null;
        String tmp = url.toLowerCase().replaceAll("https?://", "");
        int slash = tmp.indexOf('/');
        String host = slash >= 0 ? tmp.substring(0, slash) : tmp;
        int colon = host.indexOf(':');
        return colon >= 0 ? host.substring(0, colon) : host;
    }

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
