package com.protect7.authanalyzer.gui.UITesting;

import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.util.RequestTableModel;
import com.protect7.authanalyzer.uitesting.runner.DualDetectionManager;
import com.protect7.authanalyzer.uitesting.runner.ProxyDriverManager;
import com.protect7.authanalyzer.uitesting.runner.UITestRunner;
import com.protect7.authanalyzer.uitesting.runner.Replayer;
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

        // 原来的中间部分：表格（左）和详情（右）
        JSplitPane center = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                tablePanel, details);
        center.setResizeWeight(0.55);
        center.setOneTouchExpandable(true);
        center.setContinuousLayout(true);
        // 设置最小尺寸防止面板被折叠过小
        tablePanel.setMinimumSize(new Dimension(200, 100));
        details.setMinimumSize(new Dimension(200, 100));

        // 外层纵向分割：上 controls， 下 center（table + details）
        JSplitPane outer = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                controls, center);
        // controls 初始占比（可根据需要调整）
        outer.setResizeWeight(0.15); // 顶部占 15%，可拖动
        outer.setOneTouchExpandable(true);
        outer.setContinuousLayout(true);

        // 允许外层分割条有优雅的最小高度
        controls.setMinimumSize(new Dimension(100, 80));

        // 将外层分割放到中心
        add(outer, BorderLayout.CENTER);
    }


    private void wireEvents() {
        controls.onStartAutomation(this::onStartAutomation);
        controls.onToggleDriver(this::onToggleDriver);
        controls.onCrawl(this::onCrawlClick);
        controls.onReplayForSession(this::onReplayForSession); // 新增事件绑定
        controls.onMirrorMode(this::onMirrorMode); // 镜像模式事件绑定
        controls.onDualDetection(this::onDualDetection); // 双重检测事件绑定
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
    // 在 UITestingPanel 类里加：
    private static final class TeePrintWriter extends PrintWriter {
        private final PrintWriter delegate;
        private final java.util.function.Consumer<String> sink;
        TeePrintWriter(PrintWriter delegate, java.util.function.Consumer<String> sink) {
            super(delegate, true);
            this.delegate = delegate;
            this.sink = sink;
        }
        @Override public void println(String x) {
            delegate.println(x);
            try { sink.accept(x); } catch (Throwable ignored) {}
        }
    }

    /**
     * 新增：在选定 Session 上对选中 ORR 进行重放（替换 Cookie）
     */
    private void onReplayForSession(ActionEvent e) {
        new Thread(() -> {
            try {
                OriginalRequestResponse orr = tablePanel.getSelectedORR();
                if (orr == null) {
                    SwingUtilities.invokeLater(() ->
                            JOptionPane.showMessageDialog(this, "请先在表格中选择一条原始请求", "No selection", JOptionPane.WARNING_MESSAGE));
                    return;
                }

                int idx = controls.getSelectedSessionIndex();
                List<Session> sessions = CurrentConfig.getCurrentConfig().getSessions();
                if (sessions == null || idx < 0 || idx >= sessions.size()) {
                    SwingUtilities.invokeLater(() ->
                            JOptionPane.showMessageDialog(this, "请先选择一个 Session", "No session", JOptionPane.WARNING_MESSAGE));
                    return;
                }
                Session s = sessions.get(idx);

                String tiupUid = controls.getTiupUid();
                String sessionCookie = controls.getSessionStr();
                log("[Replay] 开始重放 ORR " + orr.getId() + " 到 Session " + s.getName());

                AnalyzerRequestResponse arr = Replayer.replayOriginalToSession(
                        orr, s, tiupUid, sessionCookie, stdout, stderr);

                if (arr != null) {
                    log("[Replay] 重放完成，刷新详情视图。");
                    SwingUtilities.invokeLater(this::refreshSelectedRowDetails);
                } else {
                    log("[Replay] 重放失败。");
                }
            } catch (Throwable t) {
                log("[Replay] 出错: " + t.getMessage());
                t.printStackTrace(stderr);
            }
        }, "Replay-Thread").start();
    }

    /**
     * 新增：镜像模式功能
     */
    private void onMirrorMode(ActionEvent e) {
        JButton btn = (JButton)e.getSource();
        new Thread(() -> {
            try {
                if (!Replayer.isMirrorRunning()) {
                    // 启动镜像模式
                    log("[Mirror] 启动镜像模式...");

                    // 确保主浏览器已启动
                    WebDriver driverA = ProxyDriverManager.getDriver();
                    if (driverA == null) {
                        log("[Mirror] 启动主浏览器 A...");
                        ProxyDriverManager.startDriver(true, PROXY_HOST, PROXY_PORT, false);
                    }

                    // 获取 B 账号的 cookie
                    String tiupUid = controls.getTiupUid();
                    String sessionCookie = controls.getSessionStr();

                    // 启动镜像模式
                    Replayer.startMirror(tiupUid, sessionCookie, PROXY_HOST, PROXY_PORT, false, stdout, stderr);

                    SwingUtilities.invokeLater(() -> btn.setText("停止镜像模式"));
                    log("[Mirror] 镜像模式已启动。请在主浏览器 A 中操作，浏览器 B 会自动镜像您的点击。");

                } else {
                    // 停止镜像模式
                    log("[Mirror] 停止镜像模式...");
                    Replayer.stopMirror(stdout);

                    SwingUtilities.invokeLater(() -> btn.setText("启动镜像模式"));
                }
            } catch (Exception ex) {
                log("[Mirror] 错误: " + ex.getMessage());
                ex.printStackTrace(stderr);
            }
        }, "Mirror-Thread").start();
    }

    /**
     * 新增：双重检测功能
     */
    private void onDualDetection(ActionEvent e) {
        JButton btn = (JButton)e.getSource();
        new Thread(() -> {
            try {
                if (!DualDetectionManager.isEnabled()) {
                    // 启动双重检测
                    log("[DualDetection] 启动双重检测...");

                    // 确保两个浏览器都已启动
                    WebDriver driverA = ProxyDriverManager.getDriver();
                    WebDriver driverB = ProxyDriverManager.getMirrorDriver();

                    if (driverA == null) {
                        log("[DualDetection] 启动主浏览器 A...");
                        ProxyDriverManager.startDriver(true, PROXY_HOST, PROXY_PORT, false);
                    }

                    if (driverB == null) {
                        log("[DualDetection] 启动镜像浏览器 B...");
                        ProxyDriverManager.startMirrorDriver(true, PROXY_HOST, PROXY_PORT, false);
                    }

                    // 设置日志输出
                    DualDetectionManager.setLoggers(stdout, stderr);

                    // 启用双重检测
                    DualDetectionManager.enable();

                    SwingUtilities.invokeLater(() -> btn.setText("停止双重检测"));
                    log("[DualDetection] 双重检测已启动。请在两个浏览器中分别登录不同账号，然后点击相同的链接。");

                } else {
                    // 停止双重检测
                    log("[DualDetection] 停止双重检测...");
                    DualDetectionManager.disable();

                    // 显示结果
                    List<DualDetectionManager.ComparisonResult> results = DualDetectionManager.getResults();
                    log("[DualDetection] 检测完成，共 " + results.size() + " 条结果：");
                    for (DualDetectionManager.ComparisonResult r : results) {
                        log("  " + r.toString());
                    }

                    SwingUtilities.invokeLater(() -> btn.setText("启动双重检测"));
                }
            } catch (Exception ex) {
                log("[DualDetection] 错误: " + ex.getMessage());
                ex.printStackTrace(stderr);
            }
        }, "DualDetection-Thread").start();
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
