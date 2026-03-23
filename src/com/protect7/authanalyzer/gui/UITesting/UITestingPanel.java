package com.protect7.authanalyzer.gui.UITesting;

import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.util.RequestTableModel;
import com.protect7.authanalyzer.gui.util.TabVisibilityAware;
import com.protect7.authanalyzer.controller.RequestController;
import com.protect7.authanalyzer.uitesting.discovery.ApiDiscoveryService;
import com.protect7.authanalyzer.uitesting.discovery.DiscoveredEndpoint;
import com.protect7.authanalyzer.uitesting.discovery.SyntheticRequestBuilder;
import com.protect7.authanalyzer.uitesting.runner.ProxyDriverManager;
import com.protect7.authanalyzer.util.CurrentConfig;
import com.protect7.authanalyzer.util.DomainHelper;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.Duration;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class UITestingPanel extends JPanel implements TabVisibilityAware {

    private final PrintWriter stdout;
    private final PrintWriter stderr;

    private final ControlsPanel controls;

    protected ControlsPanel createControlsPanel() {
        return new ControlsPanel();
    }

    protected ControlsPanel getControls() {
        return controls;
    }
    protected final RequestTablePanel tablePanel = new RequestTablePanel();
    private final DetailPanel details = new DetailPanel();
    protected final DiscoveredApiListPanel discoveredApiListPanel = new DiscoveredApiListPanel();
    private final Set<String> sentDiscoveredEndpointKeys = Collections.synchronizedSet(new HashSet<>());
    private final Map<String, Set<String>> discoveredEndpointOrigins = new ConcurrentHashMap<>();
    private JSplitPane mainSplitPane;

    private javax.swing.Timer modelBinderTimer;
    private javax.swing.Timer autoSelectDebounceTimer;
    private RequestTableModel attachedModel;
    private TableModelListener tableListener;
    private boolean tabVisible;

    // proxy config
    private static final String PROXY_HOST = "127.0.0.1";
    private static final int PROXY_PORT = 8080;

    // 抓取等待配置（缓解 SPA/慢页面「未找到元素」）
    private static final int RETURN_PAGE_WAIT_MS = 1500;
    private static final int FIND_RETRY_MS = 500;
    private static final int FIND_RETRY_COUNT = 2;
    /** 同页 Tab/状态切换后等待 DOM 更新（Angular 等 SPA） */
    private static final int SAME_PAGE_DOM_WAIT_MS = 1000;

    /** DOM 指纹采样：链接数量 + 前 N 个 href 的排序拼接，用于区分实质性结构变化（如 Tab 切换）与无状态变化操作（如点赞） */
    private static final String DOM_FINGERPRINT_SCRIPT =
            "var links = document.querySelectorAll('a[href]');" +
            "var arr = [];" +
            "for (var i = 0; i < Math.min(links.length, 60); i++) {" +
            "  var h = links[i].getAttribute('href');" +
            "  if (h) arr.push(h);" +
            "}" +
            "arr.sort();" +
            "return links.length + '|' + arr.join(';').substring(0, 1500);";

    public UITestingPanel() {
        this(resolveStdout(), resolveStderr());
    }

    public UITestingPanel(PrintWriter stdout, PrintWriter stderr) {
        this.stdout = stdout;
        this.stderr = stderr;
        this.controls = createControlsPanel();
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

        JPanel rightTop = new JPanel(new BorderLayout());
        rightTop.add(center, BorderLayout.CENTER);

        JSplitPane rightVertical = new JSplitPane(JSplitPane.VERTICAL_SPLIT, rightTop,
                createDiscoveredApiSection());
        rightVertical.setResizeWeight(0.7);
        rightVertical.setDividerLocation(400);
        rightVertical.setOneTouchExpandable(true);

        mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                new JScrollPane(controls), rightVertical);
        mainSplitPane.setResizeWeight(0);
        mainSplitPane.setDividerLocation(420);
        mainSplitPane.setOneTouchExpandable(true);
        add(mainSplitPane, BorderLayout.CENTER);
    }

    private JPanel createDiscoveredApiSection() {
        JPanel wrap = new JPanel(new BorderLayout());
        wrap.setBorder(javax.swing.BorderFactory.createTitledBorder("发现的隐藏 API"));
        JPanel toolbar = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.RIGHT, 4, 2));
        JButton clearDiscoveredBtn = new JButton("清空");
        clearDiscoveredBtn.addActionListener(e -> {
            discoveredApiListPanel.clear();
            sentDiscoveredEndpointKeys.clear();
            discoveredEndpointOrigins.clear();
        });
        toolbar.add(clearDiscoveredBtn);
        wrap.add(toolbar, BorderLayout.NORTH);
        wrap.add(new JScrollPane(discoveredApiListPanel), BorderLayout.CENTER);
        wrap.setMinimumSize(new Dimension(0, 120));
        return wrap;
    }

    /** 供合并面板使用：将 Analyzer 配置面板插入到左侧。merged=true 时 configPanel 已含 controls 内容，不再单独添加 controls */
    protected void setAnalyzerConfigPanel(javax.swing.JPanel configPanel, boolean merged) {
        JPanel left = new JPanel();
        left.setLayout(new BoxLayout(left, BoxLayout.Y_AXIS));
        left.add(configPanel);
        if (!merged) left.add(controls);
        JScrollPane leftScroll = new JScrollPane(left);
        leftScroll.setMinimumSize(new Dimension(280, 0));
        leftScroll.setPreferredSize(new Dimension(420, 0));
        mainSplitPane.setLeftComponent(leftScroll);
        mainSplitPane.setDividerLocation(420);
        mainSplitPane.setResizeWeight(0);
        revalidate();
    }

    /** 供合并面板使用：清空表格（与 CenterPanel.clearTable 一致） */
    public void clearTable() {
        com.protect7.authanalyzer.util.CurrentConfig config = CurrentConfig.getCurrentConfig();
        config.clearSessionRequestMaps();
        RequestTableModel tm = config.getTableModel();
        if (tm != null) tm.clearRequestMap();
        if (config.getSymmetricTrafficStore() != null) {
            config.getSymmetricTrafficStore().clear();
            if (config.getTrivialityChecker() != null) config.getTrivialityChecker().clearCache();
        }
        config.setSymmetricRun2Mode(false);
    }


    private void wireEvents() {
        controls.onCrawl(this::onCrawlClick);
        controls.onDiscover(this::onDiscoverClick);
        controls.onSessionChanged(e -> {
            details.setSessionTabTitle(controls.getSelectedSessionName());
            refreshSelectedRowDetails();
        });
        controls.onClearLog(e -> details.clearLog());
        controls.onClearTable(e -> onClearTable());

        tablePanel.addSelectionListener(new ListSelectionListener() {
            @Override public void valueChanged(ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) refreshSelectedRowDetails();
            }
        });
    }

    /* ================= 主动作 ================= */

    private void onDiscoverClick(ActionEvent e) {
        new Thread(() -> {
            try {
                String targetUrl = controls.getTargetUrl();
                if (targetUrl == null || targetUrl.trim().isEmpty()) {
                    log("[API 发现] 请先配置 Target URL");
                    return;
                }
                boolean fromJs = controls.isDiscoverFromJsSelected();
                boolean fromSwagger = controls.isDiscoverFromSwaggerSelected();
                if (!fromJs && !fromSwagger) {
                    log("[API 发现] 请至少勾选一种发现方式");
                    return;
                }

                java.util.List<DiscoveredEndpoint> all = new java.util.ArrayList<>();
                ApiDiscoveryService service = new ApiDiscoveryService();
                ApiDiscoveryService.DiscoveryCallback cb = new ApiDiscoveryService.DiscoveryCallback() {
                    @Override
                    public void onProgress(String msg) {
                        log("[API 发现] " + msg);
                    }
                    @Override
                    public void onError(String msg) {
                        log("[API 发现] " + msg);
                    }
                };

                if (fromJs) {
                    log("[API 发现] 正在启动浏览器...");
                    WebDriver driver = ProxyDriverManager.getOrStartDriver(true, PROXY_HOST, PROXY_PORT, false);
                    if (driver != null) {
                        try {
                            log("[API 发现] 导航至目标页面并注入 Cookie...");
                            driver.get(targetUrl);
                            Thread.sleep(500);
                            applyCookies(driver, targetUrl, true);
                            driver.get(targetUrl);
                            Thread.sleep(800);
                            String headers = controls.getHeadersToReplaceText();
                            java.util.List<DiscoveredEndpoint> js = service.discoverFromJs(driver, targetUrl, cb, headers);
                            for (DiscoveredEndpoint ep : js) {
                                if (!all.contains(ep)) all.add(ep);
                            }
                            rememberEndpointOrigins(js, targetUrl);
                            final java.util.List<DiscoveredEndpoint> jsList = new java.util.ArrayList<>(all);
                            SwingUtilities.invokeLater(() -> {
                                discoveredApiListPanel.setEndpoints(jsList);
                                log("[API 发现] JS 完成，已发现 " + jsList.size() + " 个端点");
                            });
                        } catch (Throwable t) {
                            log("[API 发现] JS 提取出错: " + t.getMessage());
                        } finally {
                            ProxyDriverManager.stopDriver();
                            log("[API 发现] 已关闭浏览器");
                        }
                    } else {
                        log("[API 发现] 无法启动浏览器，跳过 JS 提取");
                    }
                }

                if (fromSwagger) {
                    java.util.List<DiscoveredEndpoint> swagger = service.discoverFromSwagger(targetUrl, cb);
                    for (DiscoveredEndpoint ep : swagger) {
                        if (!all.contains(ep)) all.add(ep);
                    }
                    rememberEndpointOrigins(swagger, targetUrl);
                    final java.util.List<DiscoveredEndpoint> finalList = all;
                    SwingUtilities.invokeLater(() -> {
                        discoveredApiListPanel.setEndpoints(finalList);
                        log("[API 发现] 完成，共发现 " + finalList.size() + " 个端点");
                    });
                }
            } catch (Throwable ex) {
                log("[API 发现] 出错: " + ex.getMessage());
                ex.printStackTrace(stderr);
            }
        }, "API-Discovery-Thread").start();
    }

    private void onCrawlClick(ActionEvent e) {
        new Thread(() -> {
            try {
                WebDriver driver = ensureValidDriver();
                if (driver == null) {
                    log("[Crawl] 无法启动浏览器");
                    return;
                }
                String targetPage = controls.getTargetUrl();
                if (targetPage == null || targetPage.trim().isEmpty()) {
                    log("[Crawl] 请先配置 Target URL");
                    return;
                }

                if (controls.isSiteBfsEnabled()) {
                    runSiteBfsCrawl(driver, targetPage);
                    log("[Crawl] 完成");
                    afterCrawlComplete(true);
                    return;
                }

                log("[Crawl] 导航至目标页面并设置 Cookie...");
                driver.get(targetPage);
                Thread.sleep(500);
                applyCookies(driver, targetPage, true);  // logOnApply=true 仅初始时打日志
                driver.get(targetPage);
                Thread.sleep(500);

                log("[Crawl] 抓取并点击...");
                Thread.sleep(300);
                waitForPageReady(driver);

                String targetDomain = getDomainFromUrl(targetPage);

                // 按用户思路：以目标状态为基准，发现链接→点击→若改变状态则记录，点击完成后切换最优先状态→重复
                Set<String> alreadyClicked = new HashSet<>();
                Queue<List<String>> statesToExplore = new LinkedList<>();
                Set<List<String>> exploredStates = new HashSet<>();
                statesToExplore.add(new ArrayList<>());
                int totalProcessed = 0;
                final int maxTotalClicks = 500;

                while (!statesToExplore.isEmpty() && totalProcessed < maxTotalClicks) {
                    if (targetPage == null || targetPage.isEmpty()) break;
                    List<String> targetStatePath = statesToExplore.poll();
                    if (exploredStates.contains(targetStatePath)) continue;
                    exploredStates.add(targetStatePath);

                    goToTargetState(driver, targetPage, targetStatePath);
                    waitForPageReady(driver);
                    Thread.sleep(300);

                    LinkedHashMap<String, Void> clickableKeys = new LinkedHashMap<>();
                    collectClickableKeys(driver, targetDomain, clickableKeys);
                    LinkedHashSet<String> stateSwitchersFound = new LinkedHashSet<>();

                    for (String key : clickableKeys.keySet()) {
                        if (alreadyClicked.contains(key)) continue;
                        if (targetStatePath.contains(key)) continue;

                        tryDismissBlockingOverlays(driver);
                        WebElement el = null;
                        for (int r = 0; r <= FIND_RETRY_COUNT && el == null; r++) {
                            if (r > 0) Thread.sleep(FIND_RETRY_MS);
                            el = findClickableByKey(driver, key);
                        }
                        if (el == null) continue;

                        try {
                            log("[Crawl] 点击: " + key);
                            boolean clickedLogout = isLogoutKey(key);
                            String urlBefore = driver.getCurrentUrl();
                            String fpBefore = getPageContentFingerprint(driver);
                            try {
                                ((JavascriptExecutor) driver).executeScript("arguments[0].scrollIntoView({block:'center'});", el);
                                Thread.sleep(100);
                            } catch (Throwable scrollEx) { /* ignore */ }
                            ensureClickInSameTab(driver, el);
                            Thread.sleep(600);
                            alreadyClicked.add(key);
                            totalProcessed++;

                            String urlAfter = driver.getCurrentUrl();
                            boolean urlChanged = urlAfter == null || urlBefore == null
                                    ? (urlAfter != urlBefore)
                                    : !normalizeUrlForCompare(urlAfter).equals(normalizeUrlForCompare(urlBefore));

                            if (urlChanged) {
                                if (clickedLogout) applyCookies(driver, targetPage);
                            } else {
                                Thread.sleep(SAME_PAGE_DOM_WAIT_MS);
                                String fpAfter = getPageContentFingerprint(driver);
                                if (hasSubstantiveDomChange(fpBefore, fpAfter)) {
                                    stateSwitchersFound.add(key);
                                } else if (looksLikeTabOrStateSwitcher(el)) {
                                    stateSwitchersFound.add(key);
                                }
                            }
                            goToTargetState(driver, targetPage, targetStatePath);
                            waitForPageReady(driver);
                            Thread.sleep(RETURN_PAGE_WAIT_MS);
                        } catch (Throwable t) {
                            log("[Crawl] 点击失败: " + key + " -> " + (t.getMessage() != null ? t.getMessage() : ""));
                            goToTargetState(driver, targetPage, targetStatePath);
                            waitForPageReady(driver);
                            Thread.sleep(RETURN_PAGE_WAIT_MS);
                        }
                    }

                    for (String sw : stateSwitchersFound) {
                        List<String> nextPath = new ArrayList<>(targetStatePath);
                        nextPath.add(sw);
                        if (!exploredStates.contains(nextPath)) {
                            statesToExplore.add(nextPath);
                            if (nextPath.size() == 1) log("[Crawl] 待探索状态: " + sw);
                        }
                    }
                }
                log("[Crawl] 完成");
                afterCrawlComplete(true);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                log("[Crawl] 中断");
            } catch (WebDriverException wde) {
                String msg = wde.getMessage() != null ? wde.getMessage() : "";
                boolean sessionDead = msg.contains("invalid session id") || msg.contains("may have died")
                        || msg.contains("remote browser") || msg.contains("session not created");
                if (sessionDead) {
                    log("[Crawl] 浏览器已断开（可能已关闭或崩溃），正在重启...");
                    ProxyDriverManager.stopDriver();
                    try {
                        WebDriver newDriver = ProxyDriverManager.getOrStartDriver(true, PROXY_HOST, PROXY_PORT, false);
                        if (newDriver != null) {
                            log("[Crawl] 已重启，请再次点击抓取");
                        } else {
                            log("[Crawl] 重启失败，请检查 Chrome 是否已安装且版本与 ChromeDriver 匹配");
                        }
                    } catch (Throwable restartEx) {
                        log("[Crawl] 重启失败: " + (restartEx.getMessage() != null ? restartEx.getMessage() : ""));
                    }
                } else {
                    log("[Crawl] 出错: " + msg);
                    wde.printStackTrace(stderr);
                }
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

    private static final class PageNode {
        final String url;
        final int depth;
        PageNode(String url, int depth) { this.url = url; this.depth = depth; }
    }

    private void runSiteBfsCrawl(WebDriver driver, String startUrl) throws Exception {
        int maxPages = Math.max(1, controls.getSiteBfsMaxPages());
        int maxDepth = Math.max(0, controls.getSiteBfsMaxDepth());
        boolean sameOriginOnly = controls.isSameOriginOnly();
        boolean syncSend = CurrentConfig.getCurrentConfig().isSymmetricCaptureEnabled();

        String canonicalStart = canonicalizePageUrl(startUrl);
        if (canonicalStart == null) {
            log("[Crawl] 起始 URL 非法，无法开始 BFS");
            return;
        }
        String startOrigin = getUrlOrigin(canonicalStart);
        String startDomain = getDomainFromUrl(canonicalStart);

        log("[Crawl] 全站 BFS：maxDepth=" + maxDepth + ", maxPages=" + maxPages
                + (sameOriginOnly ? ", scope=同源" : ", scope=同根域"));

        Queue<PageNode> q = new LinkedList<>();
        Set<String> visitedPages = new HashSet<>();
        q.add(new PageNode(canonicalStart, 0));
        visitedPages.add(canonicalStart);

        String originalTarget = controls.getTargetUrl();

        int processed = 0;
        while (!q.isEmpty() && processed < maxPages) {
            PageNode node = q.poll();
            if (node.depth > maxDepth) continue;

            try {
                SwingUtilities.invokeAndWait(() -> controls.setTargetUrl(node.url));
            } catch (Exception ignore) {}

            log("[Crawl] BFS 访问(" + processed + "/" + maxPages + ", depth=" + node.depth + "): " + node.url);

            driver.get(node.url);
            Thread.sleep(500);
            applyCookies(driver, node.url, processed == 0);
            driver.get(node.url);
            Thread.sleep(500);
            waitForPageReady(driver);

            Set<String> discoveredPages = crawlSinglePageAndCollectDiscoveredPages(driver, node.url, startOrigin, startDomain, sameOriginOnly, visitedPages);

            if (controls.isDiscoverFromJsSelected() || controls.isDiscoverFromSwaggerSelected()) {
                runDiscoveryAfterCrawl();
                sendDiscoveredApisToAnalyzer(syncSend);
            }

            for (String raw : discoveredPages) {
                String canon = canonicalizePageUrl(raw);
                if (canon == null) continue;
                if (visitedPages.contains(canon)) continue;
                if (!isPageUrlInScope(canon, startOrigin, startDomain, sameOriginOnly)) continue;
                visitedPages.add(canon);
                q.add(new PageNode(canon, node.depth + 1));
                if (visitedPages.size() >= maxPages) break;
            }

            processed++;
        }

        try {
            SwingUtilities.invokeAndWait(() -> controls.setTargetUrl(originalTarget));
        } catch (Exception ignore) {}

        log("[Crawl] 全站 BFS 完成：visitedPages=" + visitedPages.size() + ", sentHiddenApis=" + sentDiscoveredEndpointKeys.size());
    }

    private Set<String> crawlSinglePageAndCollectDiscoveredPages(WebDriver driver, String targetPage,
            String startOrigin, String startDomain, boolean sameOriginOnly, Set<String> visitedPagesCanonical) throws InterruptedException {
        String targetDomain = getDomainFromUrl(targetPage);
        Set<String> discoveredPages = new LinkedHashSet<>();

        Set<String> alreadyClicked = new HashSet<>();
        Queue<List<String>> statesToExplore = new LinkedList<>();
        Set<List<String>> exploredStates = new HashSet<>();
        statesToExplore.add(new ArrayList<>());
        int totalProcessed = 0;
        final int maxTotalClicks = 500;

        while (!statesToExplore.isEmpty() && totalProcessed < maxTotalClicks) {
            List<String> targetStatePath = statesToExplore.poll();
            if (exploredStates.contains(targetStatePath)) continue;
            exploredStates.add(targetStatePath);

            goToTargetState(driver, targetPage, targetStatePath);
            waitForPageReady(driver);
            Thread.sleep(300);
            discoveredPages.addAll(collectCandidatePageUrlsFromDom(driver, targetPage, startOrigin, startDomain, sameOriginOnly));

            LinkedHashMap<String, Void> clickableKeys = new LinkedHashMap<>();
            collectClickableKeys(driver, targetDomain, clickableKeys);
            LinkedHashSet<String> stateSwitchersFound = new LinkedHashSet<>();

            for (String key : clickableKeys.keySet()) {
                if (alreadyClicked.contains(key)) continue;
                if (targetStatePath.contains(key)) continue;

                tryDismissBlockingOverlays(driver);
                WebElement el = null;
                for (int r = 0; r <= FIND_RETRY_COUNT && el == null; r++) {
                    if (r > 0) Thread.sleep(FIND_RETRY_MS);
                    el = findClickableByKey(driver, key);
                }
                if (el == null) continue;

                try {
                    if (visitedPagesCanonical != null && key.startsWith("a|")) {
                        try {
                            String href = el.getAttribute("href");
                            String abs = resolveToAbsoluteUrl(targetPage, href);
                            String canon = canonicalizePageUrl(abs);
                            if (canon != null && visitedPagesCanonical.contains(canon)) {
                                alreadyClicked.add(key);
                                continue;
                            }
                        } catch (Throwable ignore) { }
                    }

                    log("[Crawl] 点击: " + key);
                    boolean clickedLogout = isLogoutKey(key);
                    String urlBefore = driver.getCurrentUrl();
                    String fpBefore = getPageContentFingerprint(driver);
                    try {
                        ((JavascriptExecutor) driver).executeScript("arguments[0].scrollIntoView({block:'center'});", el);
                        Thread.sleep(100);
                    } catch (Throwable scrollEx) { }
                    ensureClickInSameTab(driver, el);
                    Thread.sleep(600);
                    alreadyClicked.add(key);
                    totalProcessed++;

                    String urlAfter = driver.getCurrentUrl();
                    boolean urlChanged = urlAfter == null || urlBefore == null
                            ? (urlAfter != urlBefore)
                            : !normalizeUrlForCompare(urlAfter).equals(normalizeUrlForCompare(urlBefore));

                    if (urlChanged) {
                        if (urlAfter != null && isPageUrlInScope(urlAfter, startOrigin, startDomain, sameOriginOnly)) {
                            discoveredPages.add(urlAfter);
                        }
                        if (clickedLogout) applyCookies(driver, targetPage);
                    } else {
                        Thread.sleep(SAME_PAGE_DOM_WAIT_MS);
                        String fpAfter = getPageContentFingerprint(driver);
                        if (hasSubstantiveDomChange(fpBefore, fpAfter)) {
                            stateSwitchersFound.add(key);
                        } else if (looksLikeTabOrStateSwitcher(el)) {
                            stateSwitchersFound.add(key);
                        }
                    }
                    goToTargetState(driver, targetPage, targetStatePath);
                    waitForPageReady(driver);
                    Thread.sleep(RETURN_PAGE_WAIT_MS);
                } catch (Throwable t) {
                    log("[Crawl] 点击失败: " + key + " -> " + (t.getMessage() != null ? t.getMessage() : ""));
                    goToTargetState(driver, targetPage, targetStatePath);
                    waitForPageReady(driver);
                    Thread.sleep(RETURN_PAGE_WAIT_MS);
                }
            }

            for (String sw : stateSwitchersFound) {
                List<String> nextPath = new ArrayList<>(targetStatePath);
                nextPath.add(sw);
                if (!exploredStates.contains(nextPath)) {
                    statesToExplore.add(nextPath);
                    if (nextPath.size() == 1) log("[Crawl] 待探索状态: " + sw);
                }
            }
        }

        return discoveredPages;
    }

    private static String resolveToAbsoluteUrl(String baseUrl, String href) {
        if (href == null) return null;
        String h = href.trim();
        if (h.isEmpty()) return null;
        String lower = h.toLowerCase();
        if (lower.startsWith("mailto:") || lower.startsWith("tel:") || lower.startsWith("data:") || lower.startsWith("blob:"))
            return null;
        if (lower.startsWith("javascript:") || lower.startsWith("#"))
            return null;
        try {
            URL base = new URL(baseUrl);
            URL resolved = new URL(base, h);
            return resolved.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private Set<String> collectCandidatePageUrlsFromDom(WebDriver driver, String baseUrl,
            String startOrigin, String startDomain, boolean sameOriginOnly) {
        Set<String> result = new LinkedHashSet<>();
        try {
            List<WebElement> anchors = driver.findElements(By.xpath("//a[@href]"));
            for (WebElement a : anchors) {
                try {
                    String href = a.getAttribute("href");
                    String abs = resolveToAbsoluteUrl(baseUrl, href);
                    if (abs == null) continue;
                    String canon = canonicalizePageUrl(abs);
                    if (canon == null) continue;
                    if (isPageUrlInScope(canon, startOrigin, startDomain, sameOriginOnly)) {
                        result.add(canon);
                    }
                } catch (Throwable ignore) { }
            }
        } catch (Throwable ignore) { }
        return result;
    }

    private void rememberEndpointOrigins(List<DiscoveredEndpoint> endpoints, String baseUrl) {
        if (endpoints == null || endpoints.isEmpty()) return;
        String origin = getUrlOrigin(baseUrl);
        if (origin == null || origin.isEmpty()) return;
        for (DiscoveredEndpoint ep : endpoints) {
            String id = endpointIdentity(ep);
            if (id == null) continue;
            discoveredEndpointOrigins.computeIfAbsent(id, k -> ConcurrentHashMap.newKeySet()).add(origin);
        }
    }

    private static String endpointIdentity(DiscoveredEndpoint ep) {
        if (ep == null) return null;
        String m = ep.getMethod();
        String p = ep.getPath();
        if (m == null || p == null) return null;
        String op = ep.getGraphqlOperation();
        String opType = ep.getGraphqlOperationType();
        if (op != null && !op.isEmpty()) {
            String t = (opType != null && !opType.isEmpty()) ? opType : "query";
            return m + " " + p + " :: " + t + " " + op;
        }
        return m + " " + p;
    }

    /** 抓取完成后回调，子类可覆盖以实现 Run2 等后续逻辑。在抓取线程中调用。 */
    protected void afterCrawlComplete(boolean success) {
        if (!success) return;
        runDiscoveryAfterCrawl();
        boolean sync = CurrentConfig.getCurrentConfig().isSymmetricCaptureEnabled();
        sendDiscoveredApisToAnalyzer(sync);
    }

    /** 抓取完成后自动运行隐藏 API 发现（复用当前浏览器），避免漏检 */
    protected void runDiscoveryAfterCrawl() {
        String targetUrl = controls.getTargetUrl();
        if (targetUrl == null || targetUrl.trim().isEmpty()) return;
        boolean fromJs = controls.isDiscoverFromJsSelected();
        boolean fromSwagger = controls.isDiscoverFromSwaggerSelected();
        if (!fromJs && !fromSwagger) return;

        java.util.List<DiscoveredEndpoint> discovered = new java.util.ArrayList<>();
        ApiDiscoveryService service = new ApiDiscoveryService();
        ApiDiscoveryService.DiscoveryCallback cb = new ApiDiscoveryService.DiscoveryCallback() {
            @Override public void onProgress(String msg) { log("[API 发现] " + msg); }
            @Override public void onError(String msg) { log("[API 发现] " + msg); }
        };

        if (fromJs) {
            WebDriver driver = ProxyDriverManager.getDriver();
            if (driver != null) {
                try {
                    driver.get(targetUrl);
                    Thread.sleep(500);
                    applyCookies(driver, targetUrl, false);
                    driver.get(targetUrl);
                    Thread.sleep(500);
                    String headers = controls.getHeadersToReplaceText();
                    java.util.List<DiscoveredEndpoint> js = service.discoverFromJs(driver, targetUrl, cb, headers);
                    for (DiscoveredEndpoint ep : js) {
                        if (!discovered.contains(ep)) discovered.add(ep);
                    }
                } catch (Throwable t) {
                    log("[API 发现] 抓取后 JS 提取出错: " + (t.getMessage() != null ? t.getMessage() : ""));
                }
            }
        }

        if (fromSwagger) {
            try {
                java.util.List<DiscoveredEndpoint> swagger = service.discoverFromSwagger(targetUrl, cb);
                for (DiscoveredEndpoint ep : swagger) {
                    if (!discovered.contains(ep)) discovered.add(ep);
                }
            } catch (Throwable t) {
                log("[API 发现] 抓取后 Swagger 探测出错: " + (t.getMessage() != null ? t.getMessage() : ""));
            }
        }

        if (!discovered.isEmpty()) {
            try {
                SwingUtilities.invokeAndWait(() -> discoveredApiListPanel.addEndpoints(discovered));
                rememberEndpointOrigins(discovered, targetUrl);
                log("[API 发现] 抓取后新发现 " + discovered.size() + " 个端点");
            } catch (Exception e) {
                log("[API 发现] 更新面板失败: " + (e.getMessage() != null ? e.getMessage() : ""));
            }
        }
    }

    /** 将发现的隐藏 API 构造请求并送入 Analyzer，与抓取到的非隐藏 API 一并完成越权检测。 */
    protected void sendDiscoveredApisToAnalyzer() {
        sendDiscoveredApisToAnalyzer(false);
    }

    /**
     * 将发现的隐藏 API 送入 Analyzer。
     * @param sync true 时在当前线程同步执行，保证在调用时 Run 模式下完成，避免异步队列导致误记为下一 Run。
     */
    protected void sendDiscoveredApisToAnalyzer(boolean sync) {
        java.util.List<DiscoveredEndpoint> endpoints = discoveredApiListPanel.getAllEndpoints();
        if (endpoints == null || endpoints.isEmpty()) return;

        String baseUrl = controls.getTargetUrl();
        String headers = controls.getHeadersToReplaceText();
        if (baseUrl == null || baseUrl.trim().isEmpty()) return;

        RequestController rc = CurrentConfig.getCurrentConfig().getRequestController();
        int sent = 0;
        for (DiscoveredEndpoint ep : endpoints) {
            String endpointId = endpointIdentity(ep);
            if (endpointId == null) continue;
            Set<String> origins = discoveredEndpointOrigins.get(endpointId);
            if (origins == null || origins.isEmpty()) {
                String fallbackOrigin = getUrlOrigin(baseUrl);
                if (fallbackOrigin != null) {
                    origins = new HashSet<>();
                    origins.add(fallbackOrigin);
                }
            }
            if (origins == null || origins.isEmpty()) continue;

            for (String origin : origins) {
                if (origin == null || origin.isEmpty()) continue;
                String sendKey = origin + "|" + endpointId;
                if (sentDiscoveredEndpointKeys.contains(sendKey)) continue;
                IHttpRequestResponse rr = SyntheticRequestBuilder.buildAndExecute(ep, origin + "/", headers, this::log);
                if (rr != null && rr.getRequest() != null) {
                    if (sync) {
                        rc.analyze(rr);
                    } else {
                        CurrentConfig.getCurrentConfig().performAuthAnalyzerRequest(rr);
                    }
                    sent++;
                    sentDiscoveredEndpointKeys.add(sendKey);
                }
            }
        }
        if (sent > 0) {
            log("[API 发现] 已送入 Analyzer: " + sent + " 个端点" + (sync ? "（同步）" : ""));
        }
    }

    /** 点击元素，确保在当前标签页打开（移除 target="_blank" 避免累积大量标签页） */
    private void ensureClickInSameTab(WebDriver driver, WebElement el) {
        try {
            String tag = el.getTagName();
            if ("a".equalsIgnoreCase(tag)) {
                ((JavascriptExecutor) driver).executeScript(
                        "var e=arguments[0]; e.removeAttribute('target'); e.setAttribute('target','_self');", el);
            }
            el.click();
        } catch (Exception clickEx) {
            try {
                ((JavascriptExecutor) driver).executeScript("arguments[0].click();", el);
            } catch (Throwable jsEx) {
                log("[Crawl] JS 点击失败: " + jsEx.getMessage());
            }
        }
    }

    /** 进入目标状态：先加载目标页，再按 path 依次点击状态切换链接 */
    private void goToTargetState(WebDriver driver, String targetPage, List<String> targetStatePath) {
        try {
            driver.get(targetPage);
            waitForPageReady(driver);
            Thread.sleep(300);
            tryDismissBlockingOverlays(driver);
            for (String key : targetStatePath) {
                WebElement el = null;
                for (int r = 0; r <= FIND_RETRY_COUNT && el == null; r++) {
                    if (r > 0) Thread.sleep(FIND_RETRY_MS);
                    el = findClickableByKey(driver, key);
                }
                if (el != null) {
                    try {
                        ((JavascriptExecutor) driver).executeScript("arguments[0].scrollIntoView({block:'center'});", el);
                        Thread.sleep(100);
                    } catch (Throwable ignore) {}
                    ensureClickInSameTab(driver, el);
                    Thread.sleep(SAME_PAGE_DOM_WAIT_MS);
                }
            }
        } catch (Throwable ignore) {}
    }

    /** 尝试关闭可能阻塞的弹窗，避免抓取卡住。策略：① 通用选择器 ② 中英文按钮文案 */
    private void tryDismissBlockingOverlays(WebDriver driver) {
        try {
            if (tryClickByGenericSelectors(driver)) return;
            if (tryClickByButtonText(driver)) return;
        } catch (Throwable ignore) {}
    }

    /** 通用选择器：Bootstrap/Element UI/Ant Design 等常见模态框的关闭按钮（语言无关） */
    private boolean tryClickByGenericSelectors(WebDriver driver) {
        String[] selectors = {
                "[data-dismiss='modal']",
                ".modal .close, .modal-header .close",
                ".el-dialog__close, .el-message-box__close",
                ".ant-modal-close",
                "[aria-label='Close']", "[aria-label='close']", "[aria-label='关闭']",
                ".dialog-close, .modal-close, .btn-close"
        };
        try {
            for (String sel : selectors) {
                try {
                    List<WebElement> els = driver.findElements(By.cssSelector(sel));
                    for (WebElement el : els) {
                        if (el.isDisplayed() && el.isEnabled()) {
                            el.click();
                            Thread.sleep(300);
                            return true;
                        }
                    }
                } catch (Throwable ignore) {}
            }
            List<WebElement> ariaBtns = driver.findElements(By.cssSelector("[aria-label]"));
            for (WebElement b : ariaBtns) {
                try {
                    String label = b.getAttribute("aria-label");
                    if (label != null && (label.equalsIgnoreCase("close") || label.contains("关闭"))) {
                        if (b.isDisplayed() && b.isEnabled()) {
                            b.click();
                            Thread.sleep(300);
                            return true;
                        }
                    }
                } catch (Throwable ignore) {}
            }
            List<WebElement> modals = driver.findElements(By.cssSelector(".modal, [role='dialog'], [aria-modal='true'], .el-dialog, .ant-modal-wrap"));
            for (WebElement m : modals) {
                if (!m.isDisplayed()) continue;
                for (String closeSel : new String[]{".close", ".el-dialog__close", ".ant-modal-close", "[aria-label='Close']", "[aria-label='close']", "[aria-label='关闭']"}) {
                    try {
                        List<WebElement> closes = m.findElements(By.cssSelector(closeSel));
                        for (WebElement close : closes) {
                            if (close.isDisplayed() && close.isEnabled()) {
                                close.click();
                                Thread.sleep(300);
                                return true;
                            }
                        }
                    } catch (Throwable ignore) {}
                }
            }
        } catch (Throwable ignore) {}
        return false;
    }

    /** 按按钮文案匹配（中英文），用于无通用 class 的自定义弹窗 */
    private boolean tryClickByButtonText(WebDriver driver) {
        String[] closeTexts = {
                "确认", "Confirm", "OK", "Ok",
                "取消", "Cancel",
                "关闭", "Close",
                "知道了", "Got it", "I see", "Dismiss",
                "暂不", "Not now", "Later",
                "同意", "同意并继续", "Accept", "Agree",
                "接受", "接受条款"
        };
        for (String text : closeTexts) {
            try {
                String escaped = text.replace("'", "\\'");
                List<WebElement> btns = driver.findElements(By.xpath(
                        "//button[contains(normalize-space(.),'" + escaped + "')] | " +
                        "//a[contains(normalize-space(.),'" + escaped + "')] | " +
                        "//*[@role='button'][contains(normalize-space(.),'" + escaped + "')] | " +
                        "//input[@type='button' or @type='submit'][@value='" + escaped + "']"));
                for (WebElement b : btns) {
                    if (b.isDisplayed() && b.isEnabled()) {
                        try {
                            b.click();
                            Thread.sleep(300);
                            return true;
                        } catch (Throwable ignore) {}
                    }
                }
            } catch (Throwable ignore) {}
        }
        return false;
    }

    /** 等待页面就绪（document.readyState），缓解 SPA 异步渲染导致的「未找到」 */
    private void waitForPageReady(WebDriver driver) {
        try {
            new WebDriverWait(driver, Duration.ofSeconds(5))
                    .until(d -> Boolean.TRUE.equals(((JavascriptExecutor) d).executeScript("return document.readyState === 'complete'")));
        } catch (Throwable ignore) {}
    }

    /** key 是否为登出类（用于判断是否需重新注入 Cookie） */
    private boolean isLogoutKey(String key) {
        if (key == null) return false;
        String k = key.toLowerCase();
        return k.contains("退出") || k.contains("登出") || k.contains("注销")
                || k.contains("log out") || k.contains("logout")
                || k.contains("sign out") || k.contains("signout")
                || k.contains("/logout") || k.contains("/signout");
    }

    /** 需使用父域的 Cookie 名（跨子域共享的认证 token 等） */
    private static final Set<String> PARENT_DOMAIN_COOKIES = new HashSet<>(Arrays.asList(
            "access_token", "token", "auth_token", "oauth_token", "bearer_token",
            "id_token", "refresh_token", "jwt", "session_token"));

    /** 从 headersToReplace 解析 Cookie 并注入，用于初始登录及点击登出后恢复登录 */
    private void applyCookies(WebDriver driver, String targetPage, boolean logOnApply) {
        String headersText = controls.getHeadersToReplaceText();
        if (headersText == null || headersText.trim().isEmpty()) return;
        String domain = getDomainFromUrl(targetPage);
        String parentDomain = getParentDomain(domain);
        if (domain == null) return;
        List<CookieEntry> cookies = parseCookiesFromHeaders(headersText);
        if (cookies.isEmpty()) return;
        try {
            driver.manage().deleteAllCookies();
            boolean isHttps = targetPage != null && targetPage.trim().toLowerCase().startsWith("https");
            for (CookieEntry ce : cookies) {
                String cookieDomain = PARENT_DOMAIN_COOKIES.contains(ce.name.toLowerCase()) && parentDomain != null
                        ? parentDomain : domain;
                driver.manage().addCookie(new Cookie.Builder(ce.name, ce.value)
                        .domain(cookieDomain).path("/").isSecure(isHttps).build());
            }
            if (logOnApply) log("[Crawl] 已应用 Cookie");
        } catch (Exception cex) {
            log("[Crawl] 设置 Cookie 失败: " + cex.getMessage());
        }
    }

    /** 解析 headersToReplace 文本，提取 Cookie 的 name=value 对 */
    private static List<CookieEntry> parseCookiesFromHeaders(String headersText) {
        List<CookieEntry> result = new ArrayList<>();
        String[] lines = headersText.replace("\r", "").split("\n");
        for (String line : lines) {
            int colon = line.indexOf(':');
            if (colon <= 0) continue;
            String headerName = line.substring(0, colon).trim();
            if (!"Cookie".equalsIgnoreCase(headerName)) continue;
            String cookieValue = line.substring(colon + 1).trim();
            String[] pairs = cookieValue.split(";");
            for (String pair : pairs) {
                int eq = pair.indexOf('=');
                if (eq <= 0) continue;
                String name = pair.substring(0, eq).trim();
                String value = pair.substring(eq + 1).trim();
                if (!name.isEmpty()) result.add(new CookieEntry(name, value));
            }
        }
        return result;
    }

    private static final class CookieEntry {
        final String name, value;
        CookieEntry(String name, String value) { this.name = name; this.value = value; }
    }

    private void applyCookies(WebDriver driver, String targetPage) {
        applyCookies(driver, targetPage, false);
    }

    /** 越权检测：收集可点击元素 key，同域过滤，扩展 button/form submit。
     *  包含隐藏元素、包含登出链接（点击登出后 applyCookies 会重新注入以恢复登录）。 */
    private void collectClickableKeys(WebDriver driver, String targetDomain, LinkedHashMap<String, Void> out) {
        // <a> 链接：同域过滤；图标链接优先 href（不排除登出，可捕获登出 API 漏洞）
        List<WebElement> anchors = driver.findElements(By.xpath("//a"));
        for (WebElement a : anchors) {
            try {
                String text = a.getText();
                String href = a.getAttribute("href");
                if (!isHrefInScopeForAuth(href, targetDomain)) continue;
                boolean textEmpty = (text == null || text.trim().isEmpty());
                boolean hrefEmpty = (href == null || href.trim().isEmpty());
                String keyPart = pickAnchorKey(a, text, href, textEmpty, hrefEmpty);
                if (keyPart == null) continue;
                out.putIfAbsent("a|" + normalizeKey(keyPart), null);
            } catch (Throwable ignore) {}
        }
        // <button> 及 input[type=submit/button]
        List<WebElement> buttons = driver.findElements(By.xpath("//button | //input[@type='submit' or @type='button']"));
        for (WebElement b : buttons) {
            try {
                String label = "button".equalsIgnoreCase(b.getTagName()) ? b.getText() : b.getAttribute("value");
                if (label == null || label.trim().isEmpty()) label = b.getAttribute("aria-label");
                if (label == null || label.trim().isEmpty()) label = "[无文本]";
                out.putIfAbsent("btn|" + normalizeKey(label), null);
            } catch (Throwable ignore) {}
        }
        // role="button" 的 div/span 等（如 Angular 的 <a role="button"> 已由上面 //a 收集）
        List<WebElement> roleButtons = driver.findElements(By.xpath("//*[@role='button' and not(self::a) and not(self::button)]"));
        for (WebElement rb : roleButtons) {
            try {
                String label = rb.getText();
                if (label == null || label.trim().isEmpty()) label = rb.getAttribute("aria-label");
                if (label == null || label.trim().isEmpty()) label = "[无文本]";
                out.putIfAbsent("btn|" + normalizeKey(label), null);
            } catch (Throwable ignore) {}
        }
    }

    /** 图标链接（text 短）优先用 href；text/href 皆空时回退到 aria-label、title、内部 img alt */
    private String pickAnchorKey(WebElement a, String text, String href, boolean textEmpty, boolean hrefEmpty) {
        if (!textEmpty) {
            if (hrefEmpty) return text.trim();
            String t = text.trim();
            if (t.length() <= 2) return href.trim();
            return t;
        }
        if (!hrefEmpty) return href.trim();
        String aria = getAttributeTrimmed(a, "aria-label");
        if (aria != null) return aria;
        String title = getAttributeTrimmed(a, "title");
        if (title != null) return title;
        String imgAlt = getFirstImgAlt(a);
        if (imgAlt != null) return imgAlt;
        return null;
    }

    private static String getAttributeTrimmed(WebElement el, String attr) {
        try {
            String v = el.getAttribute(attr);
            if (v != null && !v.trim().isEmpty()) return v.trim();
        } catch (Throwable ignore) {}
        return null;
    }

    private static String getFirstImgAlt(WebElement anchor) {
        try {
            List<WebElement> imgs = anchor.findElements(By.tagName("img"));
            for (WebElement img : imgs) {
                String alt = img.getAttribute("alt");
                if (alt != null && !alt.trim().isEmpty()) return alt.trim();
            }
        } catch (Throwable ignore) {}
        return null;
    }

    /** 规范化 key 用于匹配：trim + 合并连续空白 */
    private String normalizeKey(String s) {
        if (s == null) return "";
        return s.trim().replaceAll("\\s+", " ");
    }

    /** 轻量级 DOM 指纹：链接数量 + 前 N 个 href 排序拼接，用于区分 Tab 切换与点赞等无结构变化操作 */
    private String getPageContentFingerprint(WebDriver driver) {
        try {
            Object r = ((JavascriptExecutor) driver).executeScript(DOM_FINGERPRINT_SCRIPT);
            return r != null ? r.toString() : "";
        } catch (Throwable t) {
            return "";
        }
    }

    /** 是否像 Tab/状态切换按钮（role=button、ng-click、btnCur 等），用于 DOM 指纹未变化时的兜底 */
    private boolean looksLikeTabOrStateSwitcher(WebElement el) {
        try {
            String role = el.getAttribute("role");
            if ("button".equalsIgnoreCase(role)) return true;
            String cls = el.getAttribute("class");
            if (cls != null && (cls.contains("btnCur") || cls.contains("tab") || cls.contains("nav-tab")))
                return true;
            String ngClick = el.getAttribute("ng-click");
            if (ngClick != null && !ngClick.trim().isEmpty()) return true;
        } catch (Throwable ignore) {}
        return false;
    }

    /** 是否发生实质性 DOM 结构变化（链接数量或链接集合变化），排除点赞等微调 */
    private boolean hasSubstantiveDomChange(String fpBefore, String fpAfter) {
        if (fpBefore == null || fpAfter == null) return false;
        if (fpBefore.equals(fpAfter)) return false;
        try {
            int sepBefore = fpBefore.indexOf('|');
            int sepAfter = fpAfter.indexOf('|');
            if (sepBefore < 0 || sepAfter < 0) return true;
            int countBefore = Integer.parseInt(fpBefore.substring(0, sepBefore));
            int countAfter = Integer.parseInt(fpAfter.substring(0, sepAfter));
            if (countBefore != countAfter) return true;
            String linksBefore = sepBefore + 1 < fpBefore.length() ? fpBefore.substring(sepBefore + 1) : "";
            String linksAfter = sepAfter + 1 < fpAfter.length() ? fpAfter.substring(sepAfter + 1) : "";
            return !linksBefore.equals(linksAfter);
        } catch (NumberFormatException e) {
            return true;
        }
    }

    /** 用于比较的 URL 规范化（忽略末尾斜杠等细微差异） */
    private static String normalizeUrlForCompare(String url) {
        if (url == null) return "";
        String s = url.trim();
        if (s.endsWith("/") && s.length() > 1) s = s.substring(0, s.length() - 1);
        return s;
    }

    /** href 是否在越权检测范围内：同根域（允许 www/api 等子域）、非 mailto/tel 等 */
    private boolean isHrefInScopeForAuth(String href, String targetDomain) {
        if (href == null || href.trim().isEmpty()) return true;
        String h = href.trim().toLowerCase();
        if (h.startsWith("mailto:") || h.startsWith("tel:") || h.startsWith("data:") || h.startsWith("blob:"))
            return false;
        if (h.startsWith("javascript:") || h.startsWith("#")) return true;
        if (!h.startsWith("http://") && !h.startsWith("https://")) return true;
        try {
            if (targetDomain == null) return true;
            String hrefDomain = getDomainFromUrl(href);
            if (hrefDomain == null) return true;
            return isSameRootDomain(hrefDomain, targetDomain);
        } catch (Throwable ignore) { return false; }
    }

    /** 判断两域名是否同根域（如 www.xxx.com 与 api.xxx.com） */
    private static boolean isSameRootDomain(String domainA, String domainB) {
        if (domainA == null || domainB == null) return false;
        String rootA = DomainHelper.getRootDomain(domainA);
        String rootB = DomainHelper.getRootDomain(domainB);
        return rootA != null && rootB != null && rootA.equalsIgnoreCase(rootB);
    }

    /** 根据 key 查找可点击元素，key 格式为 "a|..." 或 "btn|..." */
    private WebElement findClickableByKey(WebDriver driver, String key) {
        if (key == null || key.isEmpty()) return null;
        if (key.startsWith("a|")) {
            String k = key.substring(2);
            return findAnchorByKey(driver, k);
        }
        if (key.startsWith("btn|")) {
            String k = key.substring(4);
            return findButtonByKey(driver, k);
        }
        return null;
    }

    private WebElement findAnchorByKey(WebDriver driver, String key) {
        if (key == null || key.isEmpty()) return null;
        String keyNorm = normalizeKey(key);
        List<WebElement> anchors = driver.findElements(By.xpath("//a"));
        for (WebElement a : anchors) {
            try {
                String text = a.getText();
                String href = a.getAttribute("href");
                boolean textEmpty = (text == null || text.trim().isEmpty());
                boolean hrefEmpty = (href == null || href.trim().isEmpty());
                String keyPart = pickAnchorKey(a, text, href, textEmpty, hrefEmpty);
                if (keyPart != null && keyNorm.equals(normalizeKey(keyPart))) return a;
            } catch (Throwable ignore) {}
        }
        return null;
    }

    private WebElement findButtonByKey(WebDriver driver, String key) {
        if (key == null || key.isEmpty()) return null;
        String keyNorm = normalizeKey(key);
        List<WebElement> buttons = driver.findElements(By.xpath("//button | //input[@type='submit' or @type='button']"));
        for (WebElement b : buttons) {
            try {
                String label = "button".equalsIgnoreCase(b.getTagName()) ? b.getText() : b.getAttribute("value");
                if (label == null || label.trim().isEmpty()) label = b.getAttribute("aria-label");
                if (label == null || label.trim().isEmpty()) label = "[无文本]";
                if (keyNorm.equals(normalizeKey(label))) return b;
            } catch (Throwable ignore) {}
        }
        List<WebElement> roleButtons = driver.findElements(By.xpath("//*[@role='button' and not(self::a) and not(self::button)]"));
        for (WebElement rb : roleButtons) {
            try {
                String label = rb.getText();
                if (label == null || label.trim().isEmpty()) label = rb.getAttribute("aria-label");
                if (label == null || label.trim().isEmpty()) label = "[无文本]";
                if (keyNorm.equals(normalizeKey(label))) return rb;
            } catch (Throwable ignore) {}
        }
        return null;
    }

    private void onClearTable() {
        CurrentConfig config = CurrentConfig.getCurrentConfig();
        Runnable clear = () -> {
            com.protect7.authanalyzer.gui.util.ICenterPanelFacade facade = CurrentConfig.getCenterPanelFacade();
            if (facade != null) facade.clearTable();
        };
        sentDiscoveredEndpointKeys.clear();
        discoveredEndpointOrigins.clear();
        if (config.isRunning()) {
            config.getAnalyzerThreadExecutor().execute(() ->
                SwingUtilities.invokeLater(clear));
        } else {
            SwingUtilities.invokeLater(clear);
        }
    }

    /** 获取有效的 driver，若会话已失效则重启。 */
    private WebDriver ensureValidDriver() {
        WebDriver d = ProxyDriverManager.getOrStartDriver(true, PROXY_HOST, PROXY_PORT, false);
        if (d == null) return null;
        try {
            d.getWindowHandles();
            return d;
        } catch (WebDriverException wde) {
            String msg = wde.getMessage() != null ? wde.getMessage() : "";
            if (msg.contains("invalid session id") || msg.contains("may have died")
                    || msg.contains("remote browser") || msg.contains("session not created")) {
                log("[Driver] 检测到失效会话，正在重启...");
                ProxyDriverManager.stopDriver();
                return ProxyDriverManager.getOrStartDriver(true, PROXY_HOST, PROXY_PORT, false);
            }
            throw wde;
        }
    }

    /* ================= 绑定模型/刷新视图 ================= */

    private void startModelBinding() {
        if (modelBinderTimer != null && modelBinderTimer.isRunning()) return;

        tableListener = new TableModelListener() {
            @Override public void tableChanged(TableModelEvent e) {
                if (e.getType() == TableModelEvent.INSERT || e.getType() == TableModelEvent.UPDATE) {
                    if (!tabVisible) return;
                    if (autoSelectDebounceTimer != null) {
                        autoSelectDebounceTimer.stop();
                        autoSelectDebounceTimer.start();
                    } else {
                        SwingUtilities.invokeLater(() -> tablePanel.autoSelectLastRowIfNone());
                    }
                }
                if (e.getType() == TableModelEvent.HEADER_ROW) {
                    SwingUtilities.invokeLater(() -> tablePanel.ensureStatusColumnsVisible());
                }
            }
        };

        autoSelectDebounceTimer = new javax.swing.Timer(300, ev -> {
            autoSelectDebounceTimer.stop();
            SwingUtilities.invokeLater(() -> tablePanel.autoSelectLastRowIfNone());
        });
        autoSelectDebounceTimer.setRepeats(false);

        modelBinderTimer = new javax.swing.Timer(500, ev -> {
            if (!tabVisible) return;
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

                    refreshSessions();
                    details.setSessionTabTitle(controls.getSelectedSessionName());
                    refreshSelectedRowDetails();
                }
            } catch (Exception ex) {
                log("绑定 TableModel 失败: " + ex.getMessage());
            }
        });
        modelBinderTimer.setRepeats(true);
        // 不在此处 start，等 onTabVisible 时再启动，避免非当前标签时空转
    }

    @Override
    public void onTabVisible() {
        tabVisible = true;
        if (modelBinderTimer != null && !modelBinderTimer.isRunning()) modelBinderTimer.start();
        SwingUtilities.invokeLater(this::tryBindModelOnce);
    }

    private void tryBindModelOnce() {
        if (!tabVisible) return;
        RequestTableModel tm = CurrentConfig.getCurrentConfig().getTableModel();
        if (tm == null) return;
        if (tm != attachedModel) {
            if (attachedModel != null && tableListener != null) attachedModel.removeTableModelListener(tableListener);
            attachedModel = tm;
            attachedModel.addTableModelListener(tableListener);
            tablePanel.bindModel(attachedModel);
            refreshSessions();
            details.setSessionTabTitle(controls.getSelectedSessionName());
            refreshSelectedRowDetails();
        }
    }

    @Override
    public void onTabHidden() {
        tabVisible = false;
        if (modelBinderTimer != null) modelBinderTimer.stop();
        if (autoSelectDebounceTimer != null) autoSelectDebounceTimer.stop();
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

    private static String canonicalizePageUrl(String url) {
        if (url == null) return null;
        String s = url.trim();
        if (s.isEmpty()) return null;
        if (!s.toLowerCase().startsWith("http://") && !s.toLowerCase().startsWith("https://")) return null;
        try {
            URL u = new URL(s);
            String protocol = u.getProtocol() != null ? u.getProtocol().toLowerCase() : "http";
            String host = u.getHost() != null ? u.getHost().toLowerCase() : "";
            int port = u.getPort();
            boolean defaultPort = (port == -1) || (protocol.equals("http") && port == 80) || (protocol.equals("https") && port == 443);
            String path = u.getPath() != null ? u.getPath() : "";
            path = path.replaceAll("/+", "/");
            if (path.isEmpty()) path = "/";
            if (path.length() > 1 && path.endsWith("/")) path = path.substring(0, path.length() - 1);

            String query = u.getQuery();
            if (query != null && !query.isEmpty()) {
                String[] parts = query.split("&");
                java.util.Arrays.sort(parts);
                StringBuilder q = new StringBuilder();
                for (String p : parts) {
                    if (p == null || p.isEmpty()) continue;
                    if (q.length() > 0) q.append('&');
                    q.append(p);
                }
                query = q.length() > 0 ? q.toString() : null;
            } else {
                query = null;
            }

            StringBuilder sb = new StringBuilder();
            sb.append(protocol).append("://").append(host);
            if (!defaultPort) sb.append(':').append(port);
            sb.append(path);
            if (query != null) sb.append('?').append(query);
            return sb.toString();
        } catch (MalformedURLException e) {
            return null;
        }
    }

    private static String getUrlOrigin(String url) {
        String canon = canonicalizePageUrl(url);
        if (canon == null) return null;
        try {
            URL u = new URL(canon);
            String protocol = u.getProtocol().toLowerCase();
            String host = u.getHost().toLowerCase();
            int port = u.getPort();
            boolean defaultPort = (port == -1) || (protocol.equals("http") && port == 80) || (protocol.equals("https") && port == 443);
            return protocol + "://" + host + (defaultPort ? "" : ":" + port);
        } catch (Exception e) {
            return null;
        }
    }

    private boolean isPageUrlInScope(String url, String startOrigin, String startDomain, boolean sameOriginOnly) {
        String canon = canonicalizePageUrl(url);
        if (canon == null) return false;
        return isCanonicalPageUrlInScope(canon, startOrigin, startDomain, sameOriginOnly);
    }

    private boolean isCanonicalPageUrlInScope(String canonicalUrl, String startOrigin, String startDomain, boolean sameOriginOnly) {
        String origin = getUrlOrigin(canonicalUrl);
        if (origin == null) return false;
        if (sameOriginOnly) {
            return startOrigin != null && startOrigin.equalsIgnoreCase(origin);
        }
        String domain = getDomainFromUrl(canonicalUrl);
        return startDomain == null || domain == null || isSameRootDomain(domain, startDomain);
    }

    /** 获取父域（如 v.ruc.edu.cn -> .ruc.edu.cn），用于 access_token 等跨子域 Cookie */
    private static String getParentDomain(String host) {
        if (host == null || host.isEmpty()) return null;
        int dot = host.indexOf('.');
        return dot > 0 ? "." + host.substring(dot + 1) : null;
    }

    protected void log(String msg) {
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
