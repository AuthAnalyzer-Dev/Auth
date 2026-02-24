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
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.WebDriverWait;

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
import java.util.LinkedHashMap;
import java.util.List;

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

    // 抓取等待配置（缓解 SPA/慢页面「未找到元素」）
    private static final int RETURN_PAGE_WAIT_MS = 1500;
    private static final int FIND_RETRY_MS = 500;
    private static final int FIND_RETRY_COUNT = 2;

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
        controls.onClearLog(e -> details.clearLog());
        controls.onClearTable(e -> onClearTable());

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

                // 第一轮：收集可点击元素 key（越权检测：同域过滤 + 扩展 button/form）
                LinkedHashMap<String, Void> clickableKeys = new LinkedHashMap<>();
                collectClickableKeys(driver, targetDomain, clickableKeys);
                log("[Crawl] 候选: " + clickableKeys.size());

                // 第二轮：每次点击后必须回到 target；仅点击登出时重新注入 Cookie，避免每次迭代都 applyCookies 过慢
                for (String key : clickableKeys.keySet()) {
                    boolean clickedLogout = false;
                    try {
                        log("[Crawl] 点击: " + key);
                        WebElement el = null;
                        for (int r = 0; r <= FIND_RETRY_COUNT && el == null; r++) {
                            if (r > 0) Thread.sleep(FIND_RETRY_MS);
                            el = findClickableByKey(driver, key);
                        }
                        if (el == null) {
                            log("[Crawl] 未找到元素: " + key);
                            continue;
                        }
                        clickedLogout = isLogoutKey(key);
                        try {
                            ((JavascriptExecutor) driver).executeScript("arguments[0].scrollIntoView({block:'center'});", el);
                            Thread.sleep(100);
                        } catch (Throwable scrollEx) { /* 滚动失败不影响点击 */ }
                        ensureClickInSameTab(driver, el);
                        Thread.sleep(600);
                    } catch (Throwable t) {
                        log("[Crawl] 点击失败: " + key + " -> " + t.getMessage());
                    } finally {
                        if (targetPage != null && !targetPage.isEmpty()) {
                            try {
                                if (clickedLogout) applyCookies(driver, targetPage);
                                driver.get(targetPage);
                                waitForPageReady(driver);
                                Thread.sleep(RETURN_PAGE_WAIT_MS);
                            } catch (Throwable ignore) {}
                        }
                    }
                }
                log("[Crawl] 完成");
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                log("[Crawl] 中断");
            } catch (WebDriverException wde) {
                if (wde.getMessage() != null && wde.getMessage().contains("invalid session id")) {
                    log("[Crawl] 浏览器会话已失效（可能已关闭），正在重启...");
                    ProxyDriverManager.stopDriver();
                    try {
                        WebDriver newDriver = ProxyDriverManager.getOrStartDriver(true, PROXY_HOST, PROXY_PORT, false);
                        if (newDriver != null) {
                            log("[Crawl] 已重启，请再次点击抓取");
                        }
                    } catch (Throwable restartEx) {
                        log("[Crawl] 重启失败: " + restartEx.getMessage());
                    }
                } else {
                    log("[Crawl] 出错: " + wde.getMessage());
                    wde.printStackTrace(stderr);
                }
            } catch (Throwable ex) {
                log("[Crawl] 出错: " + ex.getMessage());
                ex.printStackTrace(stderr);
            }
        }, "Crawl-Click-Thread").start();
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

    /** 注入 Cookie（access_token/tiup_uid/session），用于初始登录及点击登出后恢复登录 */
    private void applyCookies(WebDriver driver, String targetPage, boolean logOnApply) {
        String accessToken = controls.getAccessToken();
        String tiupUid = controls.getTiupUid();
        String session = controls.getSessionStr();
        boolean hasAny = (accessToken != null && !accessToken.trim().isEmpty())
                || (tiupUid != null && !tiupUid.trim().isEmpty())
                || (session != null && !session.trim().isEmpty());
        if (!hasAny) return;
        String domain = getDomainFromUrl(targetPage);
        String parentDomain = getParentDomain(domain);
        if (domain == null) return;
        try {
            driver.manage().deleteAllCookies();
            boolean isHttps = targetPage != null && targetPage.trim().toLowerCase().startsWith("https");
            if (accessToken != null && !accessToken.trim().isEmpty() && parentDomain != null) {
                driver.manage().addCookie(new Cookie.Builder("access_token", accessToken.trim())
                        .domain(parentDomain).path("/").isSecure(isHttps).build());
            }
            if (tiupUid != null && !tiupUid.trim().isEmpty()) {
                driver.manage().addCookie(new Cookie.Builder("tiup_uid", tiupUid.trim())
                        .domain(domain).path("/").isSecure(isHttps).build());
            }
            if (session != null && !session.trim().isEmpty()) {
                driver.manage().addCookie(new Cookie.Builder("session", session.trim())
                        .domain(domain).path("/").isSecure(isHttps).build());
            }
            if (logOnApply) log("[Crawl] 已应用 Cookie");
        } catch (Exception cex) {
            log("[Crawl] 设置 Cookie 失败: " + cex.getMessage());
        }
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
                if (textEmpty && hrefEmpty) continue;
                String keyPart = pickAnchorKey(text, href, textEmpty, hrefEmpty);
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
    }

    /** 图标链接（text 短）优先用 href 作为 key，避免环境差异导致匹配失败 */
    private String pickAnchorKey(String text, String href, boolean textEmpty, boolean hrefEmpty) {
        if (textEmpty) return hrefEmpty ? null : href.trim();
        if (hrefEmpty) return text.trim();
        String t = text.trim();
        if (t.length() <= 2) return href.trim();
        return t;
    }

    /** 规范化 key 用于匹配：trim + 合并连续空白 */
    private String normalizeKey(String s) {
        if (s == null) return "";
        return s.trim().replaceAll("\\s+", " ");
    }

    /** href 是否在越权检测范围内：同域、非 mailto/tel 等 */
    private boolean isHrefInScopeForAuth(String href, String targetDomain) {
        if (href == null || href.trim().isEmpty()) return true;
        String h = href.trim().toLowerCase();
        if (h.startsWith("mailto:") || h.startsWith("tel:") || h.startsWith("data:") || h.startsWith("blob:"))
            return false;
        if (h.startsWith("javascript:") || h.startsWith("#")) return true;
        if (!h.startsWith("http://") && !h.startsWith("https://")) return true;
        try {
            if (targetDomain == null) return true;
            String domain = getDomainFromUrl(href);
            return domain != null && domain.equalsIgnoreCase(targetDomain);
        } catch (Throwable ignore) { return false; }
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
                if (textEmpty && hrefEmpty) continue;
                String keyPart = pickAnchorKey(text, href, textEmpty, hrefEmpty);
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
        return null;
    }

    private void onClearTable() {
        CurrentConfig config = CurrentConfig.getCurrentConfig();
        Runnable clear = () -> {
            if (BurpExtender.mainPanel != null) {
                BurpExtender.mainPanel.getCenterPanel().clearTable();
            }
        };
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
            if (wde.getMessage() != null && wde.getMessage().contains("invalid session id")) {
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

    /** 获取父域（如 v.ruc.edu.cn -> .ruc.edu.cn），用于 access_token 等跨子域 Cookie */
    private static String getParentDomain(String host) {
        if (host == null || host.isEmpty()) return null;
        int dot = host.indexOf('.');
        return dot > 0 ? "." + host.substring(dot + 1) : null;
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
