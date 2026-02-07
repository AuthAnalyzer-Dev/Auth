package com.protect7.authanalyzer.uitesting.runner;

import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.util.BypassConstants;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IResponseInfo;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;

import java.io.PrintWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Replayer（镜像点击专用版）
 * - 不再“重放 HTTP”；
 * - 监听 A（主浏览器）的真实点击 -> 在 B（镜像浏览器）执行同样的 click，点不到就以 href 导航；
 * - B 在新域首次访问时自动注入 tiup_uid / session；
 * - 提供 持续镜像 + 一次性镜像 两种模式。
 */
public class Replayer {

    /* ===== 调试输出 ===== */
    private static volatile PrintWriter G_OUT = null, G_ERR = null;
    private static void out(String s){ if(G_OUT!=null) G_OUT.println(s); }
    private static void err(String s){ if(G_ERR!=null) G_ERR.println(s); }

    public static void setLoggers(PrintWriter stdout, PrintWriter stderr){
        G_OUT = stdout; G_ERR = stderr;
    }

    /* ===== JS：记录 selector + href + 是否为 SPA 导航 ===== */
    private static final String JS_INSTALL =
            "(()=>{if(window.__uaSpy)return true;window.__uaSpy=true;window.__uaQ=[];" +
                    "function css(el){if(!(el instanceof Element))return null;" +
                    " if(el.id) return '#'+CSS.escape(el.id);" +
                    " const arr=[]; let cur=el; let d=0;" +
                    " while(cur&&cur.nodeType===1&&d<8){" +
                    "   let s=cur.nodeName.toLowerCase();" +
                    "   if(cur.classList&&cur.classList.length){s+='.'+Array.from(cur.classList).slice(0,3).map(CSS.escape).join('.');}" +
                    "   let sib=cur,n=1; while((sib=sib.previousElementSibling)){ if(sib.nodeName===cur.nodeName) n++; }" +
                    "   s+=':nth-of-type('+n+')'; arr.unshift(s); if(cur.id) break; cur=cur.parentElement; d++; }" +
                    " return arr.join('>'); }" +
                    "document.addEventListener('click',ev=>{try{" +
                    " const t=ev.target; const sel=css(t);" +
                    " let href=null; let a=t.closest?t.closest('a'):null; if(a&&a.href) href=a.href;" +
                    " window.__uaQ.push({ts:Date.now(),sel:sel,href:href});" +
                    "}catch(e){}},true);" +
                    // 记录 SPA 导航（history API / popstate）
                    "const _ps=history.pushState,_rs=history.replaceState;" +
                    "function rec(){try{window.__uaQ.push({ts:Date.now(),spa:true,href:location.href});}catch(e){}}" +
                    "history.pushState=function(){_ps.apply(this,arguments);rec();};" +
                    "history.replaceState=function(){_rs.apply(this,arguments);rec();};" +
                    "window.addEventListener('popstate',rec);" +
                    "return true;})();";

    private static final String JS_DRAIN =
            "try{const q=window.__uaQ||[];window.__uaQ=[];return q;}catch(e){return [];}";

    /* ===== 持续镜像 ===== */
    private static final AtomicBoolean MIRROR_ON = new AtomicBoolean(false);
    private static Thread mirrorThread;

    /**
     * 开启“持续镜像”：A 每次点击都会在 B 上被镜像（click -> 导航回退）。
     */
    public static synchronized void startMirror(
            String bTiupUid, String bSession,
            String proxyHost, int proxyPort, boolean headless,
            PrintWriter stdout, PrintWriter stderr) {

        setLoggers(stdout, stderr);

        if (MIRROR_ON.get()) { out("[Mirror] 已开启"); return; }

        final WebDriver A = ProxyDriverManager.getDriver();
        if (A == null) { err("[Mirror] 主浏览器(A) 未启动"); return; }

        WebDriver B = ProxyDriverManager.getMirrorDriver();
        if (B == null) {
            B = ProxyDriverManager.startMirrorDriver(true, proxyHost, proxyPort, headless);
            out("[Mirror] 已启动镜像浏览器(B)");
        }
        final WebDriver AF = A, BF = B;
        final String uidF = bTiupUid, sessF = bSession;

        try {
            Object r = ((JavascriptExecutor)AF).executeScript(JS_INSTALL);
            out("[Mirror] 注入 A 监听结果: " + r);
        } catch (Throwable t) {
            err("[Mirror] 注入监听失败: " + t.getMessage());
            return;
        }

        MIRROR_ON.set(true);
        mirrorThread = new Thread(() -> {
            out("[Mirror] 镜像线程启动");
            while (MIRROR_ON.get()) {
                try {
                    Object q = ((JavascriptExecutor)AF).executeScript(JS_DRAIN);
                    if (q instanceof List) {
                        @SuppressWarnings("unchecked")
                        List<Map<String,Object>> list = (List<Map<String,Object>>) q;
                        if (!list.isEmpty()) {
                            Map<String,Object> e = list.get(list.size()-1);
                            String sel  = asStr(e.get("sel"));
                            String href = asStr(e.get("href"));
                            boolean spa = Boolean.TRUE.equals(e.get("spa"));
                            out("[Mirror] 捕获 A 点击: sel="+sel+" href="+href+" spa="+spa);

                            // 先确保 B 具备 cookie（按当前 A 的域注入；如果后面导航到新域，会再注入）
                            String aUrl = currentUrl(AF);
                            if (aUrl != null) ensureCookies(BF, aUrl, uidF, sessF);

                            boolean clicked = false;
                            if (sel != null && !sel.isEmpty()) {
                                try {
                                    Object ok = ((JavascriptExecutor)BF).executeScript(
                                            "var el=document.querySelector(arguments[0]); if(el){ el.click(); return true; } return false;",
                                            sel
                                    );
                                    clicked = Boolean.TRUE.equals(ok);
                                    out("[Mirror] B.click(): "+sel+" -> "+clicked);
                                } catch (Throwable ex) {
                                    err("[Mirror] B.click 异常: " + ex.getMessage());
                                }
                            }
                            if (!clicked && href != null && !href.isEmpty()) {
                                try {
                                    ensureCookies(BF, href, uidF, sessF);
                                    BF.get(href);
                                    out("[Mirror] B 导航兜底: " + href);
                                } catch (Throwable ex) {
                                    err("[Mirror] B 导航失败: " + ex.getMessage());
                                }
                            }
                        }
                    }
                } catch (Throwable t) {
                    err("[Mirror] 线程异常: " + t.getMessage());
                }
                try { Thread.sleep(100); } catch (InterruptedException ignored) {}
            }
            out("[Mirror] 镜像线程退出");
        }, "mirror-loop");
        mirrorThread.setDaemon(true);
        mirrorThread.start();
    }

    /** 停止持续镜像 */
    public static synchronized void stopMirror(PrintWriter stdout) {
        setLoggers(stdout, G_ERR);
        if (!MIRROR_ON.get()) { out("[Mirror] 未开启"); return; }
        MIRROR_ON.set(false);
        try { if (mirrorThread != null) mirrorThread.join(Duration.ofSeconds(2).toMillis()); } catch (InterruptedException ignored) {}
        mirrorThread = null;
        out("[Mirror] 已停止");
    }

    /** 检查镜像模式是否正在运行 */
    public static boolean isMirrorRunning() {
        return MIRROR_ON.get();
    }

    /* ===== 一次性镜像（只镜像下一次点击） ===== */
    public static void mirrorNextClickOnce(String bTiupUid, String bSession, long maxWaitMs, PrintWriter stdout, PrintWriter stderr) {
        setLoggers(stdout, stderr);
        final WebDriver A = ProxyDriverManager.getDriver();
        final WebDriver B = ProxyDriverManager.getMirrorDriver();
        if (A == null || B == null) { err("[Mirror-Once] 需要已启动的 A&B 浏览器"); return; }
        try { ((JavascriptExecutor)A).executeScript(JS_INSTALL); } catch (Throwable t){ err("[Mirror-Once] 注入失败: "+t.getMessage()); return; }

        long end = System.currentTimeMillis() + (maxWaitMs > 0 ? maxWaitMs : 5000);
        out("[Mirror-Once] 等待下一次点击…(最多 " + (end - System.currentTimeMillis()) + " ms)");
        while (System.currentTimeMillis() < end) {
            try {
                Object q = ((JavascriptExecutor)A).executeScript(JS_DRAIN);
                if (q instanceof List) {
                    @SuppressWarnings("unchecked")
                    List<Map<String,Object>> list = (List<Map<String,Object>>) q;
                    if (!list.isEmpty()) {
                        Map<String,Object> e = list.get(list.size()-1);
                        String sel  = asStr(e.get("sel"));
                        String href = asStr(e.get("href"));
                        boolean spa = Boolean.TRUE.equals(e.get("spa"));
                        out("[Mirror-Once] 收到事件 sel="+sel+" href="+href+" spa="+spa);

                        String base = currentUrl(A);
                        if (base != null) ensureCookies(B, base, bTiupUid, bSession);

                        boolean clicked = false;
                        if (sel != null && !sel.isEmpty()) {
                            try {
                                Object ok = ((JavascriptExecutor)B).executeScript(
                                        "var el=document.querySelector(arguments[0]); if(el){ el.click(); return true; } return false;",
                                        sel
                                );
                                clicked = Boolean.TRUE.equals(ok);
                                out("[Mirror-Once] B.click(): "+sel+" -> "+clicked);
                            } catch (Throwable ex) { err("[Mirror-Once] B.click 异常: " + ex.getMessage()); }
                        }
                        if (!clicked && href != null && !href.isEmpty()) {
                            try { ensureCookies(B, href, bTiupUid, bSession); B.get(href); out("[Mirror-Once] B 导航兜底: "+href); }
                            catch (Throwable ex){ err("[Mirror-Once] B 导航失败: " + ex.getMessage()); }
                        }
                        return; // 完成一次镜像
                    }
                }
            } catch (Throwable t) {
                err("[Mirror-Once] 轮询异常: " + t.getMessage());
                break;
            }
            try { Thread.sleep(80); } catch (InterruptedException ignored) {}
        }
        err("[Mirror-Once] 超时未捕获到点击");
    }

    /* ===== 工具 ===== */
    private static String asStr(Object o){ return o==null?null:String.valueOf(o); }

    private static String currentUrl(WebDriver d){
        try { return d.getCurrentUrl(); }
        catch(Throwable t){ try{ Object href=((JavascriptExecutor)d).executeScript("return location.href||document.URL||null;"); return href==null?null:href.toString(); }catch(Throwable ignored){ return null; } }
    }

    /** 按 URL 的 host 注入 B 账号 cookie（首次注入即可；HttpOnly 读不回属正常） */
    private static void ensureCookies(WebDriver drv, String url, String uid, String sess){
        String host = hostOnly(url); if (host == null) return;
        String scheme = schemeOnly(url);
        String root = scheme + "://" + host + "/";
        try {
            drv.get(root);
            if (uid != null && !uid.isEmpty())  drv.manage().addCookie(new Cookie("tiup_uid", uid));
            if (sess != null && !sess.isEmpty()) drv.manage().addCookie(new Cookie("session",  sess));
            out("[Mirror] 写入 B cookie -> host=" + host);
        } catch (Throwable ignored) {}
    }

    private static String hostOnly(String url){
        try { return new URI(url).getHost(); } catch (URISyntaxException e) { return null; }
    }
    private static String schemeOnly(String url){
        try { String s=new URI(url).getScheme(); return s==null?"https":s; } catch (URISyntaxException e) { return "https"; }
    }

    /* ===== HTTP 请求重放功能 ===== */

    /**
     * 重放原始请求到指定 Session（替换 Cookie）
     * @param orr 原始请求响应
     * @param session 目标 Session
     * @param tiupUid tiup_uid cookie 值
     * @param sessionCookie session cookie 值
     * @param stdout 标准输出
     * @param stderr 错误输出
     * @return 重放后的 AnalyzerRequestResponse，失败返回 null
     */
    public static AnalyzerRequestResponse replayOriginalToSession(
            OriginalRequestResponse orr,
            Session session,
            String tiupUid,
            String sessionCookie,
            PrintWriter stdout,
            PrintWriter stderr) {

        setLoggers(stdout, stderr);

        try {
            if (orr == null || session == null) {
                err("[Replay] ORR 或 Session 为 null");
                return null;
            }

            IHttpRequestResponse originalReqResp = orr.getRequestResponse();
            if (originalReqResp == null || originalReqResp.getRequest() == null) {
                err("[Replay] 原始请求为空");
                return null;
            }

            byte[] originalRequest = originalReqResp.getRequest();

            // 解析原始请求
            IRequestInfo reqInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(originalRequest);
            List<String> headers = new ArrayList<>(reqInfo.getHeaders());

            // 替换 Cookie 头
            boolean foundCookie = false;
            for (int i = 0; i < headers.size(); i++) {
                String header = headers.get(i);
                if (header.toLowerCase().startsWith("cookie:")) {
                    // 构建新的 Cookie 头
                    StringBuilder newCookie = new StringBuilder("Cookie: ");
                    if (tiupUid != null && !tiupUid.isEmpty()) {
                        newCookie.append("tiup_uid=").append(tiupUid).append("; ");
                    }
                    if (sessionCookie != null && !sessionCookie.isEmpty()) {
                        newCookie.append("session=").append(sessionCookie);
                    }
                    headers.set(i, newCookie.toString());
                    foundCookie = true;
                    break;
                }
            }

            // 如果没有 Cookie 头，添加一个
            if (!foundCookie) {
                StringBuilder newCookie = new StringBuilder("Cookie: ");
                if (tiupUid != null && !tiupUid.isEmpty()) {
                    newCookie.append("tiup_uid=").append(tiupUid).append("; ");
                }
                if (sessionCookie != null && !sessionCookie.isEmpty()) {
                    newCookie.append("session=").append(sessionCookie);
                }
                headers.add(newCookie.toString());
            }

            // 获取请求体
            int bodyOffset = reqInfo.getBodyOffset();
            byte[] body = new byte[originalRequest.length - bodyOffset];
            System.arraycopy(originalRequest, bodyOffset, body, 0, body.length);

            // 构建新请求
            byte[] newRequest = BurpExtender.callbacks.getHelpers().buildHttpMessage(headers, body);

            // 发送请求
            IHttpService httpService = originalReqResp.getHttpService();
            IHttpRequestResponse newReqResp = BurpExtender.callbacks.makeHttpRequest(httpService, newRequest);

            out("[Replay] 重放完成: " + reqInfo.getUrl());

            // 分析响应
            int statusCode = -1;
            int responseContentLength = -1;
            if (newReqResp.getResponse() != null) {
                burp.IResponseInfo respInfo = BurpExtender.callbacks.getHelpers().analyzeResponse(newReqResp.getResponse());
                statusCode = respInfo.getStatusCode();
                responseContentLength = newReqResp.getResponse().length - respInfo.getBodyOffset();
            }

            // 创建 AnalyzerRequestResponse
            AnalyzerRequestResponse arr = new AnalyzerRequestResponse(
                    newReqResp,
                    com.protect7.authanalyzer.util.BypassConstants.NA,
                    "Replayed for session: " + session.getName(),
                    statusCode,
                    responseContentLength
            );

            // 将结果存入 Session 的 RequestResponseMap
            session.getRequestResponseMap().put(orr.getId(), arr);

            return arr;

        } catch (Exception e) {
            err("[Replay] 重放失败: " + e.getMessage());
            e.printStackTrace(stderr);
            return null;
        }
    }
}
