package com.protect7.authanalyzer.gui.Result;

import java.awt.BorderLayout;
import java.awt.Font;
import java.util.Arrays;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;

/**
 * Result 页面的详情面板：展示 Original 与选中 Session 的请求/响应。
 */
class ResultDetailPanel extends JPanel {

    private static final long serialVersionUID = 1L;
    private final JTabbedPane rootTabs = new JTabbedPane();
    private final JTabbedPane originalTP = new JTabbedPane();
    private final JTabbedPane sessionTP = new JTabbedPane();
    private final JTextArea originalReq = monoArea();
    private final JTextArea originalResp = monoArea();
    private final JTextArea sessionReq = monoArea();
    private final JTextArea sessionResp = monoArea();

    ResultDetailPanel() {
        setLayout(new BorderLayout());
        originalTP.addTab("Request", new JScrollPane(originalReq));
        originalTP.addTab("Response", new JScrollPane(originalResp));
        sessionTP.addTab("Request", new JScrollPane(sessionReq));
        sessionTP.addTab("Response", new JScrollPane(sessionResp));
        rootTabs.addTab("Original", originalTP);
        rootTabs.addTab("Session", sessionTP);
        add(rootTabs, BorderLayout.CENTER);
    }

    void showEmpty() {
        originalReq.setText("[请选择表格中的一行]");
        originalResp.setText("");
        sessionReq.setText("");
        sessionResp.setText("");
    }

    void showOriginal(OriginalRequestResponse orr) {
        try {
            if (orr == null || orr.getRequestResponse() == null) {
                originalReq.setText("[no original request]");
                originalResp.setText("");
                return;
            }
            IHttpRequestResponse rr = orr.getRequestResponse();
            String req = rr.getRequest() != null
                    ? BurpExtender.callbacks.getHelpers().bytesToString(rr.getRequest())
                    : "[no request]";
            originalReq.setText(req);
            originalReq.setCaretPosition(0);

            String respTxt = "[no response]";
            if (rr.getResponse() != null) {
                byte[] resp = rr.getResponse();
                IResponseInfo ri = BurpExtender.callbacks.getHelpers().analyzeResponse(resp);
                String head = String.join("\r\n", ri.getHeaders());
                String body = BurpExtender.callbacks.getHelpers().bytesToString(
                        Arrays.copyOfRange(resp, ri.getBodyOffset(), resp.length));
                respTxt = head + "\r\n\r\n" + body;
            }
            originalResp.setText(respTxt);
            originalResp.setCaretPosition(0);
        } catch (Throwable t) {
            originalReq.setText("[failed: " + t.getMessage() + "]");
            originalResp.setText("");
        }
    }

    void showSession(AnalyzerRequestResponse arr) {
        try {
            if (arr == null || arr.getRequestResponse() == null) {
                sessionReq.setText("[no replay for selected session]");
                sessionResp.setText("");
                return;
            }
            IHttpRequestResponse rr = arr.getRequestResponse();
            String req = rr.getRequest() != null
                    ? BurpExtender.callbacks.getHelpers().bytesToString(rr.getRequest())
                    : "[no request]";
            sessionReq.setText(req);
            sessionReq.setCaretPosition(0);

            String respTxt = "[no response]";
            if (rr.getResponse() != null) {
                byte[] resp = rr.getResponse();
                IResponseInfo ri = BurpExtender.callbacks.getHelpers().analyzeResponse(resp);
                String head = String.join("\r\n", ri.getHeaders());
                String body = BurpExtender.callbacks.getHelpers().bytesToString(
                        Arrays.copyOfRange(resp, ri.getBodyOffset(), resp.length));
                respTxt = head + "\r\n\r\n" + body;
            }
            sessionResp.setText(respTxt);
            sessionResp.setCaretPosition(0);
        } catch (Throwable t) {
            sessionReq.setText("[failed: " + t.getMessage() + "]");
            sessionResp.setText("");
        }
    }

    private static JTextArea monoArea() {
        JTextArea ta = new JTextArea();
        ta.setEditable(false);
        ta.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        ta.setLineWrap(false);
        return ta;
    }
}
