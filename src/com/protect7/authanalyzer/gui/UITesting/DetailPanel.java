package com.protect7.authanalyzer.gui.UITesting;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.Arrays;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;

import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;

class DetailPanel extends JPanel {

    private final JTabbedPane rootTabs   = new JTabbedPane();       // Original | Session | Log
    private final JTabbedPane originalTP = new JTabbedPane();       // Request | Response
    private final JTabbedPane sessionTP  = new JTabbedPane();       // Request | Response

    private final JTextArea originalReq  = monoArea();
    private final JTextArea originalResp = monoArea();
    private final JTextArea sessionReq   = monoArea();
    private final JTextArea sessionResp  = monoArea();
    private final JTextArea logArea      = monoArea();

    DetailPanel() {
        setLayout(new BorderLayout());

        originalTP.addTab("Request", new JScrollPane(originalReq));
        originalTP.addTab("Response", new JScrollPane(originalResp));
        sessionTP.addTab("Request", new JScrollPane(sessionReq));
        sessionTP.addTab("Response", new JScrollPane(sessionResp));

        rootTabs.addTab("Original", originalTP);
        rootTabs.addTab("Session", sessionTP);

        JPanel logPanel = new JPanel(new BorderLayout());
        JButton clearLogBtn = new JButton("清空日志");
        clearLogBtn.addActionListener(e -> clearLog());
        JPanel logToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 2));
        logToolbar.add(clearLogBtn);
        logPanel.add(logToolbar, BorderLayout.NORTH);
        logPanel.add(new JScrollPane(logArea), BorderLayout.CENTER);
        rootTabs.addTab("Log", logPanel);

        add(rootTabs, BorderLayout.CENTER);
    }

    void setSessionTabTitle(String name) {
        int idx = rootTabs.indexOfComponent(sessionTP);
        if (idx >= 0) rootTabs.setTitleAt(idx, name);
    }

    void showOriginal(OriginalRequestResponse orr) {
        try {
            if (orr == null || orr.getRequestResponse() == null) {
                originalReq.setText("[no original request]");
                originalResp.setText("[no original response]");
                return;
            }
            IHttpRequestResponse rr = orr.getRequestResponse();

            String req = rr.getRequest()!=null
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
            originalReq.setText("[failed to render original: " + t.getMessage() + "]");
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

            String req = rr.getRequest()!=null
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
            sessionReq.setText("[failed to render session replay: " + t.getMessage() + "]");
            sessionResp.setText("");
        }
    }

    void appendLog(String msg) {
        logArea.append(msg + "\n");
        logArea.setCaretPosition(logArea.getDocument().getLength());
    }

    void clearLog() {
        logArea.setText("");
    }

    private static JTextArea monoArea() {
        JTextArea ta = new JTextArea();
        ta.setEditable(false);
        ta.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        ta.setLineWrap(false);
        return ta;
    }
}
