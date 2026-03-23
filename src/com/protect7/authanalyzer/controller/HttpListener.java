package com.protect7.authanalyzer.controller;

import java.util.List;
import com.protect7.authanalyzer.filter.RequestFilter;
import com.protect7.authanalyzer.uitesting.runner.DualDetectionManager;
import com.protect7.authanalyzer.util.CurrentConfig;
import com.protect7.authanalyzer.util.IdentityMatcher;
import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IInterceptedProxyMessage;
import burp.IProxyListener;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class HttpListener implements IHttpListener, IProxyListener {

	private final CurrentConfig config = CurrentConfig.getCurrentConfig();

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		// Dual Detection: record requests from BrowserA and BrowserB (skip static resources)
		if (!messageIsRequest && DualDetectionManager.isEnabled()) {
			IRequestInfo reqInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(messageInfo);
			if (!isStaticResource(reqInfo)) {
				DualDetectionManager.recordRequest(messageInfo, reqInfo);
			}
		}

		// Skip auth analyzer processing for UI testing browsers to prevent infinite loops
		if (isUITestingBrowser(messageInfo)) {
			return;
		}

		if(config.isRunning() && (!messageIsRequest || (messageIsRequest && config.isDropOriginal() && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY))) {
			if(!isFiltered(toolFlag, messageInfo)) {
				if (config.isSymmetricCaptureEnabled() && messageIsRequest) {
					IRequestInfo reqInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(messageInfo);
					List<String> headers = reqInfo.getHeaders();
					String currentOriginal = config.getCurrentOriginalHeaders();
					if (!IdentityMatcher.requestMatchesHeaders(headers, currentOriginal)) {
						return;
					}
				}
				config.performAuthAnalyzerRequest(messageInfo);
			}
		}
	}

	@Override
	public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
		if(config.isDropOriginal() && messageIsRequest) {
			if(!isFiltered(IBurpExtenderCallbacks.TOOL_PROXY, message.getMessageInfo())) {
				processHttpMessage(IBurpExtenderCallbacks.TOOL_PROXY, true, message.getMessageInfo());
				message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
			}
		}
	}
	
	private boolean isFiltered(int toolFlag, IHttpRequestResponse messageInfo) {
		boolean isFiltered = false;
		IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(messageInfo);
		IResponseInfo responseInfo = null;
		if(messageInfo.getResponse() != null) {
			responseInfo = BurpExtender.callbacks.getHelpers().analyzeResponse(messageInfo.getResponse());
		}
		for(int i=0; i<config.getRequestFilterList().size(); i++) {
			RequestFilter filter = config.getRequestFilterAt(i);
			if(filter.filterRequest(BurpExtender.callbacks, toolFlag, requestInfo, responseInfo)) {
				return true;
			}
		}
		return isFiltered;
	}

	/**
	 * Check if the request is for a static resource (images, CSS, JS, fonts, etc.)
	 * to reduce noise in dual detection mode
	 */
	private boolean isStaticResource(IRequestInfo requestInfo) {
		String url = requestInfo.getUrl().toString().toLowerCase();
		// Skip common static resources
		return url.endsWith(".jpg") || url.endsWith(".jpeg") || url.endsWith(".png") ||
		       url.endsWith(".gif") || url.endsWith(".svg") || url.endsWith(".ico") ||
		       url.endsWith(".webp") || url.endsWith(".bmp") ||
		       url.endsWith(".css") ||
		       url.endsWith(".js") ||
		       url.endsWith(".woff") || url.endsWith(".woff2") || url.endsWith(".ttf") ||
		       url.endsWith(".eot") || url.endsWith(".otf") ||
		       url.endsWith(".mp4") || url.endsWith(".webm") || url.endsWith(".mp3") ||
		       url.endsWith(".pdf") || url.endsWith(".zip") || url.endsWith(".tar") ||
		       url.contains("/favicon.") || url.contains("manifest.json");
	}

	/**
	 * Check if the request comes from UI testing browsers (BrowserA or BrowserB)
	 * to prevent infinite loops when auth analyzer processes their requests
	 */
	private boolean isUITestingBrowser(IHttpRequestResponse messageInfo) {
		try {
			IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(messageInfo);
			for (String header : requestInfo.getHeaders()) {
				if (header.toLowerCase().startsWith("user-agent:")) {
					String userAgent = header.substring("user-agent:".length()).trim();
					if (userAgent.contains("AuthAnalyzer-BrowserA") || userAgent.contains("AuthAnalyzer-BrowserB")) {
						return true;
					}
					break;
				}
			}
		} catch (Exception e) {
			// If we can't determine, assume it's not a UI testing browser
		}
		return false;
	}
}
