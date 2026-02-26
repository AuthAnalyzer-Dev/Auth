package com.protect7.authanalyzer.util;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.protect7.authanalyzer.controller.RequestController;
import com.protect7.authanalyzer.util.BypassConstants;
import burp.BurpExtender;
import burp.IResponseInfo;

/**
 * 对称采集后的平凡性/垂直/水平判定。
 */
public class TrivialityChecker {

    private final SymmetricTrafficStore store;
    private final RequestController requestController;
    private final Map<String, BypassStatus> statusCache = new ConcurrentHashMap<>();

    public TrivialityChecker(SymmetricTrafficStore store, RequestController requestController) {
        this.store = store;
        this.requestController = requestController;
    }

    /**
     * 计算指定 endpoint 的 BypassStatus。
     */
    public BypassStatus computeStatus(String endpointKey) {
        if (endpointKey == null) return BypassStatus.UNKNOWN;

        boolean hasA = store.hasResponseA(endpointKey);
        boolean hasB = store.hasResponseB(endpointKey);
        BypassConstants replay1 = store.getReplayStatusRun1(endpointKey);
        BypassConstants replay2 = store.getReplayStatusRun2(endpointKey);

        if (hasA && hasB) {
            byte[] respA = store.getResponseA(endpointKey);
            byte[] respB = store.getResponseB(endpointKey);
            if (respA != null && respB != null && isSameResponse(respA, respB)) {
                return BypassStatus.TRIVIAL;
            }
            if (isSuspiciousReplay(replay1) || isSuspiciousReplay(replay2)) {
                return BypassStatus.HORIZONTAL;
            }
            return BypassStatus.UNKNOWN;
        }

        if (hasA && !hasB && isSuspiciousReplay(replay1)) {
            return BypassStatus.VERTICAL;
        }
        if (!hasA && hasB && isSuspiciousReplay(replay2)) {
            return BypassStatus.VERTICAL;
        }

        return BypassStatus.UNKNOWN;
    }

    /**
     * 获取 endpoint 的 BypassStatus，带缓存。
     */
    public BypassStatus getStatus(String endpointKey) {
        return statusCache.computeIfAbsent(endpointKey, k -> computeStatus(k));
    }

    /** 清除缓存（Store 清空后调用） */
    public void clearCache() {
        statusCache.clear();
    }

    private static boolean isSuspiciousReplay(BypassConstants status) {
        return status == BypassConstants.SAME || status == BypassConstants.SIMILAR;
    }

    private boolean isSameResponse(byte[] respA, byte[] respB) {
        if (respA == null || respB == null) return false;
        try {
            IResponseInfo infoA = BurpExtender.callbacks.getHelpers().analyzeResponse(respA);
            IResponseInfo infoB = BurpExtender.callbacks.getHelpers().analyzeResponse(respB);
            return requestController.analyzeResponse(respA, respB, infoA, infoB) == BypassConstants.SAME;
        } catch (Exception e) {
            return false;
        }
    }
}
