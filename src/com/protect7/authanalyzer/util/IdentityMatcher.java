package com.protect7.authanalyzer.util;

import java.util.List;

/**
 * 判断请求是否匹配指定身份的 headers（用于对称采集时的流量过滤）。
 */
public final class IdentityMatcher {

    private IdentityMatcher() {}

    /**
     * 请求的 headers 是否包含 headersToReplace 中的每一行。
     * 若 headersToReplace 为 null 或空，返回 true（不过滤）。
     */
    public static boolean requestMatchesHeaders(List<String> requestHeaders, String headersToReplace) {
        if (requestHeaders == null) return false;
        if (headersToReplace == null || headersToReplace.trim().isEmpty()) {
            return true;
        }
        String[] lines = headersToReplace.replace("\r", "").split("\n");
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) continue;
            if (!requestHeaders.contains(trimmed)) {
                return false;
            }
        }
        return true;
    }
}
