package com.protect7.authanalyzer.util;

/**
 * 域名相关工具，用于 endpoint 配对时 host 规范化。
 * 与 UITestingPanel.isHrefInScopeForAuth 中的同根域逻辑保持一致，
 * 确保抓取范围扩大（api.xxx.com、www.xxx.com）后，Run1/Run2 能正确配对。
 */
public final class DomainHelper {

    private DomainHelper() {}

    /**
     * 提取根域名，用于 endpointKey 的 host 规范化。
     * 示例：www.example.com -> example.com，api.v.ruc.edu.cn -> ruc.edu.cn
     */
    public static String getRootDomain(String host) {
        if (host == null || host.isEmpty()) return host;
        String h = host.trim().toLowerCase();
        String[] parts = h.split("\\.");
        if (parts.length <= 2) return h;
        if (parts.length >= 3) {
            String lastTwo = parts[parts.length - 2] + "." + parts[parts.length - 1];
            if ("co.uk".equals(lastTwo) || "com.cn".equals(lastTwo) || "net.cn".equals(lastTwo)
                    || "org.cn".equals(lastTwo) || "gov.cn".equals(lastTwo) || "edu.cn".equals(lastTwo)) {
                if (parts.length >= 4) {
                    return parts[parts.length - 4] + "." + parts[parts.length - 3] + "." + lastTwo;
                }
            }
        }
        return parts[parts.length - 2] + "." + parts[parts.length - 1];
    }
}
