package com.protect7.authanalyzer.util;

/**
 * 越权类型：用于对称采集后的平凡性/垂直/水平判定。
 */
public enum BypassStatus {
    TRIVIAL("Trivial"),
    VERTICAL("Vertical"),
    HORIZONTAL("Horizontal"),
    /** Run1 有、Run2 无：该 endpoint 仅用户 A 访问过 */
    RUN1_ONLY("Run2缺"),
    /** Run2 有、Run1 无：该 endpoint 仅用户 B 访问过 */
    RUN2_ONLY("Run1缺"),
    UNKNOWN("Unknown");

    private final String displayName;

    BypassStatus(String displayName) {
        this.displayName = displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
