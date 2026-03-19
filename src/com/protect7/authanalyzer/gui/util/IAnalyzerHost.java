package com.protect7.authanalyzer.gui.util;

import com.protect7.authanalyzer.gui.main.ConfigurationPanel;

/**
 * Analyzer 宿主面板接口，提供 ConfigurationPanel 与 CenterPanel 操作。
 * 由 MainPanel 或合并后的 UI Testing 面板实现。
 */
public interface IAnalyzerHost {
    ICenterPanelFacade getCenterPanelFacade();
    ConfigurationPanel getConfigurationPanel();
    void updateDividerLocation();

    /** Original 的 headers（用于对称采集身份识别）。无则返回空字符串。 */
    default String getOriginalHeadersToReplace() {
        return "";
    }

    /** 设置 Original 的 headers（用于对称采集交换配置）。 */
    default void setOriginalHeadersToReplace(String headers) {
        // 默认空实现
    }

    /** 触发抓取（Run2 后自动执行，使用交换后的 Original 即 Session1 的 Cookie）。不支持则空实现。 */
    default void triggerRun2Crawl() {
        // 默认空实现
    }

    /** 对称采集开关切换时回调，用于更新 Run1/Run2 切换面板可见性。 */
    default void onSymmetricCaptureToggled() {
        // 默认空实现
    }

    /** 是否支持对称采集（需提供 Original headers 用于身份过滤）。MainPanel 不支持，合并布局支持。 */
    default boolean supportsSymmetricCapture() {
        return false;
    }
}
