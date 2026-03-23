package com.protect7.authanalyzer.gui.util;

/**
 * 表格/中心面板的 facade 接口，供 ConfigurationPanel、CurrentConfig 等调用。
 * 解耦对具体 CenterPanel 的依赖，便于将 Analyzer 合并到 UI Testing 等场景。
 */
public interface ICenterPanelFacade {
    void clearTable();
    void updateAmountOfPendingRequests(int amount);
    void initCenterPanel();
}
