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
}
