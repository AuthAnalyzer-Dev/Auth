package com.protect7.authanalyzer.gui.UITesting;

import java.awt.BorderLayout;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.SwingUtilities;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingConstants;
import com.protect7.authanalyzer.controller.ContextMenuController;
import com.protect7.authanalyzer.gui.main.ConfigurationPanel;
import com.protect7.authanalyzer.gui.util.IAnalyzerHost;
import com.protect7.authanalyzer.gui.util.ICenterPanelFacade;
import com.protect7.authanalyzer.gui.util.RequestTableModel;
import com.protect7.authanalyzer.util.CurrentConfig;
import burp.BurpExtender;

/**
 * 合并 Analyzer 与 UI Testing 的面板：左侧为 Analyzer 配置（Sessions、Filters、Start/Stop）
 * + UI Testing 配置（Target URL、Cookie、抓取按钮），右侧为表格与详情。
 */
public class MergedUITestingPanel extends UITestingPanel implements IAnalyzerHost {

    private static final long serialVersionUID = 1L;
    private final ConfigurationPanel configurationPanel;
    private final ICenterPanelFacade centerFacade;
    private final JLabel pendingRequestsLabel = new JLabel("", SwingConstants.CENTER);

    @Override
    protected ControlsPanel createControlsPanel() {
        return new ControlsPanel(true);
    }

    public MergedUITestingPanel() {
        RequestTableModel model = new RequestTableModel();
        CurrentConfig.getCurrentConfig().setTableModel(model);

        centerFacade = new ICenterPanelFacade() {
            @Override
            public void clearTable() {
                MergedUITestingPanel.this.clearTable();
            }
            @Override
            public void updateAmountOfPendingRequests(int amount) {
                if (amount == 0) {
                    pendingRequestsLabel.setVisible(false);
                } else {
                    pendingRequestsLabel.setVisible(true);
                    pendingRequestsLabel.setText("Pending: " + amount);
                }
            }
            @Override
            public void initCenterPanel() {
                MergedUITestingPanel.this.clearTable();
            }
        };
        CurrentConfig.setCenterPanelFacade(centerFacade);

        configurationPanel = new ConfigurationPanel(this);
        configurationPanel.loadAutoStoredData();
        configurationPanel.buildMergedLayout(
                getControls().getOriginalSectionPanel(),
                getControls().getTargetUrlSectionPanel(),
                getControls().getApiDiscoveryPanel(),
                getControls().getButtonsPanel());
        setAnalyzerConfigPanel(wrapConfigWithPending(configurationPanel), true);

        if (CurrentConfig.getCurrentConfig().isSymmetricCaptureEnabled()) {
            String h = getOriginalHeadersToReplace();
            CurrentConfig.getCurrentConfig().setCurrentOriginalHeaders(h != null ? h : "");
        }

        BurpExtender.callbacks.registerContextMenuFactory(new ContextMenuController(configurationPanel));
    }

    private JPanel wrapConfigWithPending(JPanel config) {
        JPanel wrap = new JPanel(new BorderLayout());
        wrap.add(new JScrollPane(config), BorderLayout.CENTER);
        pendingRequestsLabel.setVisible(false);
        wrap.add(pendingRequestsLabel, BorderLayout.SOUTH);
        return wrap;
    }

    @Override
    public ICenterPanelFacade getCenterPanelFacade() {
        return centerFacade;
    }

    @Override
    public ConfigurationPanel getConfigurationPanel() {
        return configurationPanel;
    }

    @Override
    public void updateDividerLocation() {
        // 合并布局无 splitPane 分隔条，可留空或做简单 revalidate
        revalidate();
    }

    @Override
    public String getOriginalHeadersToReplace() {
        return getControls().getHeadersToReplaceText();
    }

    @Override
    public void setOriginalHeadersToReplace(String headers) {
        getControls().setHeadersToReplaceText(headers);
    }

    @Override
    public void triggerRun2Crawl() {
        getControls().triggerCrawl();
    }

    @Override
    public void onSymmetricCaptureToggled() {
        tablePanel.setRunToggleVisible(CurrentConfig.getCurrentConfig().isSymmetricCaptureEnabled());
    }

    @Override
    public boolean supportsSymmetricCapture() {
        return true;
    }

    @Override
    protected void afterCrawlComplete(boolean success) {
        if (!success) return;
        boolean symmetric = CurrentConfig.getCurrentConfig().isSymmetricCaptureEnabled();
        boolean run2Mode = CurrentConfig.getCurrentConfig().isSymmetricRun2Mode();

        if (symmetric && !run2Mode) {
            runDiscoveryAfterCrawl();
            sendDiscoveredApisToAnalyzer(true);
            SwingUtilities.invokeLater(() -> {
                if (configurationPanel.performRun2Transition()) {
                    log("[Crawl] Run1 完成（含发现 API），自动进入 Run2...");
                    triggerRun2Crawl();
                }
            });
        } else if (symmetric && run2Mode) {
            runDiscoveryAfterCrawl();
            sendDiscoveredApisToAnalyzer(true);
        } else {
            super.afterCrawlComplete(true);
        }
    }
}
