package com.protect7.authanalyzer.ai;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.ArrayList;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;

import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.Result.ResultTableModel;
import com.protect7.authanalyzer.gui.util.TabVisibilityAware;
import com.protect7.authanalyzer.util.CurrentConfig;
import com.protect7.authanalyzer.util.Setting;

/**
 * AI 分析标签页主面板。
 * 布局：顶部配置区 → 进度条 → 左侧结果列表 / 右侧 AI 分析详情。
 */
public class AIAnalysisPanel extends JPanel implements TabVisibilityAware {

    private static final long serialVersionUID = 1L;

    // ── 配置区控件 ──
    private final JTextField urlField    = new JTextField(28);
    private final JTextField keyField    = new JTextField(22);
    private final JTextField modelField  = new JTextField(16);
    private final JTextArea  promptArea  = new JTextArea(4, 40);
    private final JButton    startBtn    = new JButton("开始分析");
    private final JButton    stopBtn     = new JButton("停止");
    private final JButton    clearBtn    = new JButton("清空结果");
    private final JButton    testBtn     = new JButton("测试连接");
    private final JButton    resetPromptBtn = new JButton("重置 Prompt");

    // ── 进度 ──
    private final JProgressBar progressBar = new JProgressBar(0, 1);
    private final JLabel       statusLabel  = new JLabel("就绪");

    // ── 结果列表 ──
    private final ResultListModel listModel = new ResultListModel();
    private final JTable          listTable  = new JTable(listModel);

    // ── 右侧详情 ──
    private final JTextArea detailArea = new JTextArea();

    private AIAnalysisService service;

    public AIAnalysisPanel() {
        setLayout(new BorderLayout(4, 4));
        setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        add(buildConfigPanel(), BorderLayout.NORTH);
        add(buildCenterPanel(), BorderLayout.CENTER);

        loadSettings();
        wireButtons();
    }

    // =========================================================================
    // UI 构建
    // =========================================================================

    private JPanel buildConfigPanel() {
        JPanel outer = new JPanel(new BorderLayout(4, 4));
        outer.setBorder(BorderFactory.createTitledBorder("AI 配置"));

        JPanel fields = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(2, 4, 2, 4);
        c.anchor = GridBagConstraints.WEST;

        // Row 0: URL + Key + Model
        c.gridx = 0; c.gridy = 0; fields.add(new JLabel("API URL:"), c);
        c.gridx = 1; fields.add(urlField, c);
        c.gridx = 2; fields.add(new JLabel("API Key:"), c);
        c.gridx = 3; fields.add(keyField, c);
        c.gridx = 4; fields.add(new JLabel("Model:"), c);
        c.gridx = 5; fields.add(modelField, c);

        // Row 1: Prompt
        c.gridx = 0; c.gridy = 1; fields.add(new JLabel("System Prompt:"), c);
        promptArea.setLineWrap(true);
        promptArea.setWrapStyleWord(true);
        promptArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        JScrollPane promptScroll = new JScrollPane(promptArea);
        promptScroll.setPreferredSize(new Dimension(600, 70));
        c.gridx = 1; c.gridy = 1; c.gridwidth = 5; c.fill = GridBagConstraints.HORIZONTAL;
        fields.add(promptScroll, c);
        c.gridwidth = 1; c.fill = GridBagConstraints.NONE;

        outer.add(fields, BorderLayout.CENTER);

        // Buttons + progress row
        JPanel bottom = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        stopBtn.setEnabled(false);
        bottom.add(startBtn);
        bottom.add(stopBtn);
        bottom.add(clearBtn);
        bottom.add(testBtn);
        bottom.add(resetPromptBtn);
        progressBar.setStringPainted(true);
        progressBar.setPreferredSize(new Dimension(200, 20));
        bottom.add(progressBar);
        bottom.add(statusLabel);
        outer.add(bottom, BorderLayout.SOUTH);

        return outer;
    }

    private JSplitPane buildCenterPanel() {
        // 左：结果列表
        listTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        listTable.setAutoCreateRowSorter(true);
        listTable.setFillsViewportHeight(true);
        listTable.getColumnModel().getColumn(0).setPreferredWidth(40);
        listTable.getColumnModel().getColumn(1).setPreferredWidth(55);
        listTable.getColumnModel().getColumn(2).setPreferredWidth(180);
        listTable.getColumnModel().getColumn(3).setPreferredWidth(55);
        listTable.getColumnModel().getColumn(4).setPreferredWidth(280);

        listTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) showDetail();
        });

        JScrollPane leftScroll = new JScrollPane(listTable);
        leftScroll.setBorder(BorderFactory.createTitledBorder("分析结果列表"));

        // 右：AI 分析详情
        detailArea.setEditable(false);
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(true);
        detailArea.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));
        JScrollPane rightScroll = new JScrollPane(detailArea);
        rightScroll.setBorder(BorderFactory.createTitledBorder("AI 分析详情"));

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftScroll, rightScroll);
        split.setResizeWeight(0.55);
        return split;
    }

    // =========================================================================
    // 按钮逻辑
    // =========================================================================

    private void wireButtons() {
        startBtn.addActionListener(e -> startAnalysis());
        stopBtn.addActionListener(e -> stopAnalysis());
        testBtn.addActionListener(e -> testConnection());
        resetPromptBtn.addActionListener(e -> {
            promptArea.setText(AIAnalysisService.getDefaultSystemPrompt());
            statusLabel.setForeground(Color.BLACK);
            statusLabel.setText("Prompt 已重置为默认值");
        });
        clearBtn.addActionListener(e -> {
            listModel.clear();
            detailArea.setText("");
            progressBar.setValue(0);
            statusLabel.setText("已清空");
        });
    }

    private void testConnection() {
        String url   = urlField.getText().trim();
        String key   = keyField.getText().trim();
        String model = modelField.getText().trim();
        if (url.isEmpty() || key.isEmpty() || model.isEmpty()) {
            statusLabel.setText("请先填写 API URL、Key 和 Model");
            statusLabel.setForeground(java.awt.Color.RED);
            return;
        }
        testBtn.setEnabled(false);
        statusLabel.setForeground(java.awt.Color.BLACK);
        statusLabel.setText("正在测试连接...");
        AIAnalysisService svc = new AIAnalysisService(url, key, model, "", 1);
        svc.testConnectionAsync(
            null,
            result -> SwingUtilities.invokeLater(() -> {
                statusLabel.setText(result.replace("\n", " "));
                statusLabel.setForeground(result.startsWith("[连接成功]") ? new java.awt.Color(0, 128, 0) : java.awt.Color.RED);
                testBtn.setEnabled(true);
                // 弹出详细信息对话框，方便查看完整错误
                javax.swing.JOptionPane.showMessageDialog(
                    AIAnalysisPanel.this, result, "连接测试结果",
                    result.startsWith("[连接成功]") ? javax.swing.JOptionPane.INFORMATION_MESSAGE : javax.swing.JOptionPane.ERROR_MESSAGE);
            })
        );
    }

    private void startAnalysis() {
        String url    = urlField.getText().trim();
        String key    = keyField.getText().trim();
        String model  = modelField.getText().trim();
        String prompt = promptArea.getText().trim();

        if (url.isEmpty() || key.isEmpty() || model.isEmpty()) {
            statusLabel.setText("请填写 API URL、Key 和 Model");
            statusLabel.setForeground(Color.RED);
            return;
        }
        statusLabel.setForeground(Color.BLACK);
        saveSettings();

        // 从 Result 模型取出 SAME/SIMILAR 条目
        ResultTableModel resultModel = new ResultTableModel();
        resultModel.refresh();
        List<OriginalRequestResponse> items = resultModel.getFilteredList();
        List<Session> sessions = CurrentConfig.getCurrentConfig().getSessions();

        if (items.isEmpty()) {
            statusLabel.setText("没有 SAME/SIMILAR 条目可分析，请先运行 Analyzer");
            return;
        }

        listModel.clear();
        detailArea.setText("");
        progressBar.setMaximum(items.size());
        progressBar.setValue(0);
        startBtn.setEnabled(false);
        stopBtn.setEnabled(true);

        service = new AIAnalysisService(url, key, model, prompt, 2);
        service.analyzeAsync(items, sessions, new AIAnalysisService.AnalysisListener() {
            @Override
            public void onStart(int total) {
                SwingUtilities.invokeLater(() -> statusLabel.setText("分析中... 共 " + total + " 条"));
            }

            @Override
            public void onResult(int index, OriginalRequestResponse orr, String aiResult, int done, int total) {
                SwingUtilities.invokeLater(() -> {
                    listModel.addRow(orr, aiResult);
                    progressBar.setValue(done);
                    progressBar.setString(done + " / " + total);
                    statusLabel.setText("已完成 " + done + " / " + total);
                });
            }

            @Override
            public void onFinished() {
                SwingUtilities.invokeLater(() -> {
                    startBtn.setEnabled(true);
                    stopBtn.setEnabled(false);
                    statusLabel.setText("分析完成，共 " + listModel.getRowCount() + " 条");
                });
            }
        });
    }

    private void stopAnalysis() {
        if (service != null) service.stop();
        startBtn.setEnabled(true);
        stopBtn.setEnabled(false);
        statusLabel.setText("已停止");
    }

    private void showDetail() {
        int viewRow = listTable.getSelectedRow();
        if (viewRow < 0) { detailArea.setText(""); return; }
        int modelRow = listTable.convertRowIndexToModel(viewRow);
        detailArea.setText(listModel.getAiResult(modelRow));
        detailArea.setCaretPosition(0);
    }

    // =========================================================================
    // 配置持久化（借用 Setting / callbacks）
    // =========================================================================

    private void loadSettings() {
        urlField.setText(Setting.getValueAsString(Setting.Item.AI_BASE_URL));
        keyField.setText(Setting.getValueAsString(Setting.Item.AI_API_KEY));
        modelField.setText(Setting.getValueAsString(Setting.Item.AI_MODEL));
        String savedPrompt = Setting.getValueAsString(Setting.Item.AI_SYSTEM_PROMPT);
        // 旧版缓存 prompt 包含编号列表格式，自动重置为新版
        boolean isStalePrompt = savedPrompt.contains("1. 该接口是否存在越权风险");
        promptArea.setText((savedPrompt.isEmpty() || isStalePrompt) ? AIAnalysisService.getDefaultSystemPrompt() : savedPrompt);
    }

    private void saveSettings() {
        Setting.setValue(Setting.Item.AI_BASE_URL,      urlField.getText().trim());
        Setting.setValue(Setting.Item.AI_API_KEY,       keyField.getText().trim());
        Setting.setValue(Setting.Item.AI_MODEL,         modelField.getText().trim());
        Setting.setValue(Setting.Item.AI_SYSTEM_PROMPT, promptArea.getText().trim());
    }

    @Override public void onTabVisible()  {}
    @Override public void onTabHidden()   {}

    // =========================================================================
    // 内部 TableModel
    // =========================================================================

    private static class ResultListModel extends AbstractTableModel {
        private static final long serialVersionUID = 1L;
        private static final String[] COLUMNS = {"#", "Method", "URL", "状态", "AI 分析摘要"};
        private final List<OriginalRequestResponse> orrs = new ArrayList<>();
        private final List<String> results = new ArrayList<>();

        void addRow(OriginalRequestResponse orr, String aiResult) {
            orrs.add(orr);
            // 摘要：取第一行非空内容
            String summary = aiResult == null ? "" : aiResult.trim();
            int nl = summary.indexOf('\n');
            if (nl > 0) summary = summary.substring(0, nl).trim();
            results.add(summary);
            fireTableRowsInserted(orrs.size() - 1, orrs.size() - 1);
        }

        String getAiResult(int row) {
            return row >= 0 && row < results.size() ? results.get(row) : "";
        }

        void clear() {
            orrs.clear();
            results.clear();
            fireTableDataChanged();
        }

        @Override public int getRowCount()    { return orrs.size(); }
        @Override public int getColumnCount() { return COLUMNS.length; }
        @Override public String getColumnName(int col) { return COLUMNS[col]; }

        @Override
        public Object getValueAt(int row, int col) {
            if (row >= orrs.size()) return null;
            OriginalRequestResponse orr = orrs.get(row);
            switch (col) {
                case 0: return orr.getId();
                case 1: return orr.getMethod();
                case 2: return orr.getUrl();
                case 3: return orr.getStatusCode();
                case 4: return results.get(row);
                default: return null;
            }
        }

        @Override
        public Class<?> getColumnClass(int col) {
            return col == 0 || col == 3 ? Integer.class : String.class;
        }
    }
}
