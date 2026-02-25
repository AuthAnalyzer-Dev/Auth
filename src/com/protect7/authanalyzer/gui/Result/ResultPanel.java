package com.protect7.authanalyzer.gui.Result;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.util.BypassCellRenderer;
import com.protect7.authanalyzer.gui.util.TabVisibilityAware;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;

/**
 * Result 页面：从 Analyzer/UI Testing 共享的表格中过滤出可能存在越权的 API（SAME/SIMILAR），
 * 与 Analyzer、UI Testing 并列展示。
 */
public class ResultPanel extends JPanel implements TabVisibilityAware {

    private static final long serialVersionUID = 1L;
    private static final int SYNC_INTERVAL_MS = 3000;
    private static final int SYNC_INTERVAL_WHEN_LARGE_MS = 8000;
    private static final int LARGE_ROW_THRESHOLD = 500;
    private static final int DEBOUNCE_MS = 400;
    /** 切换标签后延迟刷新，让标签先完成绘制，避免卡顿 */
    private static final int TAB_VISIBLE_DEFER_MS = 200;

    private final ResultTableModel resultModel = new ResultTableModel();
    private final JTable table = new JTable();
    private final ResultDetailPanel detailPanel = new ResultDetailPanel();
    private final JButton refreshButton = new JButton("刷新");
    private final JComboBox<String> sessionChooser = new JComboBox<>();
    private Timer syncTimer;
    private Timer debounceTimer;
    private Timer deferRefreshTimer;
    private final AtomicBoolean tabVisible = new AtomicBoolean(false);

    public ResultPanel() {
        setLayout(new BorderLayout());

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        topPanel.add(refreshButton);
        topPanel.add(new JLabel("Session:"));
        topPanel.add(sessionChooser);
        add(topPanel, BorderLayout.NORTH);

        table.setModel(resultModel);
        table.setAutoCreateRowSorter(true);
        table.setFillsViewportHeight(true);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setDefaultRenderer(Integer.class, new BypassCellRenderer());
        table.setDefaultRenderer(String.class, new BypassCellRenderer());
        table.setDefaultRenderer(BypassConstants.class, new BypassCellRenderer());

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                new JScrollPane(table), detailPanel);
        splitPane.setResizeWeight(0.55);
        add(splitPane, BorderLayout.CENTER);

        refreshButton.addActionListener(e -> doRefresh());
        sessionChooser.addActionListener(e -> refreshSelectedRowDetails());

        table.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) refreshSelectedRowDetails();
            }
        });

        startSyncWithMainModel();
    }

    private void doRefresh() {
        scheduleRefresh(false);
    }

    /** 在后台线程执行 refresh，避免阻塞 EDT */
    private void scheduleRefresh(boolean debounced) {
        if (debounced && debounceTimer != null && debounceTimer.isRunning()) {
            debounceTimer.restart();
            return;
        }
        com.protect7.authanalyzer.gui.util.RequestTableModel mainModel =
                CurrentConfig.getCurrentConfig().getTableModel();
        if (mainModel == null) return;
        new Thread(() -> {
            resultModel.refresh();
            SwingUtilities.invokeLater(() -> {
                resultModel.notifyDataChanged();
                refreshSessions();
                refreshSelectedRowDetails();
            });
        }, "ResultPanel-refresh").start();
    }

    private void refreshSessions() {
        sessionChooser.removeAllItems();
        List<Session> sessions = CurrentConfig.getCurrentConfig().getSessions();
        if (sessions == null || sessions.isEmpty()) {
            sessionChooser.addItem("(no sessions)");
            sessionChooser.setEnabled(false);
            return;
        }
        for (Session s : sessions) sessionChooser.addItem(s.getName());
        sessionChooser.setEnabled(true);
    }

    private void refreshSelectedRowDetails() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            detailPanel.showEmpty();
            return;
        }
        int modelRow = table.getRowSorter() != null ? table.convertRowIndexToModel(viewRow) : viewRow;
        OriginalRequestResponse orr = resultModel.getOriginalRequestResponse(modelRow);
        detailPanel.showOriginal(orr);

        int idx = sessionChooser.getSelectedIndex();
        List<Session> sessions = CurrentConfig.getCurrentConfig().getSessions();
        AnalyzerRequestResponse arr = null;
        if (orr != null && sessions != null && idx >= 0 && idx < sessions.size()) {
            Session s = sessions.get(idx);
            if (s != null) arr = s.getRequestResponseMap().get(orr.getId());
        }
        detailPanel.showSession(arr);
    }

    /** 监听主表变化，定期刷新 Result 过滤结果。仅当标签可见时运行。 */
    private void startSyncWithMainModel() {
        syncTimer = new Timer(SYNC_INTERVAL_MS, ev -> {
            if (!tabVisible.get()) return;
            com.protect7.authanalyzer.gui.util.RequestTableModel mainModel =
                    CurrentConfig.getCurrentConfig().getTableModel();
            if (mainModel != null) {
                int rowCount = mainModel.getRowCount();
                int delay = rowCount > LARGE_ROW_THRESHOLD ? SYNC_INTERVAL_WHEN_LARGE_MS : SYNC_INTERVAL_MS;
                if (syncTimer.getDelay() != delay) syncTimer.setDelay(delay);
                scheduleRefresh(false);
            }
        });
        syncTimer.setRepeats(true);
        syncTimer.setInitialDelay(SYNC_INTERVAL_MS);  // 首次 fire 与切换时的手动刷新错开

        debounceTimer = new Timer(DEBOUNCE_MS, ev -> {
            debounceTimer.stop();
            scheduleRefresh(false);
        });
        debounceTimer.setRepeats(false);

        // 主表模型可能尚未就绪，延迟绑定监听器
        Timer bindTimer = new Timer(500, e -> {
            com.protect7.authanalyzer.gui.util.RequestTableModel mainModel =
                    CurrentConfig.getCurrentConfig().getTableModel();
            if (mainModel != null) {
                mainModel.addTableModelListener(new TableModelListener() {
                    @Override
                    public void tableChanged(TableModelEvent ev) {
                        if (ev.getType() == TableModelEvent.INSERT || ev.getType() == TableModelEvent.UPDATE) {
                            if (!tabVisible.get()) return;
                            debounceTimer.stop();
                            debounceTimer.start();
                        }
                    }
                });
                scheduleRefresh(false);
                ((Timer) e.getSource()).stop();
            }
        });
        bindTimer.setRepeats(true);
        bindTimer.start();
    }

    @Override
    public void onTabVisible() {
        tabVisible.set(true);
        if (syncTimer != null) syncTimer.start();
        if (deferRefreshTimer != null) deferRefreshTimer.stop();
        deferRefreshTimer = new Timer(TAB_VISIBLE_DEFER_MS, ev -> {
            deferRefreshTimer.stop();
            scheduleRefresh(false);
            revalidate();
            repaint();
        });
        deferRefreshTimer.setRepeats(false);
        deferRefreshTimer.start();
    }

    @Override
    public void onTabHidden() {
        tabVisible.set(false);
        if (syncTimer != null) syncTimer.stop();
        if (debounceTimer != null) debounceTimer.stop();
        if (deferRefreshTimer != null) deferRefreshTimer.stop();
    }
}
