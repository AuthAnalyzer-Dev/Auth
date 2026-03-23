package com.protect7.authanalyzer.gui.UITesting;

import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.gui.util.BypassCellRenderer;
import com.protect7.authanalyzer.gui.util.RequestTableModel;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;

import javax.swing.*;
import javax.swing.event.ListSelectionListener;
import javax.swing.RowFilter;
import javax.swing.table.TableRowSorter;
import java.awt.*;

class RequestTablePanel extends JPanel {

    private final JTable table = new JTable();
    private RequestTableModel model;
    private final JPanel runTogglePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
    private final ButtonGroup runToggleGroup = new ButtonGroup();
    private final JRadioButton run1Btn = new JRadioButton("Run1", true);
    private final JRadioButton run2Btn = new JRadioButton("Run2", false);
    private final JRadioButton runAllBtn = new JRadioButton("全部", false);

    RequestTablePanel() {
        setLayout(new BorderLayout());
        runTogglePanel.add(new JLabel("结果:"));
        runToggleGroup.add(run1Btn);
        runToggleGroup.add(run2Btn);
        runToggleGroup.add(runAllBtn);
        runTogglePanel.add(run1Btn);
        runTogglePanel.add(run2Btn);
        runTogglePanel.add(runAllBtn);
        runTogglePanel.setVisible(false);
        run1Btn.addActionListener(e -> applyRunFilter("Run1"));
        run2Btn.addActionListener(e -> applyRunFilter("Run2"));
        runAllBtn.addActionListener(e -> applyRunFilter(null));

        table.setAutoCreateRowSorter(true);
        table.setFillsViewportHeight(true);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        BypassCellRenderer bypassRenderer = new BypassCellRenderer();
        table.setDefaultRenderer(Integer.class, bypassRenderer);
        table.setDefaultRenderer(String.class, bypassRenderer);
        table.setDefaultRenderer(BypassConstants.class, bypassRenderer);

        JPanel tableWrap = new JPanel(new BorderLayout());
        tableWrap.add(runTogglePanel, BorderLayout.NORTH);
        tableWrap.add(new JScrollPane(table,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED), BorderLayout.CENTER);
        add(tableWrap, BorderLayout.CENTER);
    }

    void setRunToggleVisible(boolean visible) {
        runTogglePanel.setVisible(visible);
    }

    void bindModel(RequestTableModel m) {
        if (this.model == m) return;
        this.model = m;
        table.setModel(m);
        runTogglePanel.setVisible(CurrentConfig.getCurrentConfig().isSymmetricCaptureEnabled());
        applyRunFilter(runAllBtn.isSelected() ? null : (run2Btn.isSelected() ? "Run2" : "Run1"));
        ensureStatusColumnsVisible();
        autoSelectLastRowIfNone();
    }

    private void applyRunFilter(String run) {
        if (model == null) return;
        int runCol = model.getRunColumnIndex();
        if (runCol < 0) {
            if (table.getRowSorter() != null) ((TableRowSorter<?>) table.getRowSorter()).setRowFilter(null);
            return;
        }
        TableRowSorter<?> sorter = (TableRowSorter<?>) table.getRowSorter();
        if (sorter == null) return;
        if (run == null) {
            sorter.setRowFilter(null);
            return;
        }
        sorter.setRowFilter(RowFilter.regexFilter("^" + run + "$", runCol));
    }

    /** 确保 Status/Diff 列可见：设置列宽并滚动到首个 Status 列 */
    void ensureStatusColumnsVisible() {
        if (model == null) return;
        int colCount = table.getColumnCount();
        int firstStatusCol = -1;
        for (int i = 0; i < colCount; i++) {
            Object hv = table.getColumnModel().getColumn(i).getHeaderValue();
            if (hv != null) {
                String header = hv.toString();
                if (header.contains("Status") || header.contains("Diff")) {
                    table.getColumnModel().getColumn(i).setMinWidth(70);
                    table.getColumnModel().getColumn(i).setPreferredWidth(70);
                    if (firstStatusCol < 0 && header.contains("Status")) firstStatusCol = i;
                }
            }
        }
        if (firstStatusCol >= 0 && table.getRowCount() > 0) {
            table.scrollRectToVisible(table.getCellRect(0, firstStatusCol, true));
        }
    }

    void addSelectionListener(ListSelectionListener l) {
        table.getSelectionModel().addListSelectionListener(l);
    }

    OriginalRequestResponse getSelectedORR() {
        if (model == null) return null;
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) return null;
        int modelRow = table.getRowSorter()!=null ? table.convertRowIndexToModel(viewRow) : viewRow;
        return model.getOriginalRequestResponse(modelRow);
    }

    void autoSelectLastRowIfNone() {
        if (model == null || model.getRowCount() == 0) return;
        if (table.getSelectedRow() < 0) {
            int lastModelRow = model.getRowCount() - 1;
            int viewRow = table.getRowSorter()!=null ? table.convertRowIndexToView(lastModelRow) : lastModelRow;
            if (viewRow >= 0 && viewRow < table.getRowCount()) {
                table.getSelectionModel().setSelectionInterval(viewRow, viewRow);
            }
        }
    }
}
