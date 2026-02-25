package com.protect7.authanalyzer.gui.UITesting;

import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.gui.util.BypassCellRenderer;
import com.protect7.authanalyzer.gui.util.RequestTableModel;
import com.protect7.authanalyzer.util.BypassConstants;

import javax.swing.*;
import javax.swing.event.ListSelectionListener;
import java.awt.*;

class RequestTablePanel extends JPanel {

    private final JTable table = new JTable();
    private RequestTableModel model;

    RequestTablePanel() {
        setLayout(new BorderLayout());
        table.setAutoCreateRowSorter(true);
        table.setFillsViewportHeight(true);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        BypassCellRenderer bypassRenderer = new BypassCellRenderer();
        table.setDefaultRenderer(Integer.class, bypassRenderer);
        table.setDefaultRenderer(String.class, bypassRenderer);
        table.setDefaultRenderer(BypassConstants.class, bypassRenderer);
        add(new JScrollPane(table,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED), BorderLayout.CENTER);
    }

    void bindModel(RequestTableModel m) {
        if (this.model == m) return;
        this.model = m;
        table.setModel(m);
        ensureStatusColumnsVisible();
        autoSelectLastRowIfNone();
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
