package com.protect7.authanalyzer.gui.UITesting;

import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.gui.util.RequestTableModel;

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
        add(new JScrollPane(table,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED), BorderLayout.CENTER);
    }

    void bindModel(RequestTableModel m) {
        if (this.model == m) return;
        this.model = m;
        table.setModel(m);
        autoSelectLastRowIfNone();
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
