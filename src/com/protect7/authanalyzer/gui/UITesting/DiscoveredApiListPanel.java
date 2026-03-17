package com.protect7.authanalyzer.gui.UITesting;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.AbstractAction;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.table.AbstractTableModel;

import com.protect7.authanalyzer.uitesting.discovery.DiscoveredEndpoint;

/**
 * 发现的隐藏 API 列表展示面板。支持 Ctrl+C 复制选中行。
 */
public class DiscoveredApiListPanel extends JPanel {

    private static final long serialVersionUID = 1L;

    private final DiscoveredApiTableModel model = new DiscoveredApiTableModel();
    private final JTable table = new JTable(model);

    public DiscoveredApiListPanel() {
        setLayout(new java.awt.BorderLayout());
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.getTableHeader().setReorderingAllowed(false);
        table.setCellSelectionEnabled(true);
        table.getInputMap(JTable.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_C, Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()), "copy");
        table.getActionMap().put("copy", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                copySelectedToClipboard();
            }
        });
        add(new JScrollPane(table), java.awt.BorderLayout.CENTER);
    }

    private void copySelectedToClipboard() {
        int[] rows = table.getSelectedRows();
        if (rows == null || rows.length == 0) return;
        StringBuilder sb = new StringBuilder();
        for (int r : rows) {
            int modelRow = table.convertRowIndexToModel(r);
            DiscoveredEndpoint ep = model.getEndpointAt(modelRow);
            if (ep != null) {
                sb.append(ep.getMethod()).append("\t").append(ep.getPath()).append("\t").append(ep.getSource()).append("\n");
            }
        }
        if (sb.length() > 0) {
            StringSelection sel = new StringSelection(sb.toString().trim());
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(sel, null);
        }
    }

    public void setEndpoints(List<DiscoveredEndpoint> endpoints) {
        model.setEndpoints(endpoints != null ? endpoints : new ArrayList<>());
    }

    public void addEndpoints(List<DiscoveredEndpoint> endpoints) {
        if (endpoints != null && !endpoints.isEmpty()) {
            model.addEndpoints(endpoints);
        }
    }

    public void clear() {
        model.clear();
    }

    public List<DiscoveredEndpoint> getAllEndpoints() {
        return model.getAllEndpoints();
    }

    private static class DiscoveredApiTableModel extends AbstractTableModel {

        private static final long serialVersionUID = 1L;
        private static final String[] COLUMNS = { "方法", "路径", "来源" };

        private final List<DiscoveredEndpoint> endpoints = new ArrayList<>();

        void setEndpoints(List<DiscoveredEndpoint> list) {
            endpoints.clear();
            endpoints.addAll(list);
            fireTableDataChanged();
        }

        void addEndpoints(List<DiscoveredEndpoint> list) {
            for (DiscoveredEndpoint e : list) {
                if (!endpoints.contains(e)) endpoints.add(e);
            }
            fireTableDataChanged();
        }

        void clear() {
            endpoints.clear();
            fireTableDataChanged();
        }

        List<DiscoveredEndpoint> getAllEndpoints() {
            return new ArrayList<>(endpoints);
        }

        DiscoveredEndpoint getEndpointAt(int rowIndex) {
            if (rowIndex >= 0 && rowIndex < endpoints.size()) {
                return endpoints.get(rowIndex);
            }
            return null;
        }

        @Override
        public int getRowCount() {
            return endpoints.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMNS.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMNS[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            DiscoveredEndpoint e = endpoints.get(rowIndex);
            switch (columnIndex) {
                case 0: return e.getMethod();
                case 1: return e.getPath();
                case 2: return e.getSource().toString();
                default: return "";
            }
        }
    }
}
