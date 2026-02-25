package com.protect7.authanalyzer.gui.Result;

import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.util.RequestTableModel.Column;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;

/**
 * 过滤并展示可能存在越权的 API 条目（任意 Session 为 SAME 或 SIMILAR）。
 * 数据来源：CurrentConfig 的 RequestTableModel（与 Analyzer/UI Testing 共享）。
 */
public class ResultTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;
    private final CurrentConfig config = CurrentConfig.getCurrentConfig();
    private final List<OriginalRequestResponse> filteredList = new ArrayList<>();
    private final int STATIC_COLUMN_COUNT = 7;

    /**
     * 从主表刷新过滤结果：仅保留任意 Session 为 SAME 或 SIMILAR 的条目。
     * 可在后台线程调用，但 fireTableDataChanged 会由调用方在 EDT 上触发。
     */
    public void refresh() {
        filteredList.clear();
        com.protect7.authanalyzer.gui.util.RequestTableModel mainModel = config.getTableModel();
        if (mainModel == null) return;

        List<Session> sessions = config.getSessions();
        if (sessions == null || sessions.isEmpty()) {
            return;
        }

        for (OriginalRequestResponse orr : mainModel.getOriginalRequestResponseList()) {
            if (hasSuspiciousStatus(orr.getId(), sessions)) {
                filteredList.add(orr);
            }
        }
    }

    /** 在 EDT 上调用，通知表格数据已更新 */
    public void notifyDataChanged() {
        fireTableDataChanged();
    }

    /** 任意 Session 对该请求的判定为 SAME 或 SIMILAR 则返回 true */
    private boolean hasSuspiciousStatus(int mapId, List<Session> sessions) {
        for (Session s : sessions) {
            AnalyzerRequestResponse arr = s.getRequestResponseMap().get(mapId);
            if (arr != null) {
                BypassConstants status = arr.getStatus();
                if (status == BypassConstants.SAME || status == BypassConstants.SIMILAR) {
                    return true;
                }
            }
        }
        return false;
    }

    public OriginalRequestResponse getOriginalRequestResponse(int listIndex) {
        if (listIndex >= 0 && listIndex < filteredList.size()) {
            return filteredList.get(listIndex);
        }
        return null;
    }

    public List<OriginalRequestResponse> getFilteredList() {
        return new ArrayList<>(filteredList);
    }

    @Override
    public int getColumnCount() {
        return STATIC_COLUMN_COUNT + (config.getSessions().size() * 4);
    }

    @Override
    public int getRowCount() {
        return filteredList.size();
    }

    @Override
    public Object getValueAt(int row, int column) {
        if (row >= filteredList.size()) return null;
        OriginalRequestResponse orr = filteredList.get(row);
        int tempColIndex = 4;
        if (column == 0) return orr.getId();
        if (column == 1) return orr.getMethod();
        if (column == 2) return orr.getHost();
        if (column == 3) return orr.getUrl();
        if (column == 4) return orr.getStatusCode();
        for (Session s : config.getSessions()) {
            tempColIndex++;
            AnalyzerRequestResponse arr = s.getRequestResponseMap().get(orr.getId());
            if (column == tempColIndex) {
                return arr != null ? arr.getStatusCode() : null;
            }
        }
        tempColIndex++;
        if (column == tempColIndex) return orr.getResponseContentLength();
        for (Session s : config.getSessions()) {
            tempColIndex++;
            AnalyzerRequestResponse arr = s.getRequestResponseMap().get(orr.getId());
            if (column == tempColIndex) {
                return arr != null ? arr.getResponseContentLength() : null;
            }
        }
        for (Session s : config.getSessions()) {
            tempColIndex++;
            AnalyzerRequestResponse arr = s.getRequestResponseMap().get(orr.getId());
            if (column == tempColIndex) {
                return (arr != null) ? (orr.getResponseContentLength() - arr.getResponseContentLength()) : null;
            }
        }
        for (Session s : config.getSessions()) {
            tempColIndex++;
            AnalyzerRequestResponse arr = s.getRequestResponseMap().get(orr.getId());
            if (column == tempColIndex) return arr != null ? arr.getStatus() : null;
        }
        tempColIndex++;
        if (column == tempColIndex) return orr.getComment();
        return null;
    }

    @Override
    public String getColumnName(int column) {
        int tempColIndex = 4;
        if (column == 0) return Column.ID.toString();
        if (column == 1) return Column.Method.toString();
        if (column == 2) return Column.Host.toString();
        if (column == 3) return Column.Path.toString();
        if (column == 4) return Column.Code.toString();
        for (Session s : config.getSessions()) {
            tempColIndex++;
            if (column == tempColIndex) return s.getName() + " " + Column.Code;
        }
        tempColIndex++;
        if (column == tempColIndex) return Column.Length.toString();
        for (Session s : config.getSessions()) {
            tempColIndex++;
            if (column == tempColIndex) return s.getName() + " " + Column.Length;
        }
        for (Session s : config.getSessions()) {
            tempColIndex++;
            if (column == tempColIndex) return s.getName() + " " + Column.Diff;
        }
        for (Session s : config.getSessions()) {
            tempColIndex++;
            if (column == tempColIndex) return s.getName() + " " + Column.Status;
        }
        tempColIndex++;
        if (column == tempColIndex) return Column.Comment.toString();
        return "";
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        int tempColIndex = 4;
        if (columnIndex == 0) return Integer.class;
        if (columnIndex == 1) return String.class;
        if (columnIndex == 2) return String.class;
        if (columnIndex == 3) return String.class;
        if (columnIndex == 4) return Integer.class;
        for (int i = 0; i < config.getSessions().size(); i++) {
            tempColIndex++;
            if (columnIndex == tempColIndex) return Integer.class;
        }
        tempColIndex++;
        if (columnIndex == tempColIndex) return Integer.class;
        for (int i = 0; i < config.getSessions().size(); i++) {
            tempColIndex++;
            if (columnIndex == tempColIndex) return Integer.class;
        }
        for (int i = 0; i < config.getSessions().size(); i++) {
            tempColIndex++;
            if (columnIndex == tempColIndex) return Integer.class;
        }
        for (int i = 0; i < config.getSessions().size(); i++) {
            tempColIndex++;
            if (columnIndex == tempColIndex) return BypassConstants.class;
        }
        tempColIndex++;
        if (columnIndex == tempColIndex) return String.class;
        return Object.class;
    }
}
