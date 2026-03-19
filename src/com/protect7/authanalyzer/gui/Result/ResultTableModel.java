package com.protect7.authanalyzer.gui.Result;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.swing.table.AbstractTableModel;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.util.RequestTableModel.Column;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.BypassStatus;
import com.protect7.authanalyzer.util.CurrentConfig;
import com.protect7.authanalyzer.util.SymmetricTrafficStore;

/**
 * 过滤并展示可能存在越权的 API 条目（任意 Session 为 SAME 或 SIMILAR）。
 * 数据来源：CurrentConfig 的 RequestTableModel（与 Analyzer/UI Testing 共享）。
 */
public class ResultTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;
    private final CurrentConfig config = CurrentConfig.getCurrentConfig();
    private final List<OriginalRequestResponse> filteredList = new ArrayList<>();
    private final int STATIC_COLUMN_COUNT = 7;
    /** 对称采集模式下，是否排除 Trivial 条目 */
    private boolean excludeTrivial = true;

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

        Set<String> seenEndpoints = new HashSet<>();
        for (OriginalRequestResponse orr : mainModel.getOriginalRequestResponseList()) {
            if (!hasSuspiciousStatus(orr.getId(), sessions)) continue;
            String ep = orr.getEndpoint();
            if (seenEndpoints.contains(ep)) continue;
            if (config.isSymmetricCaptureEnabled() && config.getSymmetricTrafficStore() != null) {
                SymmetricTrafficStore store = config.getSymmetricTrafficStore();
                if (store.hasResponseA(ep) && store.hasResponseB(ep)) {
                    BypassStatus status = config.getTrivialityChecker().getStatus(ep);
                    if (excludeTrivial && status == BypassStatus.TRIVIAL) continue;
                }
            }
            seenEndpoints.add(ep);
            filteredList.add(orr);
        }
    }

    public void setExcludeTrivial(boolean exclude) {
        this.excludeTrivial = exclude;
    }

    public boolean isExcludeTrivial() {
        return excludeTrivial;
    }

    /** 在 EDT 上调用，通知表格数据已更新 */
    public void notifyDataChanged() {
        fireTableDataChanged();
    }

    /** 在 EDT 上调用，通知表格列结构已变化（如对称采集开关导致 Bypass 列显隐） */
    public void notifyStructureChanged() {
        fireTableStructureChanged();
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
        java.util.List<Session> sessions = config.getSessions();
        int base = STATIC_COLUMN_COUNT + (sessions != null ? sessions.size() * 4 : 0);
        return base + (config.isSymmetricCaptureEnabled() ? 1 : 0);
    }

    @Override
    public int getRowCount() {
        return filteredList.size();
    }

    @Override
    public Object getValueAt(int row, int column) {
        if (row >= filteredList.size()) return null;
        OriginalRequestResponse orr = filteredList.get(row);
        List<Session> sessions = config.getSessions();
        if (sessions == null) sessions = Collections.emptyList();
        int tempColIndex = 4;
        if (column == 0) return orr.getId();
        if (column == 1) return orr.getMethod();
        if (column == 2) return orr.getHost();
        if (column == 3) return orr.getUrl();
        if (column == 4) return orr.getStatusCode();
        for (Session s : sessions) {
            tempColIndex++;
            AnalyzerRequestResponse arr = s.getRequestResponseMap().get(orr.getId());
            if (column == tempColIndex) return arr != null ? arr.getStatusCode() : null;
        }
        for (Session s : sessions) {
            tempColIndex++;
            AnalyzerRequestResponse arr = s.getRequestResponseMap().get(orr.getId());
            if (column == tempColIndex) return arr != null ? arr.getStatus() : null;
        }
        tempColIndex++;
        if (column == tempColIndex) return orr.getResponseContentLength();
        for (Session s : sessions) {
            tempColIndex++;
            AnalyzerRequestResponse arr = s.getRequestResponseMap().get(orr.getId());
            if (column == tempColIndex) return arr != null ? arr.getResponseContentLength() : null;
        }
        for (Session s : sessions) {
            tempColIndex++;
            AnalyzerRequestResponse arr = s.getRequestResponseMap().get(orr.getId());
            if (column == tempColIndex) return (arr != null) ? (orr.getResponseContentLength() - arr.getResponseContentLength()) : null;
        }
        tempColIndex++;
        if (column == tempColIndex) return orr.getComment();
        tempColIndex++;
        if (column == tempColIndex && config.isSymmetricCaptureEnabled()) {
            SymmetricTrafficStore store = config.getSymmetricTrafficStore();
            if (store == null) return null;
            boolean hasA = store.hasResponseA(orr.getEndpoint());
            boolean hasB = store.hasResponseB(orr.getEndpoint());
            if (hasA && hasB) return config.getTrivialityChecker().getStatus(orr.getEndpoint());
            if (hasA && !hasB) return BypassStatus.RUN1_ONLY;
            if (!hasA && hasB) return BypassStatus.RUN2_ONLY;
            return null;
        }
        return null;
    }

    @Override
    public String getColumnName(int column) {
        List<Session> sessions = config.getSessions();
        if (sessions == null) sessions = Collections.emptyList();
        int tempColIndex = 4;
        if (column == 0) return Column.ID.toString();
        if (column == 1) return Column.Method.toString();
        if (column == 2) return Column.Host.toString();
        if (column == 3) return Column.Path.toString();
        if (column == 4) return Column.Code.toString();
        for (Session s : sessions) {
            tempColIndex++;
            if (column == tempColIndex) return s.getName() + " " + Column.Code;
        }
        for (Session s : sessions) {
            tempColIndex++;
            if (column == tempColIndex) return s.getName() + " " + Column.Status;
        }
        tempColIndex++;
        if (column == tempColIndex) return Column.Length.toString();
        for (Session s : sessions) {
            tempColIndex++;
            if (column == tempColIndex) return s.getName() + " " + Column.Length;
        }
        for (Session s : sessions) {
            tempColIndex++;
            if (column == tempColIndex) return s.getName() + " " + Column.Diff;
        }
        tempColIndex++;
        if (column == tempColIndex) return Column.Comment.toString();
        tempColIndex++;
        if (column == tempColIndex && config.isSymmetricCaptureEnabled()) return "Bypass";
        return "";
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        List<Session> sessions = config.getSessions();
        if (sessions == null) sessions = Collections.emptyList();
        int tempColIndex = 4;
        if (columnIndex == 0) return Integer.class;
        if (columnIndex == 1) return String.class;
        if (columnIndex == 2) return String.class;
        if (columnIndex == 3) return String.class;
        if (columnIndex == 4) return Integer.class;
        for (int i = 0; i < sessions.size(); i++) {
            tempColIndex++;
            if (columnIndex == tempColIndex) return Integer.class;
        }
        for (int i = 0; i < sessions.size(); i++) {
            tempColIndex++;
            if (columnIndex == tempColIndex) return BypassConstants.class;
        }
        tempColIndex++;
        if (columnIndex == tempColIndex) return Integer.class;
        for (int i = 0; i < sessions.size(); i++) {
            tempColIndex++;
            if (columnIndex == tempColIndex) return Integer.class;
        }
        for (int i = 0; i < sessions.size(); i++) {
            tempColIndex++;
            if (columnIndex == tempColIndex) return Integer.class;
        }
        tempColIndex++;
        if (columnIndex == tempColIndex) return String.class;
        tempColIndex++;
        if (columnIndex == tempColIndex && config.isSymmetricCaptureEnabled()) return BypassStatus.class;
        return Object.class;
    }
}
