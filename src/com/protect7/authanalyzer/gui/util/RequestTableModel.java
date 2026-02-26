package com.protect7.authanalyzer.gui.util;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;
import com.protect7.authanalyzer.util.SymmetricTrafficStore;

public class RequestTableModel extends AbstractTableModel {

	private static final long serialVersionUID = 1L;
	private final ArrayList<OriginalRequestResponse> originalRequestResponseList = new ArrayList<OriginalRequestResponse>();
	private final CurrentConfig config = CurrentConfig.getCurrentConfig();
	private final int STATIC_COLUMN_COUNT = 7;
	private final Map<Integer, Boolean> run2ByMapId = new HashMap<>();
	
	public ArrayList<OriginalRequestResponse> getOriginalRequestResponseList() {
		return originalRequestResponseList;
	}
	
	public synchronized void addNewRequestResponse(OriginalRequestResponse requestResponse) {
		addNewRequestResponse(requestResponse, config.isSymmetricCaptureEnabled() && config.isSymmetricRun2Mode());
	}

	public synchronized void addNewRequestResponse(OriginalRequestResponse requestResponse, boolean isRun2) {
		originalRequestResponseList.add(requestResponse);
		if (config.isSymmetricCaptureEnabled()) {
			run2ByMapId.put(requestResponse.getId(), isRun2);
		}
		final int index = originalRequestResponseList.size()-1;
		SwingUtilities.invokeLater(new Runnable() {
			
			@Override
			public void run() {
				fireTableRowsInserted(index, index);
			}
		});
	}
	
	public boolean isDuplicate(int id, String endpoint) {
		for(OriginalRequestResponse requestResponse : originalRequestResponseList) {
			if(requestResponse.getEndpoint().equals(endpoint) && requestResponse.getId() < id) {
				return true;
			}
		}
		return false;
	}
	
	public void deleteRequestResponse(OriginalRequestResponse requestResponse) {
		originalRequestResponseList.remove(requestResponse);
		run2ByMapId.remove(requestResponse.getId());
		SwingUtilities.invokeLater(new Runnable() {			
			@Override
			public void run() {
				fireTableDataChanged();
			}
		});
	}
	
	public void clearRequestMap() {
		originalRequestResponseList.clear();
		run2ByMapId.clear();
		fireTableDataChanged();
	}

	public boolean isRun2(int mapId) {
		Boolean b = run2ByMapId.get(mapId);
		return b != null && b;
	}

	public String getRunLabel(int mapId) {
		return isRun2(mapId) ? "Run2" : "Run1";
	}

	public int getRunColumnIndex() {
		if (!config.isSymmetricCaptureEnabled()) return -1;
		java.util.List<?> sessions = config.getSessions();
		int base = STATIC_COLUMN_COUNT + (sessions != null ? sessions.size() * 4 : 0);
		return base;
	}

	private String getMatchLabel(OriginalRequestResponse orr) {
		SymmetricTrafficStore store = config.getSymmetricTrafficStore();
		if (store == null) return "—";
		String ep = orr.getEndpoint();
		boolean hasA = store.hasResponseA(ep);
		boolean hasB = store.hasResponseB(ep);
		if (!hasA || !hasB) return "—";
		boolean thisIsRun2 = isRun2(orr.getId());
		for (OriginalRequestResponse other : originalRequestResponseList) {
			if (other.getId() == orr.getId()) continue;
			if (!other.getEndpoint().equals(ep)) continue;
			if (isRun2(other.getId()) != thisIsRun2) {
				return thisIsRun2 ? "↔ Run1#" + other.getId() : "↔ Run2#" + other.getId();
			}
		}
		return "✓匹配";
	}
	
	public OriginalRequestResponse getOriginalRequestResponse(int listIndex) {
		if(listIndex < originalRequestResponseList.size()) {
			return originalRequestResponseList.get(listIndex);
		}
		else {
			return null;
		}
	}
	
	public OriginalRequestResponse getOriginalRequestResponseById(int id) {
		for(OriginalRequestResponse requestResponse : originalRequestResponseList) {
			if(requestResponse.getId() == id) {
				return requestResponse;
			}
		}
		return null;
	}
	
	@Override
	public int getColumnCount() {
		java.util.List<?> sessions = config.getSessions();
		int base = STATIC_COLUMN_COUNT + (sessions != null ? sessions.size() * 4 : 0);
		return base + (config.isSymmetricCaptureEnabled() ? 2 : 0);
	}

	@Override
	public int getRowCount() {
		return originalRequestResponseList.size();
	}

	@Override
	public Object getValueAt(int row, int column) {
		if(row >= originalRequestResponseList.size()) {
			return null;
		}
		OriginalRequestResponse originalRequestResponse = originalRequestResponseList.get(row);
		int tempColunmIndex = 4;
		if(column == 0) {
			return originalRequestResponse.getId();
		}
		if(column == 1) {
			return  originalRequestResponse.getMethod();
		}
		if(column == 2) {
			return originalRequestResponse.getHost();
		}
		if(column == 3) {
			return originalRequestResponse.getUrl();
		}
		if(column == 4) {
			return originalRequestResponse.getStatusCode();
		}
		java.util.List<com.protect7.authanalyzer.entities.Session> sessions = config.getSessions();
		if (sessions == null) sessions = java.util.Collections.emptyList();
		for(int i=0; i<sessions.size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				com.protect7.authanalyzer.entities.AnalyzerRequestResponse arr = sessions.get(i).getRequestResponseMap().get(originalRequestResponse.getId());
				return arr != null ? arr.getStatusCode() : null;
			}
		}
		for(int i=0; i<sessions.size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				com.protect7.authanalyzer.entities.AnalyzerRequestResponse arr = sessions.get(i).getRequestResponseMap().get(originalRequestResponse.getId());
				return arr != null ? arr.getStatus() : BypassConstants.NA;
			}
		}
		tempColunmIndex++;
		if(column == tempColunmIndex) {
			return originalRequestResponse.getResponseContentLength();
		}
		for(int i=0; i<sessions.size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				com.protect7.authanalyzer.entities.AnalyzerRequestResponse arr = sessions.get(i).getRequestResponseMap().get(originalRequestResponse.getId());
				return arr != null ? arr.getResponseContentLength() : null;
			}
		}
		for(int i=0; i<sessions.size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				com.protect7.authanalyzer.entities.AnalyzerRequestResponse arr = sessions.get(i).getRequestResponseMap().get(originalRequestResponse.getId());
				return arr != null ? (originalRequestResponse.getResponseContentLength() - arr.getResponseContentLength()) : null;
			}
		}
		tempColunmIndex++;
		if(column == tempColunmIndex) {
			return originalRequestResponse.getComment();
		}
		if (config.isSymmetricCaptureEnabled()) {
			tempColunmIndex++;
			if (column == tempColunmIndex) return getRunLabel(originalRequestResponse.getId());
			tempColunmIndex++;
			if (column == tempColunmIndex) return getMatchLabel(originalRequestResponse);
		}
		throw new IndexOutOfBoundsException("Column index out of bounds: " + column);
	}

	@Override
	public String getColumnName(int column) {
		int tempColunmIndex = 4;
		if(column == 0) {
			return Column.ID.toString();
		}
		if(column == 1) {
			return  Column.Method.toString();
		}
		if(column == 2) {
			return Column.Host.toString();
		}
		if(column == 3) {
			return Column.Path.toString();
		}
		if(column == 4) {
			return Column.Code.toString();
		}
		java.util.List<com.protect7.authanalyzer.entities.Session> sessionsForCol = config.getSessions();
		if (sessionsForCol == null) sessionsForCol = java.util.Collections.emptyList();
		for(int i=0; i<sessionsForCol.size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				return sessionsForCol.get(i).getName() + " " + Column.Code;
			}
		}
		for(int i=0; i<sessionsForCol.size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				return sessionsForCol.get(i).getName() + " " + Column.Status;
			}
		}
		tempColunmIndex++;
		if(column == tempColunmIndex) {
			return Column.Length.toString();
		}
		for(int i=0; i<sessionsForCol.size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				return sessionsForCol.get(i).getName() + " " + Column.Length;
			}
		}
		for(int i=0; i<sessionsForCol.size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				return sessionsForCol.get(i).getName() + " " + Column.Diff;
			}
		}
		tempColunmIndex++;
		if(column == tempColunmIndex) {
			return Column.Comment.toString();
		}
		if (config.isSymmetricCaptureEnabled()) {
			tempColunmIndex++;
			if (column == tempColunmIndex) return "Run";
			tempColunmIndex++;
			if (column == tempColunmIndex) return "匹配";
		}
		throw new IndexOutOfBoundsException("Column index out of bounds: " + column);
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		int tempColunmIndex = 4;
		if(columnIndex == 0) {
			return Integer.class;
		}
		if(columnIndex == 1) {
			return String.class;
		}
		if(columnIndex == 2) {
			return String.class;
		}
		if(columnIndex == 3) {
			return String.class;
		}
		if(columnIndex == 4) {
			return Integer.class;
		}
		int sessionCount = config.getSessions() != null ? config.getSessions().size() : 0;
		for(int i=0; i<sessionCount; i++) {
			tempColunmIndex++;
			if(columnIndex == tempColunmIndex) {
				return Integer.class;
			}
		}
		for(int i=0; i<sessionCount; i++) {
			tempColunmIndex++;
			if(columnIndex == tempColunmIndex) {
				return BypassConstants.class;
			}
		}
		tempColunmIndex++;
		if(columnIndex == tempColunmIndex) {
			return Integer.class;
		}
		for(int i=0; i<sessionCount; i++) {
			tempColunmIndex++;
			if(columnIndex == tempColunmIndex) {
				return Integer.class;
			}
		}
		for(int i=0; i<sessionCount; i++) {
			tempColunmIndex++;
			if(columnIndex == tempColunmIndex) {
				return Integer.class;
			}
		}
		tempColunmIndex++;
		if(columnIndex == tempColunmIndex) {
			return String.class;
		}
		if (config.isSymmetricCaptureEnabled()) {
			tempColunmIndex++;
			if (columnIndex == tempColunmIndex) return String.class;
			tempColunmIndex++;
			if (columnIndex == tempColunmIndex) return String.class;
		}
		throw new IndexOutOfBoundsException("Column index out of bounds: " + columnIndex);
	}
	
	public enum Column {
		ID, Method, Host, Path, Code, Length, Diff, Status, Comment;
		
		public static EnumSet<Column> getDefaultSet() {
			return EnumSet.of(ID, Method, Host, Path, Status);
		}
		
	}
}
