package com.protect7.authanalyzer.gui.util;

import java.awt.Color;
import java.awt.Component;

import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableModel;

import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.gui.Result.ResultTableModel;
import com.protect7.authanalyzer.util.BypassConstants;

public class BypassCellRenderer extends DefaultTableCellRenderer {

	private static final long serialVersionUID = 1L;
	

	@Override
	public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus,
			int row, int column) {
		Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
		if (value instanceof BypassConstants) {
			BypassConstants bypassConstant = (BypassConstants) value;
			setText(bypassConstant.toString());
			if (!bypassConstant.toString().equals(BypassConstants.NA.toString())) {
				if (bypassConstant == BypassConstants.SAME) {
					if (!isSelected) {
						c.setBackground(new Color(255, 51, 51, 80));
					}
				}
				if (bypassConstant == BypassConstants.SIMILAR) {
					if (!isSelected) {
						c.setBackground(new Color(255, 153, 0, 80));
					}
				}
				if (bypassConstant == BypassConstants.DIFFERENT) {
					if (!isSelected) {
						c.setBackground(new Color(0, 255, 51, 80));
					}
				}
			}
		}
		else {
			OriginalRequestResponse requestResponse = getOriginalRequestResponse(table, row);
			if (requestResponse != null && requestResponse.isMarked()) {
				if(!isSelected) {
					c.setBackground(new Color(255, 255, 0, 120));
				}
				else {
					c.setBackground(new Color(210, 210, 0, 120));
				}
			}
			else {
				if(!isSelected) {
					if(row % 2 == 0) {
						c.setBackground(table.getBackground());
					}
					else {
						c.setBackground(new Color(200, 200, 200, 80));
					}
				}
			}
		}
		return c;
	}

	private static OriginalRequestResponse getOriginalRequestResponse(JTable table, int viewRow) {
		TableModel model = table.getModel();
		int modelRow = table.getRowSorter() != null ? table.convertRowIndexToModel(viewRow) : viewRow;
		if (model instanceof RequestTableModel) {
			return ((RequestTableModel) model).getOriginalRequestResponse(modelRow);
		}
		if (model instanceof ResultTableModel) {
			return ((ResultTableModel) model).getOriginalRequestResponse(modelRow);
		}
		return null;
	}
}