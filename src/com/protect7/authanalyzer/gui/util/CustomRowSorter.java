package com.protect7.authanalyzer.gui.util;

import java.util.Collections;
import java.util.Comparator;

import javax.swing.JCheckBox;
import javax.swing.RowFilter;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.table.TableRowSorter;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.main.CenterPanel;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;

public class CustomRowSorter extends TableRowSorter<RequestTableModel> {
	
	private String getRequestById(int id) {
		for (Session session : CurrentConfig.getCurrentConfig().getSessions()) {
			AnalyzerRequestResponse analyzerRequestResponse = session.getRequestResponseMap().get(id);
			if (analyzerRequestResponse != null && analyzerRequestResponse.getRequestResponse().getRequest() != null) {
				byte[] requestBytes = analyzerRequestResponse.getRequestResponse().getRequest();
				if (requestBytes != null) {
					return new String(requestBytes);
				}
			}
		}
		return "";
	}

	private String getResponseById(int id) {
		for (Session session : CurrentConfig.getCurrentConfig().getSessions()) {
			AnalyzerRequestResponse analyzerRequestResponse = session.getRequestResponseMap().get(id);
			if (analyzerRequestResponse != null && analyzerRequestResponse.getRequestResponse().getResponse() != null) {
				byte[] responseBytes = analyzerRequestResponse.getRequestResponse().getResponse();
				if (responseBytes != null) {
					return new String(responseBytes);
				}
			}
		}
		return "";
	}

	private int countStrInLine(String line,String s,int[] value){
		if (s == null || s.isEmpty() || line == null || 
			value == null || value.length != line.length()) {
			return 0;
		}
		int cnt=0;
		int index=line.indexOf(s);
		while(index!=-1){
			cnt+=value[index];
			index=line.indexOf(s,index+1);
		}
		return cnt;
	}

	private int[] checkValue(String line){
		int[] value=new int[line.length()];
		int[] v=new int[line.length()];
		int st=0,t=0;
		for(int i=0;i<line.length();i++){
			char c=line.charAt(i);
			if(c==' '||c=='&')	st=0;
			if(st==1)	v[t]*=((c>='0'&&c<='9')?1:0);
			if(st==0&&c=='=')
			{
				st=1;
				v[++t]=1;
			}
		}
		st=t=0;
		for(int i=0;i<line.length();i++){
			value[i]=st*v[t];
			if(st==1&&line.charAt(i)=='=')
			{
				st=0;
				value[i]++;
			}
			else if(line.charAt(i)=='?'||line.charAt(i)=='&')
			{
				st=1;
				t++;
			}
		}
		return value;
	}

	private int calculateValue(String request) {
		if (request == null || request.isEmpty()) {
			return 0;
		}
		
		String[] lines = request.split("\n");
		if (lines.length == 0) {
			return 0;
		}

		//有效参数会出现在请求报文的第一行和最后一行，故统计这两行
		String firstLine = lines[0].trim().toLowerCase();
		String lastLine = lines[lines.length - 1].trim().toLowerCase();
		String fl=firstLine+lastLine;

		//标记有效参数名及等号位置
		int[] value=checkValue(fl);

		int wordsCnt=0;
		wordsCnt+=countStrInLine(fl,"id",value);//统计"id"出现次数
		wordsCnt+=countStrInLine(fl,"user",value);//统计"user"出现次数
		wordsCnt-=countStrInLine(fl,"userid",value);//容斥原理
		
		int equalCnt=countStrInLine(fl, "=", value);//统计等号数量

		//等号数量也有意义，参数越多越有可能有漏洞，但相比之下"id"等敏感参数的出现更可疑，因此给wordsCnt加入一个权重系数5
		return equalCnt+wordsCnt*3;
	}
	
	private int judgeResponse(String response)
	{
		for(int i=0;i<response.length();i++)
		{
			if(response.charAt(i)=='{')	return Math.min(10,(response.length()-i)/50-10);
		}
		return -10;
	}
	
	public CustomRowSorter(CenterPanel centerPanel, RequestTableModel tableModel, JCheckBox showOnlyMarked, JCheckBox showDuplicates, JCheckBox showBypassed, 
			JCheckBox showPotentialBypassed, JCheckBox showNotBypassed, JCheckBox showNA, PlaceholderTextField filterText,
			JCheckBox searchInPath, JCheckBox searchInRequest, JCheckBox searchInResponse, JCheckBox negativeSearch) {
		super(tableModel);
		showOnlyMarked.addActionListener(e -> tableModel.fireTableDataChanged());
		showDuplicates.addActionListener(e -> tableModel.fireTableDataChanged());
		showBypassed.addActionListener(e -> tableModel.fireTableDataChanged());
		showPotentialBypassed.addActionListener(e -> tableModel.fireTableDataChanged());
		showNotBypassed.addActionListener(e -> tableModel.fireTableDataChanged());
		showNA.addActionListener(e -> tableModel.fireTableDataChanged());
		filterText.addActionListener(e -> tableModel.fireTableDataChanged());

        // 以行id为排序关键字，并自定义Comparator，计算行价值，降序排序
		setMaxSortKeys(1);
        setSortKeys(Collections.singletonList(new RowSorter.SortKey(0, SortOrder.DESCENDING)));
		setComparator(0, new Comparator<Object>() {
			@Override
			public int compare(Object o1, Object o2) {
				try {
					//获取行id
					int id1 = Integer.parseInt(o1.toString());
					int id2 = Integer.parseInt(o2.toString());

					//获取request报文
					String request1 = getRequestById(id1);
					String request2 = getRequestById(id2);
					String response1 = getResponseById(id1);
					String response2 = getResponseById(id2);

					//计算行价值
					int count1 = calculateValue(request1)+judgeResponse(response1);
					int count2 = calculateValue(request2)+judgeResponse(response2);

					return Integer.compare(count1, count2); 
				} catch (Exception e) {
					e.printStackTrace();
					return 0;
				}
			}
		});	
		
		RowFilter<Object, Object> filter = new RowFilter<Object, Object>() {
			
			public boolean include(Entry<?, ?> entry) {
				if(filterText.getText() != null && !filterText.getText().equals("")) {
					centerPanel.toggleSearchButtonText();
					boolean doShow = false;
					if(searchInPath.isSelected()) {
						boolean contained = entry.getStringValue(3).toString().contains(filterText.getText());
						if((contained && !negativeSearch.isSelected()) || (!contained && negativeSearch.isSelected())) {
							doShow = true;
						}
					}
					if(searchInRequest.isSelected() && !doShow) {	
						try {
							int id = Integer.parseInt(entry.getStringValue(0));
							for (Session session : CurrentConfig.getCurrentConfig().getSessions()) {
								AnalyzerRequestResponse analyzerRequestResponse = session.getRequestResponseMap().get(id);
								if(analyzerRequestResponse.getRequestResponse().getRequest() != null) {
									String response = new String(analyzerRequestResponse.getRequestResponse().getRequest());
									boolean contained = response.contains(filterText.getText());
									if((contained && !negativeSearch.isSelected()) || (!contained && negativeSearch.isSelected())) {
										doShow = true;
										break;
									}
								}
							}
						}
						catch (Exception e) {
							e.printStackTrace();
						}
					}
					if(searchInResponse.isSelected() && !doShow) {	
						try {
							int id = Integer.parseInt(entry.getStringValue(0));
							for (Session session : CurrentConfig.getCurrentConfig().getSessions()) {
								AnalyzerRequestResponse analyzerRequestResponse = session.getRequestResponseMap().get(id);
								if(analyzerRequestResponse.getRequestResponse().getResponse() != null) {
									String response = new String(analyzerRequestResponse.getRequestResponse().getResponse());
									boolean contained = response.contains(filterText.getText());
									if((contained && !negativeSearch.isSelected()) || (!contained && negativeSearch.isSelected())) {
										doShow = true;
										break;
									}
								}
							}
						}
						catch (Exception e) {
							e.printStackTrace();
						}
					}
					centerPanel.toggleSearchButtonText();
					if(!doShow && (searchInPath.isSelected() || searchInResponse.isSelected() || searchInRequest.isSelected())) {
						return false;
					}
				}
				if(showOnlyMarked.isSelected()) {
					OriginalRequestResponse requestResponse = tableModel.getOriginalRequestResponseById(Integer.parseInt(entry.getStringValue(0)));
					if(requestResponse != null && !requestResponse.isMarked()) {
						return false;
					}
				}
				if(!showDuplicates.isSelected()) {
					String endpoint = entry.getStringValue(1).toString() + entry.getStringValue(2).toString() 
							+ entry.getStringValue(3).toString();	
					if(tableModel.isDuplicate(Integer.parseInt(entry.getStringValue(0)), endpoint)) {
						return false;
					}
				}
				if(showBypassed.isSelected()) {
					for(int i = entry.getValueCount()-1; i>3; i--) {
						if(entry.getStringValue(i).equals(BypassConstants.SAME.toString())) {
							return true;
						}
					}
				}
				if(showPotentialBypassed.isSelected()) {
					for(int i = entry.getValueCount()-1; i>3; i--) {
						if(entry.getStringValue(i).equals(BypassConstants.SIMILAR.toString())) {
							return true;
						}
					}
				}
				if(showNotBypassed.isSelected()) {
					for(int i = entry.getValueCount()-1; i>3; i--) {
						if(entry.getStringValue(i).equals(BypassConstants.DIFFERENT.toString())) {
							return true;
						}
					}
				}
				if(showNA.isSelected()) {
					for(int i = entry.getValueCount()-1; i>3; i--) {
						if(entry.getStringValue(i).equals(BypassConstants.NA.toString())) {
							return true;
						}
					}
				}
				return false;
			}
		};
		
		setRowFilter(filter);
	}
}
