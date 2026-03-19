package burp;

import java.awt.Component;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import com.protect7.authanalyzer.controller.HttpListener;
import com.protect7.authanalyzer.gui.util.AuthAnalyzerMenu;
import com.protect7.authanalyzer.util.DataStorageProvider;
import com.protect7.authanalyzer.util.GenericHelper;
import com.protect7.authanalyzer.util.Globals;

import com.protect7.authanalyzer.gui.UITesting.MergedUITestingPanel;
import com.protect7.authanalyzer.gui.Result.ResultPanel;
import com.protect7.authanalyzer.gui.util.IAnalyzerHost;
import com.protect7.authanalyzer.gui.util.TabVisibilityAware;

public class BurpExtender implements IBurpExtender, ITab, IExtensionStateListener {

	public static IAnalyzerHost hostPanel;
	private JMenu authAnalyzerMenu = null;
	public static IBurpExtenderCallbacks callbacks;
	public static JTabbedPane burpTabbedPane = null;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		BurpExtender.callbacks = callbacks;
		callbacks.setExtensionName(Globals.EXTENSION_NAME);
		try {
			burpTabbedPane = new JTabbedPane();
			MergedUITestingPanel mergedPanel = new MergedUITestingPanel();
			hostPanel = mergedPanel;
			ResultPanel resultPanel = new ResultPanel();
			burpTabbedPane.addTab("UI Testing", mergedPanel);
			burpTabbedPane.addTab("Result", resultPanel);

			SwingUtilities.invokeLater(() -> {
				int idx = burpTabbedPane.getSelectedIndex();
				if (idx == 0) {
					((TabVisibilityAware) mergedPanel).onTabVisible();
					((TabVisibilityAware) resultPanel).onTabHidden();
				} else if (idx == 1) {
					((TabVisibilityAware) mergedPanel).onTabHidden();
					((TabVisibilityAware) resultPanel).onTabVisible();
				}
			});

			burpTabbedPane.addChangeListener(e -> {
				int idx = burpTabbedPane.getSelectedIndex();
				TabVisibilityAware ui = (TabVisibilityAware) mergedPanel;
				TabVisibilityAware res = (TabVisibilityAware) resultPanel;
				if (idx == 0) {
					ui.onTabVisible();
					res.onTabHidden();
				} else if (idx == 1) {
					ui.onTabHidden();
					res.onTabVisible();
				} else {
					ui.onTabHidden();
					res.onTabHidden();
				}
			});

			callbacks.addSuiteTab(this);
			addAuthAnalyzerMenu();
			HttpListener httpListener = new HttpListener();
			callbacks.registerHttpListener(httpListener);
			callbacks.registerProxyListener(httpListener);
			callbacks.registerExtensionStateListener(this);
			callbacks.printOutput(Globals.EXTENSION_NAME + " successfully started");
			callbacks.printOutput("Version " + Globals.VERSION);
			callbacks.printOutput("Created by zmlad");
		} catch (Exception e) {
			callbacks.printError("Auth Analyzer failed to load: " + e.getMessage());
			e.printStackTrace();
		}
	}

	@Override
	public String getTabCaption() {
		return Globals.EXTENSION_NAME;
	}

	@Override
	public Component getUiComponent() {
		return (burpTabbedPane != null) ? burpTabbedPane : (hostPanel != null ? (Component) hostPanel : new JPanel());
	}

	private void addAuthAnalyzerMenu() {
		SwingUtilities.invokeLater(new Runnable() {

			@Override
			public void run() {
				JFrame burpFrame = GenericHelper.getBurpFrame();
				if(burpFrame != null) {
					authAnalyzerMenu = new AuthAnalyzerMenu(Globals.EXTENSION_NAME);
					JMenuBar burpMenuBar = burpFrame.getJMenuBar();
					burpMenuBar.add(authAnalyzerMenu, burpMenuBar.getMenuCount() - 1);
				}
			}
		});

	}

	@Override
	public void extensionUnloaded() {
		if(authAnalyzerMenu != null && authAnalyzerMenu.getParent() != null) {
			authAnalyzerMenu.getParent().remove(authAnalyzerMenu);
		}
		if (hostPanel != null) {
			try {
				hostPanel.getConfigurationPanel().createSessionObjects(false);
				DataStorageProvider.saveSetup();
			} catch (Exception e) {
				callbacks.printOutput("INFO: Session Setup not stored due to invalid data.");
			}
		}
	}
}