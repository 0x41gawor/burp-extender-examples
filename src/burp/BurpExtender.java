package burp;


// In this extension we will create a tab in Burp Suite so we need some graphic library
// Burp Suite allows us to create tabs with Swing
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
// We use URL in LogEntry class (see line 37)
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender extends
        // Swing class that represents an abstract TableModel, it implements `Swing.TableModel` intrarface
        AbstractTableModel
        implements
        IBurpExtender,
        // To be able to create an UI Tab by Extension we need to implement ITab interface
        ITab,
        // This allows our request/response viewers to obtain details about the messages being displayed
        // use to control MessageEditor
        IMessageEditorController,
        // Finally we implement HTTP Listener, to have the content to be displayed in our Logger
        IHttpListener
    {
    // We need this field to keep a reference for callback object send to us via `registerExtenderCallbacks` param
    private IBurpExtenderCallbacks callbacks;

    // helpers object so we can use some useful IExtensionHelpers methods (`helpers.analyzeRequest(messageInfo).getUrl()`)
    private IExtensionHelpers helpers;

    // Main Swing Pane for UI Tab
    private JSplitPane splitPane;


    // Our extension is about CustomLogs, so we define our LogEntry class
    private static class LogEntry {
        final int tool; // Tool from where HTTP message came
        final IHttpRequestResponsePersisted requestResponse; // HTTP message
        final URL url; // HTTP message URL

        LogEntry(int tool, IHttpRequestResponsePersisted requestResponse, URL url) {
            this.tool = tool;
            this.requestResponse = requestResponse;
            this.url = url;
        }
    }

    // This is the list of our logs
    private final List<LogEntry> logs = new ArrayList<LogEntry>();

    // Burp has built in HTTP Message Editor.
    // This white filed, with "Raw", "HTML", "Render" etc tabs
    // You can use it in your extension.
    // And IMessageEditor is the tool to do so.
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;

    // Current item displayed in our Logger
    // It is an IHTttpRequestResponse object (this interface represents HTTP message)
    private IHttpRequestResponse currentlyDisplayedItem;


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();


        // set our extension name
        callbacks.setExtensionName("Custom logger");

        // Create our UI Tab
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                // Main Pane
                splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                // Table of log entries
                Table logsTable = new Table(BurpExtender.this);
                JScrollPane scrollPane = new JScrollPane(logsTable);


                // tabs with request/response viewers
                JTabbedPane tabs = new JTabbedPane();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());

                // Layout Table on the left, and MessageEditor on the right.
                // But its vertical_split so left is up, and right is actually down.
                splitPane.setLeftComponent(scrollPane);
                splitPane.setRightComponent(tabs);

                // customize our UI components
                callbacks.customizeUiComponent(splitPane);
                callbacks.customizeUiComponent(logsTable);
                callbacks.customizeUiComponent(scrollPane);
                callbacks.customizeUiComponent(tabs);

                // add the custom tab to Burp's UI (so this line ACTUALLY CREATES THE TAB)
                callbacks.addSuiteTab(BurpExtender.this);

                // register ourselves as an HTTP listener
                callbacks.registerHttpListener(BurpExtender.this);
            }
        });
    }

    //
    // implement ITab
    //

    @Override // Method from ITab
    public String getTabCaption() {
        return "Custom Logger";
    }

    @Override // Method from ITab
    // This way we tell Burp which our graphical component should represent UI Tab
    // Make this method to return the main swing component
    public Component getUiComponent() {
        return splitPane;
    }

    //
    // extend AbstractTableModel
    //

    @Override // from AbstractTableModel
    public int getRowCount() {
        // Table is list of logs in stored in `logs` list so..
        return logs.size();
    }

    @Override // from AbstractTableModel
    public int getColumnCount() {
        // We can hardcode 2, because "Tool" and "URL" from `LogEntry` will be displayed in the table.
        // LogEntry.requestResponse will be shown below in "MessageEditor"
        return 2;
    }

    @Override // from AbstractTableModel
    // We need to tell Burp about column names
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return "Tool";
            case 1:
                return "URL";
            default:
                return "";
        }
    }

    @Override // from AbstractTableModel
    public Class<?> getColumnClass(int columnIndex)
    {
        return String.class;
    }

    @Override // from AbstractTableModel
    public Object getValueAt(int rowIndex, int columnIndex) {
        LogEntry logEntry = logs.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return callbacks.getToolName(logEntry.tool);
            case 1:
                return logEntry.url.toString();
            default:
                return "";
        }
    }

    //
    // implement IMessageEditorController
    //

    @Override // from IMessageEditorController
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override // from IMessageEditorController
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override // from IMessageEditorController
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    //
    // extend JTable to handle cell selection
    //

    private class Table extends JTable {
        public Table(TableModel tableModel) {
            super(tableModel);
        }

        @Override //Method from JTable
        // Updates the selection models of the table, depending on the state of the two flags: toggle and extend.
        // https://docs.oracle.com/javase/7/docs/api/javax/swing/JTable.html#changeSelection(int, int, boolean, boolean)
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            // show the log entry for the selected row
            LogEntry logEntry = logs.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }

    //
    // implement IHttpListener
    //
    // Last step is to implement HTTP listener which will fill our `logs` list with content
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
    // only process responses
        if (!messageIsRequest)
        {
            // create a new log entry with the message details
            synchronized(logs)
            {
                int row = logs.size();
                // Our LogEntry class contructor as 2nd param take IHttpRequestResponsePersisted object
                // And this is the way `callbacks.saveBuffersToTempFiles(messageInfo)` we obtain it from IHttpRequestResponse object
                logs.add(new LogEntry(toolFlag, callbacks.saveBuffersToTempFiles(messageInfo), helpers.analyzeRequest(messageInfo).getUrl()));
                // Swing.Table method that notifies all listeners, that there were inserted a new rows in the given range
                fireTableRowsInserted(row, row);
            }
        }
    }
}