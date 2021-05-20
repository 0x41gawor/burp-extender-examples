# Custom Logger

This extension provides something that has often been requested: a suite-wide HTTP logger within the main Burp UI.

This example shows how to create an UI Tab and fill it with content (in contrary to 5. example).



The extension uses the following techniques, which are made possible by the [extender API](https://portswigger.net/burp/extender/):

- It creates a custom **tab** within the main **Burp UI**, in which to display the message log.
- It creates two instances of Burp's own **HTTP message editor**, in which to display the selected request and response (as in the Proxy history).
- It provides an implementation of **IMessageEditorController**, which the message editors can query to obtain additional details about the displayed messages (to support context menu actions, etc.).
- It asks Burp to customize its own UI components, in line with Burp's UI style.
- It adds an HTTP listener, to receive details of requests and responses made by all Burp tools.
- It uses an extension helper method to analyze the URL in each request (`helpers.analyzeRequest(messageInfo).getUrl()`)



## Overall UI preview

Burp Suite with our extension tab open presents this way.

![](example_description_img/1.png)

### Tab UI

Burp Suite uses Swing library to build UI.

Our Tab main node is `SplitPane` with `VERTICAL_SPLIT` layout.

`SplitPane` has two components `JScrollPane` on top and `JTabbedPane` on the bottom.

#### JScrollPane

> SWING THEORY
>
> **JScrollPane**
>
> `JScrollPane.JScrollPane(Component view)` 
>
> `view` is scrollable swing component.

In our case we pass `logsTable` object, which is an instance of `Table` class defined by us.

`Table`  extends `JTable` class 

> SWING THEORY
>
> The **`JTable`** is used to display and edit regular two-dimensional tables of cells.
>
> `public void changeSelection(int row, int col, boolean toggle, boolean extend)` 
>
> Updates the selection models of the table, depending on the state of the two flags: toggle and extend:
>
> - `toggle`: *false*, `extend`: *false*. Clear the previous selection and ensure the new cell is selected.
> - `toggle`: *false*, `extend`: *true*. Extend the previous selection from the anchor to the specified cell, clearing all other selections.
> - `toggle`: *true*, `extend`: *false*. If the specified cell is selected, deselect it. If it is not selected, select it.
> - `toggle`: *true*, `extend`: *true*. Apply the selection state of the anchor to all cells between it and the specified cell.
>
> **Parameters:**
>
> `rowIndex` - affects the selection at `row
> `columnIndex` - affects the selection at `column
>
>
> `toggle` - see description above
>
> `extend` - if true, extend the current selection

**In short**

We use `JScrollPane` and put there a `Table` object which extends `JTable` class, becasue we need to implement `public void changeSelection` method in our way.

#### JTabbedPane

The core of this pane is object provided by Burp Suite which is `IMessageEditor`. We can see it in Burp Suite official tabs.

They look like these two guys below.

<img src="example_description_img/2.png" style="zoom:75%;" />

In our case we display them as tabs. Which mean you can switch tabs and show only one at a time.

One `IMessageEditor` for *request* and one for *response*.

U can see their field declarations here

```java
private IMessageEditor requestViewer;
private IMessageEditor responseViewer;
```

That's how we ask Burp to initialize there variables with such objects:

```java
requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
```

We want them to be in `JTabbedPane` so we call:

```java
 JTabbedPane tabs = new JTabbedPane();
 tabs.addTab("Request", requestViewer.getComponent());
 tabs.addTab("Response", responseViewer.getComponent());
```

## Implemented Interfaces

Our `BurpExtender` class need to implement some interaces

### IBurpExtender

It's obvious. See previous examples.

### ITab

We need it to create a tab

```java
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
```

### (extend) AbstractTableModel

> This abstract class provides default implementations for most of the methods in the `TableModel` interface. It takes care of the management of listeners and provides some conveniences for generating `TableModelEvents` and dispatching them to the listeners

We extend these methods:

- `getRowCount` and return here size of our logs list
- `getColumnCount` we have two columns "Tool" and "URL", so we return 2.
- `getColumnName` we distinguish column by Id and return  "Tool" or"URL"
- `getColumnClass` Returns `Object.class` regardless of `columnIndex`. Because all columns should be the same class so you can know it blindly.
- `getValueAt(int rowIndex, int columnIndex)` we return specific element to be displayed in UI.

### IMessageEditorController

>This interface is used by an `IMessageEditor` to obtain details about the currently displayed message. Extensions that create instances of Burp's HTTP message editor can optionally provide an implementation of `IMessageEditorController`, which the editor will invoke when it requires further information about the current message (for example, to send it to another Burp tool). Extensions that provide custom editor tabs via an `IMessageEditorTabFactory` will receive a reference to an `IMessageEditorController` object for each tab instance they generate, which the tab can invoke if it requires further information about the current message.

We implement these methods:

- `getHttpService` and return current item *HTTP Service*
- `getRequest` and return current item *Request* (because our table items are HTTP messages)
- `getResponse`  and return current item *Request (because our table items are HTTP messages)*

### IHttpListener

See 3. Event Listeners example.

We need to fill our table with content.

In `processHttpMessage` we create `LogEntry` (class defined by us) and add it to the list. Then fire `Swing.AbstractTableModel.fireTableRowsInserted(int, int)` to notify Swing UI that table content has changed.

## Extension flow

Some Request is detected by `IHttpListener` and its message is processed in `processHttpMessage` method.

Then it is added to `logs` list and table is updated.

Also u can select specific log entry and display its `IHttpRequestResponsePersisted` in `IMessageEditorController`.

***

Note that in `registerExtenderCallbacks` we start a thread for UI with 

```java
SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
            ...
            // add the custom tab to Burp's UI (so this line ACTUALLY CREATES THE TAB)
            callbacks.addSuiteTab(BurpExtender.this);
            ...
            }
```

## Log Entry 

We defined our class to store logs.

It is called `LogEntry`.

