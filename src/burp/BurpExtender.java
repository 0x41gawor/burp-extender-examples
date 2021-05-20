package burp;

import java.awt.Component;

public class BurpExtender implements IBurpExtender,
        //Extensions can implement this interface and then call IBurpExtenderCallbacks.registerMessageEditorTabFactory()
        // to register a factory for custom message editor tabs.
        // This allows extensions to provide custom rendering or editing of HTTP messages, within Burp's own HTTP editor.
        IMessageEditorTabFactory
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    //
    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;

        helpers = callbacks.getHelpers();

        callbacks.setExtensionName("Serialized input editor");

        // register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(this);
        // ourselves has a method that returns `IMessageEditorTab` which can be displayed as an option to choose among
        // "raw", "pretty", "render"
    }

    //
    // implement IMessageEditorTabFactory
    //

    @Override // from IMessageEditorTabFactory
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable)
    {
        // create a new instance of our custom editor tab
        return new Base64InputTab(controller, editable);
        // Below we need to define a class that implements `IMessageEditorTab`
    }

    //
    // class implementing IMessageEditorTab
    //

    class Base64InputTab implements IMessageEditorTab
    {
        private boolean editable;       // it indicates if user can edit content of the HTTP Message
        private ITextEditor txtInput;   // This interface is used to provide extensions with an instance of Burp's raw text editor,
                                        // for the extension to use in its own UI.
                                        // Extensions should call `IBurpExtenderCallbacks.createTextEditor()`
                                        // to obtain an instance of this interface.
        private byte[] currentMessage;  // Message displayed in `txtInput` in bytes

        // Class constructor
        public Base64InputTab(IMessageEditorController controller, boolean editable)
        {
            this.editable = editable;

            // create an instance of Burp's text editor, to display our deserialized data
            txtInput = callbacks.createTextEditor(); // ask burp for TextEditor object
            txtInput.setEditable(editable);
        }

        //
        // implement IMessageEditorTab
        //

        @Override //from IMessageEditorTab
        public String getTabCaption()
        {
            return "Serialized input";
        }

        @Override //from IMessageEditorTab
        // return component representing the MessageEditorTab in our case it is txtInput,
        // which derives from Swing.Component by implementation of Burp's ITextEditor interface
        public Component getUiComponent()
        {
            return txtInput.getComponent();
        }

        @Override //from IMessageEditorTab
        // Not every message match our desired encoding
        // Remember we define our MessageEditorTab to encode data encoded in some specific, unique format
        public boolean isEnabled(byte[] content, boolean isRequest)
        {
            // enable this tab for requests containing a data parameter
            //return isRequest && null != helpers.getRequestParameter(content, "data");
            return isRequest;
            // Here we just simply return true if HTTP message is request
        }

        @Override //from IMessageEditorTab
        public void setMessage(byte[] content, boolean isRequest)
        {
            if (content == null)
            {
                // clear our display
                txtInput.setText(null);
                txtInput.setEditable(false);
            }
            else
            {
                // retrieve the data parameter
                IParameter parameter = helpers.getRequestParameter(content, "Host");

                // deserialize the parameter value
                // from original: // txtInput.setText(helpers.base64Decode(helpers.urlDecode(parameter.getValue())));
                txtInput.setText(helpers.stringToBytes("Niby tam jakies serialized data"));
                txtInput.setEditable(editable);
            }

            // remember the displayed content
            currentMessage = content;
        }

        @Override //from IMessageEditorTab
        public byte[] getMessage()
        {
            // determine whether the user modified the deserialized data
            if (txtInput.isTextModified())
            {
                // reserialize the data
                byte[] text = txtInput.getText();
                String input = helpers.urlEncode(helpers.base64Encode(text));

                // update the request with the new parameter value
                return helpers.updateParameter(currentMessage, helpers.buildParameter("Host", input, IParameter.PARAM_BODY));
            }
            else return currentMessage;
        }

        @Override //from IMessageEditorTab
        public boolean isModified()
        {
            return txtInput.isTextModified();
        }

        @Override //from IMessageEditorTab
        public byte[] getSelectedData()
        {
            return txtInput.getSelectedText();
        }
    }
}