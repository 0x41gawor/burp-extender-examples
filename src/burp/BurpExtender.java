package burp;

// Copied from: https://github.com/PortSwigger/example-event-listeners/blob/master/java/BurpExtender.java

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender,
        // This class implements several interface so it can use methods used to listen to specific events
        IHttpListener, IProxyListener, IScannerListener, IExtensionStateListener
{
    // We want to have reference for `callbacks` send to us as `registerExtenderCallbacks` param
    private IBurpExtenderCallbacks callbacks;
    // Standard output for Burp Extensions
    private PrintWriter stdout;

    // How does Burp works?
    // From our point of view Burp just generates some events and can register callbacks for this events.
    // In our extension we have a method that can be used to register our class to receive callbacks
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        // This method is an entry point for our extension, and receive callbacks object
        // in order to acces this object in other BurpExtender methods we need a field in class
        this.callbacks = callbacks;

        // set our extension name
        callbacks.setExtensionName("Event listeners");

        // obtain our output stream
        stdout = new PrintWriter(callbacks.getStdout(), true);

        // register ourselves as an HTTP listener
        callbacks.registerHttpListener(this);

        // register ourselves as a Proxy listener
        callbacks.registerProxyListener(this);

        // register ourselves as a Scanner listener
        callbacks.registerScannerListener(this);

        // register ourselves as an extension state listener
        callbacks.registerExtensionStateListener(this);
    }

    //
    // implement IHttpListener
    //

    @Override // Method from IHttpListener
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
            // toolFlag - indicates which tool issued the request (Intruder, Proxy, Repeater etc.)
            //            flags are defined in `IBurpExtenderCallbacks` interface
            // messageIsRequest - boolean indicates if HTTP message is request or response in HTTP terms
            // messageInfo - `IHttpRequestResponse` object that represents HTTP message
    {
        stdout.println(
                (messageIsRequest ? "HTTP request to " : "HTTP response from ") +
                        messageInfo.getHttpService() +
                        " [" + callbacks.getToolName(toolFlag) + "]");
        // Note that we can get toolName from toolFlag using callbacks objects method
    }

    //
    // implement IProxyListener
    //

    @Override // Method from IProxyListener
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message)
            // messageIsRequest - boolean indicates if HTTP message is request or response in HTTP terms
            // message - `IInterceptedProxyMessage` object that represents Intercepted HTTP message
            //           `IInterceptedProxyMessage` interface add some info to `IHttpRequestResponse` interface
            //            u can use IInterceptedProxyMessage.getMessageInfo to get IHttpRequestResponse object
    {
        stdout.println(
                (messageIsRequest ? "Proxy request to " : "Proxy response from ") +
                        message.getMessageInfo().getHttpService());
    }

    //
    // implement IScannerListener
    //

    @Override // Method from IScannerListener
    public void newScanIssue(IScanIssue issue)
    {
        ///TODO Still dunno what Issues is this about
        stdout.println("New scan issue: " + issue.getIssueName());
    }

    //
    // implement IExtensionStateListener
    //

    @Override // Method from IExtensionStateListener
    public void extensionUnloaded()
    {
        // IExtensionStateListener has only one method and it is fired when user unloads the extension
        // Here u do some cleaning up after your extensions
        // Abort threads, clear memory used for resources, close open files etc.
        stdout.println("Extension was unloaded");
    }
}