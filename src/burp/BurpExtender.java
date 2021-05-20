package burp;

public class BurpExtender implements IBurpExtender, IHttpListener
{
    // Change it to hosts u want to redirect between
    private static final String HOST_FROM = "host1.example.org";
    private static final String HOST_TO = "host2.example.org";

    private IExtensionHelpers helpers;

    //
    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        /*
         helpers is an `IExtensionHelpers` object that will help you:
         - analyze HTTP Request or Response
         - Build HTTP service (in order to put it in HTTP message)
         - encode and decode HTTP messages
         - Build HTTP Request or Response (HTTP message in general)
         */

        // set our extension name
        callbacks.setExtensionName("Traffic redirector");

        // register ourselves as an HTTP listener
        callbacks.registerHttpListener(this);
    }

    //
    // implement IHttpListener
    //

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {
        // only process requests
        if (messageIsRequest)
        {
            // get the HTTP service for the request
            IHttpService httpService = messageInfo.getHttpService();

            // We want to check if request is from some Service, and if it is redirect it to other service

            // if the host is HOST_FROM, change it to HOST_TO
            if (HOST_FROM.equalsIgnoreCase(httpService.getHost())) // equalsIgnoreCase is String's method
            {
                // We've got HTTPmessage in method params and we are setting a new Service for it
                messageInfo.setHttpService(helpers.buildHttpService(HOST_TO, httpService.getPort(), httpService.getProtocol()));
            }
            ///TODO Do we send it further? IDK but 90% we don't in this code.
        }
    }
}