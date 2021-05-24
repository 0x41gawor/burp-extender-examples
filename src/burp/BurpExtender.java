package burp;


import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender,
        //Extensions can implement this interface and then call `IBurpExtenderCallbacks.registerScannerInsertionPointProvider()`
        // to register a factory for custom Scanner insertion points.
        // Insertion points are points where Scanner puts some payloads on HTTP request
        IScannerInsertionPointProvider {

    private IExtensionHelpers helpers;

    //
    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Serialized input scan insertion point");

        // register ourselves as a scanner insertion point provider
        callbacks.registerScannerInsertionPointProvider(this);
    }

    @Override //from IScannerInsertionPointProvider
    // Burp Suite just iterates through HTTP request he can send to a webpage and asks if extension has some
    // InsertionPoints for this HTTP request to test them out

    //This one has such list if HTTP request contain 'data' param.
    public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse) {
        // retrieve the data parameter
        IParameter dataParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "data");
        if (dataParameter == null)
            return null;

        List<IScannerInsertionPoint> insertionPoints = new ArrayList<IScannerInsertionPoint>();
        // To InsertionPoint constructor we send the whole HTTP request and its 'data' param value
        insertionPoints.add(new InsertionPoint(baseRequestResponse.getRequest(), dataParameter.getValue()));
        return insertionPoints;
    }

    //
    // class implementing IScannerInsertionPoint
    //
    private class InsertionPoint implements IScannerInsertionPoint
    {
        private byte[] baseRequest;             //entry request
                                                // we want to insert payload: e.g. "<script>alert(1)</script>"
        private String insertionPointPrefix;    // so this is the text before payload
        private String baseValue;               // this is the text where payload will be, just a param value
        private String insertionPointSuffix;    // text between `baseValue` and '&' ('&' is used to separate multiple values)

        InsertionPoint(byte[] baseRequest, String dataParameterValue) {

            this.baseRequest = baseRequest;
            // URL- and base64-decode the data
            dataParameterValue = helpers.bytesToString(helpers.base64Decode(helpers.urlDecode(dataParameterValue)));

            int start = dataParameterValue.indexOf("input=") + 6;
            insertionPointPrefix = dataParameterValue.substring(0, start);
            int end = dataParameterValue.indexOf("&", start);
            if (end == -1) end = dataParameterValue.length();// If "&" is not found

            baseValue = dataParameterValue.substring(start, end);
            insertionPointSuffix = dataParameterValue.substring(end, dataParameterValue.length());
            // In `example_description_img/3.png` variable values are:
            // insertionPointPrefix = "input="
            // baseValue = "4511dac60311e3ee"
            // insertionPointSuffix = "time1355742156502"
        }

        @Override// from IScannerInsertionPoint
        public String getInsertionPointName() {
            return "Base64-wrapped input";
        }

        @Override// from IScannerInsertionPoint
        public String getBaseValue() {
            return baseValue;
        }

        @Override // from IScannerInsertionPoint
        // Burp Suite has some buil-in payloads to test e.g. XSS vulnerability
        // And Burp will send here "<script>alert(1)</script>"
        public byte[] buildRequest(byte[] payload) {
            // build the raw data using the specified payload
            String input = insertionPointPrefix + helpers.bytesToString(payload) + insertionPointSuffix;

            // Base64- and URL-encode the data
            input = helpers.urlEncode(helpers.base64Encode(input));

            // update the request with the new parameter value
            return helpers.updateParameter(baseRequest, helpers.buildParameter("data", input, IParameter.PARAM_BODY));
            // `helpers.buildParameter` method doc:
            // build a HTTP message param with given (name, value, type[body, cookie, json etc..])
        }

        @Override// from IScannerInsertionPoint
        public int[] getPayloadOffsets(byte[] payload) {
            // since the payload is being inserted into a serialized data structure, there aren't any offsets
            // into the request where the payload literally appears
            return null;
        }

        @Override// from IScannerInsertionPoint
        public byte getInsertionPointType() {
            return INS_EXTENSION_PROVIDED;
            //Used to indicate where the insertion point is provided by an extension-registered IScannerInsertionPointProvider.
        }
    }
}

