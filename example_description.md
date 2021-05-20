# custom editor tab

This extension demonstrates how you can extend Burp's own HTTP message editor to handle the display and editing of unsupported data formats. This capability can let you handle custom serialization implemented by specific applications, or any other data format that Burp does not natively support.

In the past, some extensions have handled unsupported serialization formats by hooking into Burp's HTTP stack, and modifying incoming and outgoing messages, in order to unpack and repack the serialized data. Although this approach can work, it is quite restricted in the type of data it can handle. And it is also inelegant: it would be preferable to customize Burp to understand the custom format itself, rather than tampering with the integrity of HTTP messages.

The [extender API](https://portswigger.net/burp/extender/) lets you add custom tabs to Burp's HTTP message editor. When a message is about to be displayed, Burp will ask the tab whether it can handle the message. If so, the custom tab will be shown in the editor, and can support rendering and editing of the message within its own UI:

![](example_description_img/1.png)

So basically the extension ads this option to **HTTP message editor** (which you learned in 6. Custom Logger).

## Base64InputTab

First we need to create class that implements `IMessageEditorTab` interface.

We called it `Base64InputTab`. This class represents our custom Message Editor Tab.

We can use `ITextEditor`. An interface provided by Burp, which extends some swing component and can be used to display and edit HTTP Message.

We use `ITextEditor` as a field in `Base64InputTab`.

How it is all implemented check the code.

### IMessageEditorTabFactory

Our `BurpExtender` class implements this interface so it can register itself as Message Editor factory and implement `createNewInstance` method which returns object of our `Base64InputTab`.

