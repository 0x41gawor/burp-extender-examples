This extension demonstrates how to redirect outgoing HTTP requests from one host to anothe.



The extension works as follows:

- It registers itself as an HTTP listener.
- For outgoing request messages, it retrieves the HTTP service for the request.
- If the HTTP service host matches the "from" host, it uses a helper method to build a new HTTP service using the "to" host, and other details unchanged.
- It updates the HTTP request with the new HTTP service.

