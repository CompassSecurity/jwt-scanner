package ch.csnc.burp.jwtscanner;

import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * This is a small workaround. When I use {@link burp.api.montoya.http.Http#sendRequest(HttpRequest)}, I want the
 * request to include a comment so that it displays in the logger. Since the scanner sends multiple requests, this helps
 * differentiate between them.
 * This handler looks for a specific header, takes its value, adds it to the annotations, and then removes the header.
 */
public class CommentHttpHandler implements burp.api.montoya.http.handler.HttpHandler {

    public static final String COMMENT_HEADER = "X-Jwt-Scanner-Comment";

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        if (!requestToBeSent.hasHeader(COMMENT_HEADER)) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
        var comment = requestToBeSent.header(COMMENT_HEADER).value();
        requestToBeSent.annotations().setNotes(comment);
        return RequestToBeSentAction.continueWith(requestToBeSent.withRemovedHeader(COMMENT_HEADER));
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        return ResponseReceivedAction.continueWith(responseReceived);
    }

}
