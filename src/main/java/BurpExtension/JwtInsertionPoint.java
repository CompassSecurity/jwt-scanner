package BurpExtension;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.utilities.Utilities;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.api.montoya.http.message.params.HttpParameter.parameter;

public class JwtInsertionPoint implements AuditInsertionPoint {
    private final MontoyaApi api;
    private final HttpRequest requestResponse;
    private String baseValue;
    private final Utilities utilities;

    private String prefix;
    private String suffix;

    private int headerPosition;

    JwtInsertionPoint(MontoyaApi api, HttpRequest baseHttpRequest){
        this.requestResponse = baseHttpRequest;
        this.api = api;
        this.utilities = api.utilities();

        String regex = "(ey[a-zA-Z0-9_=]+)\\.(ey[a-zA-Z0-9_=]+)\\.([a-zA-Z0-9_\\-\\+\\/=]*)";
        Pattern pattern = Pattern.compile(regex);
        String input = baseHttpRequest.toString();
        Matcher matcher = pattern.matcher(input);

        if (matcher.find()) {
            int startIndex = matcher.start();
            int endIndex = matcher.end();
            this.prefix = input.substring(0, startIndex);
            this.suffix = input.substring(endIndex,input.length());
        } else {
            api.logging().logToError("No JWT found.");
        }
    }
    @Override
    public String name() {
        return "JWT-Authorization-Header";
    }

    @Override
    public String baseValue() {
        return "demo-jwt";
    }

    @Override
    public HttpRequest buildHttpRequestWithPayload(ByteArray payload){
        HttpRequest req = HttpRequest.httpRequest(this.prefix + payload.toString() + this.suffix);
        HttpService service = this.requestResponse.httpService();
        return req.withService(service);
    }

    @Override
    public List<Range> issueHighlights(ByteArray byteArray) {
        return null;
    }
}
