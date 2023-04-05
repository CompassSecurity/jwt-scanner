package BurpExtension;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.utilities.Utilities;

import java.util.List;

import static burp.api.montoya.http.message.params.HttpParameter.parameter;

public class JwtInsertionPoint implements AuditInsertionPoint {
    private final MontoyaApi api;
    private final HttpRequest requestResponse;
    private String baseValue;
    private final Utilities utilities;

    private int headerPosition;

    JwtInsertionPoint(MontoyaApi api, HttpRequest baseHttpRequest){
        this.requestResponse = baseHttpRequest;
        this.api = api;
        this.utilities = api.utilities();

        for (int i=0; i <= baseHttpRequest.headers().toArray().length - 1; i++){
            if (baseHttpRequest.headers().get(i).name().equals("Authorization")){
                baseValue = baseHttpRequest.headers().get(i).value().toString();
                headerPosition = i;
            }
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

        HttpHeader newHeader = HttpHeader.httpHeader("Authorization",payload.toString());
        return requestResponse.withUpdatedHeader(newHeader);
    }

    @Override
    public List<Range> issueHighlights(ByteArray byteArray) {
        return null;
    }
}
