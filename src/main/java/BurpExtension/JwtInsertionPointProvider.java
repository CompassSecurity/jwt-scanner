package BurpExtension;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointProvider;

import java.util.List;
import java.util.stream.Collectors;

public class JwtInsertionPointProvider implements AuditInsertionPointProvider {

    private final MontoyaApi api;

    JwtInsertionPointProvider(MontoyaApi api){
        this.api = api;
    }
    @Override
    public List<AuditInsertionPoint> provideInsertionPoints(HttpRequestResponse httpRequestResponse) {
        List<HttpHeader> headers = httpRequestResponse.request().headers();
        api.logging().logToOutput("Insertion Point headers: " + headers);
        return headers.stream()
                .filter(h -> h.name().equals("Authorization"))
                .map(h -> new JwtInsertionPoint(api, httpRequestResponse.request()))
                .collect(Collectors.toList());
    }
}
