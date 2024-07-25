package BurpExtension;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointProvider;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JwtInsertionPointProvider implements AuditInsertionPointProvider {
    private final MontoyaApi api;

    JwtInsertionPointProvider(MontoyaApi api)
    {
        this.api = api;
    }

    private final Pattern jwtPattern = Pattern.compile("(ey[a-zA-Z0-9_=]+)\\.(ey[a-zA-Z0-9_=\\-]+)\\.([a-zA-Z0-9_\\-+/=]*)");

    @Override
    public List<AuditInsertionPoint> provideInsertionPoints(HttpRequestResponse httpRequestResponse) {
        return provideInsertionPointsInSelection(httpRequestResponse, 0, 0);
    }

    public List<AuditInsertionPoint> provideInsertionPointsInSelection(HttpRequestResponse httpRequestResponse, int selectionStart, int selectionEnd) {
        List<AuditInsertionPoint> auditInsertionPoints = new ArrayList<>();

        String input;

        if (selectionEnd > selectionStart) {
            input = httpRequestResponse.request().toString().substring(selectionStart, selectionEnd);
        } else {
            input = httpRequestResponse.request().toString();
        }

        Matcher matcher = jwtPattern.matcher(input);

        while (matcher.find()) {
            auditInsertionPoints.add(AuditInsertionPoint.auditInsertionPoint("Detected JWT", httpRequestResponse.request(), selectionStart + matcher.start(), selectionStart + matcher.end()));
        }

        return auditInsertionPoints;
    }
}
