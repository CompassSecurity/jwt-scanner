package BurpExtension;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.core.ByteArray.byteArray;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;

class JWTScanCheck implements ScanCheck
{
    private final MontoyaApi api;

    JWTScanCheck(MontoyaApi api)
    {
        this.api = api;
    }

    ArrayList<String> algoList = new ArrayList<>();


    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint)
    {
        JwtModifier jwtModifier = new JwtModifier(api);
        String origJwt = "";
        String regex = "(ey[a-zA-Z0-9_=]+)\\.(ey[a-zA-Z0-9_=]+)\\.([a-zA-Z0-9_\\-\\+\\/=]*)";
        Pattern pattern = Pattern.compile(regex);
        HttpRequest req = baseRequestResponse.request();
        Matcher matcher = pattern.matcher(req.toString());

        if (matcher.find()) {
            int startIndex = matcher.start();
            int endIndex = matcher.end();
            origJwt = req.toString().substring(startIndex,endIndex);
            // Validate if the origJwt is still valid
            if (jwtModifier.isJwtNotExpired(origJwt)) {
                api.logging().logToOutput("using JWT:\n" + origJwt);
            } else {
                api.logging().raiseErrorEvent("JWT expired, please choose a valid one!");
                api.logging().logToOutput("JWT expired, please choose a valid one!");
            }

        } else {
            api.logging().logToError("No JWT found.");
        }

        HttpRequest checkRequestNoSig = auditInsertionPoint.buildHttpRequestWithPayload(byteArray(jwtModifier.removeSignature(origJwt)));
        HttpRequestResponse checkRequestResponseNoSig = api.http().sendRequest(checkRequestNoSig);
        if (checkRequestResponseNoSig.response().statusCode() == 200){
            api.siteMap().add(JwtAuditIssues.withoutSignature(baseRequestResponse.request().url(), checkRequestResponseNoSig));
        }

        HttpRequest checkRequestSig = auditInsertionPoint.buildHttpRequestWithPayload(byteArray(jwtModifier.wrongSignature(origJwt)));
        HttpRequestResponse checkRequestResponseSig = api.http().sendRequest(checkRequestSig);
        if (checkRequestResponseSig.response().statusCode() == 200){
            api.siteMap().add(JwtAuditIssues.invalidSignature(baseRequestResponse.request().url(), checkRequestResponseSig));
        }

        this.permute("none", "");

        for(int i = 0; i< algoList.size(); i++) {
            HttpRequest checkRequestNone = auditInsertionPoint.buildHttpRequestWithPayload(byteArray(jwtModifier.algNone(origJwt, algoList.get(i))));
            HttpRequestResponse checkRequestResponseNone = api.http().sendRequest(checkRequestNone);
            if (checkRequestResponseNone.response().statusCode() == 200) {
                api.siteMap().add(JwtAuditIssues.getAlgNone(baseRequestResponse.request().url(), checkRequestResponseNone));
            }
        }

        HttpRequest checkRequestEmpty = auditInsertionPoint.buildHttpRequestWithPayload(byteArray(jwtModifier.emptyPassword(origJwt)));
        HttpRequestResponse checkRequestResponseEmpty = api.http().sendRequest(checkRequestEmpty);
        if (checkRequestResponseEmpty.response().statusCode() == 200){
            api.siteMap().add(JwtAuditIssues.emptyPassword(baseRequestResponse.request().url(), checkRequestResponseEmpty));
        }

        HttpRequest checkRequestEcdsa = auditInsertionPoint.buildHttpRequestWithPayload(byteArray(jwtModifier.invalidEcdsa(origJwt)));
        HttpRequestResponse checkRequestResponseEcdsa = api.http().sendRequest(checkRequestEcdsa);
        if (checkRequestResponseEcdsa.response().statusCode() == 200){
            api.siteMap().add(JwtAuditIssues.invalidEcdsa(baseRequestResponse.request().url(), checkRequestResponseEcdsa));
        }

        HttpRequest checkRequestJwks = auditInsertionPoint.buildHttpRequestWithPayload(byteArray(jwtModifier.jwksInjection(origJwt)));
        HttpRequestResponse checkRequestResponseJwks = api.http().sendRequest(checkRequestJwks);
        if (checkRequestResponseJwks.response().statusCode() == 200){
            api.siteMap().add(JwtAuditIssues.jwksInjection(baseRequestResponse.request().url(), checkRequestResponseJwks));
        }

        return auditResult();
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse)
    {
        return auditResult();
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue)
    {
        return existingIssue.name().equals(newIssue.name()) ? KEEP_EXISTING : KEEP_BOTH;
    }
    private void permute(String ip, String op)
    {
        // base case
        if(ip.length() == 0){
            this.algoList.add(op);
            return;
        }
        // pick lower and uppercase
        String ch = ("" + ip.charAt(0)).toLowerCase();
        String ch2 = ("" + ip.charAt(0)).toUpperCase();
        ip = ip.substring(1, ip.length()) ;

        permute(ip, op + ch);
        permute(ip, op + ch2);
    }
}
