package ch.csnc.burp.jwtscanner;

public class JwtParseException extends RuntimeException {
    public JwtParseException(String msg) {
        super(msg);
    }
}
