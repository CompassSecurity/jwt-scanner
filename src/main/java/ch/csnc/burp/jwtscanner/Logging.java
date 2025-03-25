package ch.csnc.burp.jwtscanner;

import burp.api.montoya.MontoyaApi;

public class Logging {

    private final MontoyaApi api;

    public Logging() {
        this(null);
    }

    public Logging(MontoyaApi api) {
        this.api = api;
    }

    public void logToOutput(String message) {
        if (this.api != null) {
            this.api.logging().logToOutput(message);
        } else {
            System.out.println(message);
        }
    }

    public void logToError(String message) {
        if (this.api != null) {
            this.api.logging().logToError(message);
        } else {
            System.err.println(message);
        }
    }

    public void logToError(Throwable throwable) {
        if (this.api != null) {
            this.api.logging().logToError(throwable);
        } else {
            throwable.printStackTrace(System.err);
        }
    }

    public void raiseErrorEvent(String message) {
        if (this.api != null) {
            this.api.logging().raiseErrorEvent(message);
        } else {
            System.err.println(message);
        }
    }

    public void raiseInfoEvent(String message) {
        if (this.api != null) {
            this.api.logging().raiseInfoEvent(message);
        } else {
            System.out.println(message);
        }
    }

}
