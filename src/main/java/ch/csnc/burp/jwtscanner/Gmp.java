package ch.csnc.burp.jwtscanner;

import org.scijava.nativelib.NativeLoader;

public class Gmp {

    static {
        try {
            System.loadLibrary("gmpwrapper");
        } catch (Exception exc1) {
            try {
                NativeLoader.loadLibrary("gmpwrapper");
            } catch (Exception exc2) {
                JwtScannerExtension.logging().logToError(exc2);
                throw new RuntimeException(exc2);
            }
        }
    }

    public native String sub(String a, String b);

    public native String cdiv(String a, String b);

    public native String pow(String base, String exp);

    public native String powm(String base, String exp, String mod);

    public native String gcd(String a, String b);

}
