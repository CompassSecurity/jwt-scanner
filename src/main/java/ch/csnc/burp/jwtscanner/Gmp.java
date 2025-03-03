package ch.csnc.burp.jwtscanner;

public class Gmp {

    static {
        System.loadLibrary("gmpwrapper");
    }

    public native String sub(String a, String b);

    public native String cdiv(String a, String b);

    public native String pow(String base, String exp);

    public native String powm(String base, String exp, String mod);

    public native String gcd(String a, String b);

}
