package ch.csnc.burp.jwtscanner;

import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import static java.util.Base64.getUrlDecoder;
import static java.util.Base64.getUrlEncoder;

public abstract class Base64 {

    public static final Encoder base64UrlEncoderWithPadding = getUrlEncoder();
    public static final Encoder base64UrlEncoderNoPadding = getUrlEncoder().withoutPadding();
    public static final Decoder base64UrlDecoder = getUrlDecoder();

}
