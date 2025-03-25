package ch.csnc.burp.jwtscanner;

import ch.csnc.burp.jwtscanner.Jwk.JwkJsonDeserializer;
import ch.csnc.burp.jwtscanner.Jwk.JwkJsonSerializer;
import com.google.gson.GsonBuilder;
import com.google.gson.ToNumberPolicy;

public abstract class Gson {

    public static final com.google.gson.Gson gson = new GsonBuilder()
            .setObjectToNumberStrategy(ToNumberPolicy.BIG_DECIMAL)
            .disableHtmlEscaping()
            .registerTypeAdapter(Jwk.class, new JwkJsonSerializer())
            .registerTypeAdapter(Jwk.class, new JwkJsonDeserializer())
            .create();

}
