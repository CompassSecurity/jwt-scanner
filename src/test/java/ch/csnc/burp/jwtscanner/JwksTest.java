package ch.csnc.burp.jwtscanner;

import org.junit.jupiter.api.Test;

import static ch.csnc.burp.jwtscanner.Gson.gson;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class JwksTest {

    @Test
    void testJsonSerialization() {
        var json = """
                {"keys":[{"kty":"RSA","e":"AQAB","use":"sig","kid":"2a4e4b46-421d-4c10-98d3-80ac1126e937","alg":"RS256","n":"wXs9piInUdh_254vD0xPU4g8avSKMAyl-xynfjSNyyT_3jW0kvZHYPIpQNQ0tWgG0qgkMUJ71Lrf30CIRFEYg0lylg90h3x3ukCdASsvOjmLOfcBukfp0vZ_kRSXYLUsFKkKHdyP9NRILOoxlST0DxtGDqoYYaMgKUghLv_vwtLeKZV0o6eQqYSwGemDkDHZ_8LTBepQispWoAqA78IJWIBpG4PgFgWci_kwcZhCupyz3dm8-XC7xbsQpQx4Puqccs24jBaiMjHKj1IGmEQCmJiMSs38feVo0Wo5yC6Hp7iHXFN4WNsVLuSsfrxLwXhsYByQ24-YdLsMinAYWC0hWQ"}]}""";
        var jwks = gson.fromJson(json, Jwks.class);
        var jsonAgain = gson.toJson(jwks);
        assertThat(jsonAgain, equalTo(json));
    }

}
