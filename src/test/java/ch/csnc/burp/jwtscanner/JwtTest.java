package ch.csnc.burp.jwtscanner;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigDecimal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

public class JwtTest {

    @ParameterizedTest
    @ValueSource(strings = {
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.wrJ__8Q_6BcB2ug9370TBuK5JoAjErqsQtYf7aLcFBk",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOiIxMjM0NTY3ODkwIiwidXNlcm5hbWUiOiJqb2huX2RvZSIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTYxNjIzOTAyMn0.rh5_JJn7hJsCZt6gCSoDW0fo5kwN3okhfLjItYIjLKI",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJvcmRlcklkIjoiOTg3NjU0MzIxMCIsInVzZXJJZCI6IjEyMzQ1Njc4OTAiLCJpdGVtcyI6W3sicHJvZHVjdElkIjoiQTEiLCJxdWFudGl0eSI6Mn0seyJwcm9kdWN0SWQiOiJCMiIsInF1YW50aXR5IjoxfV0sInRvdGFsIjo1OS45OSwiaWF0IjoxNjE2MjM5MDIyfQ.y43-l2Fw-JPNbLce4lCzsZ43pjpUIJuengXelZYboAU",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgU21pdGgiLCJlbWFpbCI6ImphbmUuc21pdGhAZXhhbXBsZS5jb20iLCJwcmVmZXJlbmNlcyI6eyJsYW5ndWFnZSI6ImVuIiwiY3VycmVuY3kiOiJVU0QifSwiaWF0IjoxNjE2MjM5MDIyfQ.JQAFq-QvRlja44sEoSnnQEASRNSXWBg629MIT3Lvdes",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzZXNzaW9uSWQiOiJhYmMxMjN4eXoiLCJ1c2VySWQiOiIxMjM0NTY3ODkwIiwiZXhwaXJlcyI6IjIwMjMtMTItMzFUMjM6NTk6NTlaIiwiaWF0IjoxNjE2MjM5MDIyfQ.0aajXlMwT1hzOVg8AkmQ-913hTckR4a1RIt852eigP0",
    })
    void testDecodeEncodeEqual(String encodedJwt) {
        var jwt = new Jwt(encodedJwt);
        assertThat(jwt.encode(), equalTo(encodedJwt));
    }

    @Test
    void testBuilder() {
        var jwt = Jwt.newBuilder()
                .withHeader("alg", "HS256")
                .withHeader("typ", "JWT")
                .withClaim("sessionId", "abc123xyz")
                .withClaim("userId", "1234567890")
                .withClaim("exp", 1616240022)
                .withClaim("iat", 1616239022)
                .withSignature("B7Hmetshf5LvHccCRW7MutfIyl4h6Td347iD7IiJIdg")
                .build();
        assertThat(jwt.encode(), equalTo("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzZXNzaW9uSWQiOiJhYmMxMjN4eXoiLCJ1c2VySWQiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNjE2MjQwMDIyLCJpYXQiOjE2MTYyMzkwMjJ9.B7Hmetshf5LvHccCRW7MutfIyl4h6Td347iD7IiJIdg"));
    }

    @Test
    void testBuilderWithHS256Signature() {
        var jwt = Jwt.newBuilder()
                .withHeader("alg", "HS256")
                .withHeader("typ", "JWT")
                .withClaim("sub", "1234567890")
                .withClaim("name", "John Doe")
                .withClaim("iat", 1516239022)
                .withHS256Signature("secret-secret-secret")
                .build();
        assertThat(jwt.encode(), equalTo("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.hK8-Z1d7eHC6cg-u7SgqXiP4oIcSNif5mk30MSEA-2g"));
    }

    @ParameterizedTest
    @CsvSource(value = {
            "nexp,1616240022,false",
            "exp,1616240022,true",
    })
    void testHasExpiry(String claim, BigDecimal value, boolean expectation) {
        var jwt = Jwt.newBuilder()
                .withHeader("alg", "HS256")
                .withHeader("typ", "JWT")
                .withClaim("sessionId", "abc123xyz")
                .withClaim("userId", "1234567890")
                .withClaim(claim, value)
                .withClaim("iat", 1616239022)
                .withHS256Signature("secret-secret-secret")
                .build();
        assertThat(jwt.hasExpiry(), is(expectation));
    }

    @ParameterizedTest
    @CsvSource(value = {
            "exp,1516239022,true",
            "exp,4102444800,false",
    })
    void testIsExpired(String claim, BigDecimal value, boolean expectation) {
        var jwt = Jwt.newBuilder()
                .withHeader("alg", "HS256")
                .withHeader("typ", "JWT")
                .withClaim("sub", "1234567890")
                .withClaim("name", "John Doe")
                .withClaim("iat", 1516239022)
                .withClaim(claim, value)
                .withHS256Signature("secret-secret-secret")
                .build();
        assertThat(jwt.isExpired(), is(expectation));
    }

    @Test
    void testWithRemovedSignature() {
        var encodedJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.hK8-Z1d7eHC6cg-u7SgqXiP4oIcSNif5mk30MSEA-2g";
        var jwt = new Jwt(encodedJwt).withRemovedSignature();
        assertThat(jwt.encode(), equalTo("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."));
    }

    @Test
    void testWithWrongSignature() {
        var encodedJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.hK8-Z1d7eHC6cg-u7SgqXiP4oIcSNif5mk30MSEA-2g";
        var jwt = new Jwt(encodedJwt).withWrongSignature();
        assertThat(jwt.encode(), startsWith("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."));
        assertThat(jwt.encode().split("\\.", -1)[2].length(), greaterThan(0));
    }

    @Test
    void testWithNoneAlg() {
        var encodedJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.hK8-Z1d7eHC6cg-u7SgqXiP4oIcSNif5mk30MSEA-2g";
        var jwts = new Jwt(encodedJwt).withAlgNone();
        assertThat(jwts.stream().map(Jwt::encode).toList(), hasItems(
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
                "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
                "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
                "eyJhbGciOiJuT25FIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        ));
    }

    @Test
    void withEmptyPassword() {
        var encodedJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.InANoos_noxPE8wedk8HAORmZ0xhKtqreCOPl460PugsDn9BbXOgA8_fA24CUMLdSfwzIbb0S_nEMyijGY1kAaAAu14zITuNmEouXPrnabjh4czqftZYeDIcnpgyOqsQK_HN1DKf3B8x83F2IFdiof9c5Z0sMFE_Box5AWVUNH3HbeC-pwszTXDf_75_VPK0FBxNlca7De31h1fLU6FTNSy8voDfxNyyOk099xycfcnPpofToczcfNFWkdsQMyMnZS-ByRVK5UztKCB94KGgkpp_bZ-UeRXnl7uyEnniEkQkXlTYLQ-WHCznp-rTG33evNn3Jt5pxWqColqoIxFLSA";
        var jwt = new Jwt(encodedJwt).withEmptyPassword();
        assertThat(jwt.encode(), equalTo("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.he0ErCNloe4J7Id0Ry2SEDg09lKkZkfsRiGsdX_vgEg"));
    }

    @Test
    void withInvalidEcdsa() {
        var encodedJwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XC5woREj5KZL12oOX130uVNvXVveZ_f30ZFNd1VjcUeh9P3JyQvdG0udfAugYBGaRMYi8dGRiQIlfnqZhs7-7ZG5yNpan7vNWNKRpnvsQ6EINQiZcKwdes9ZSYvZsvKYE3H6YLwAStmoe1Kco-ZSnBuudewg4SIq9k_qaiF0sEyGaIUYSoBd9N2gaHUgjJOdTNeAUJjrQICyhVzSf_wfjPRCqQGDN0i_LCAcDWtBCGHley4TbXcPifPtSa7Fb4nTBeeW1DERjKzKX8HDlRZwJau0wTSItBt25GKrCtRj46E_T4qSMdC2i7dLy_rhtDw0dUywEFbxc-4MdWUHAL697Q";
        var jwt = new Jwt(encodedJwt).withInvalidEcdsa();
        assertThat(jwt.encode(), equalTo("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.MAYCAQACAQA"));
    }

    @Test
        // TODO: improve test
    void withInjectedJwkSelfSigned() {
        var encodedJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assertDoesNotThrow(new Jwt(encodedJwt)::withInjectedJwkSelfSigned);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "HS256",
            "HS384",
            "HS512",
    })
    void isSymmetricallySigned(String alg) {
        var jwt = Jwt.newBuilder().withHeader("alg", alg).build();
        assertThat(jwt.hasSymmetricAlg(), is(true));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512",
    })
    void isAsymmetricallySigned(String alg) {
        var jwt = Jwt.newBuilder().withHeader("alg", alg).build();
        assertThat(jwt.hasAsymmetricAlg(), is(true));
    }

    @Test
    void testHasJku() {
        var url = "https://example.com/jwks.json";
        var jwt = Jwt.newBuilder().withHeader("jku", url).build();
        assertThat(jwt.hasJku(), is(true));
        assertThat(jwt.getJku(), equalTo(url));
    }
}
