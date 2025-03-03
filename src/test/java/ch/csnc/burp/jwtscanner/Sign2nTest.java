package ch.csnc.burp.jwtscanner;

import org.junit.jupiter.api.Test;

public class Sign2nTest {

    @Test
    void test() {
        var jwtEncoded1 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.IDcgYnWIJ0my4FurSqfiAAbYBz2BfImT-uSqKKnk-JfncL_Nreo8Phol1KNn9fK0ZmVfcvHL-pUvVUBzI5NrJNCFMiyZWxS7msB2VKl6-jAXr9NqtVjIDyUSr_gpk51xSzHiBPVAnQn8m1Dg3dR0YkP9b5uJ70qpZ37PWOCKYAIfAhinDA77RIP9q4ImwpnJuY3IDuilDKOq9bsb6zWB8USz0PAYReqWierdS4TYAbUFrhuGZ9mPgSLRSQVtibyNTSTQYtfghYkmV9gWyCJUVwMGCM5l1xlylHYiioasBJA1Wr_NAf_sr4G8OVrW1eO01MKhijpaE8pR6DvPYNrTMQ";
        var jwtEncoded2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODEsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.AH-6ZBGA38IjQdBWbc9mPSPwdHGBcNUw1fT-FhhRA-DnX7A7Ecyaip0jt7gOkuvlXfSBXC91DU6FH7rRcnwgs474jgWCAQm6k5hOngOIce_pKQ_Pk1JU_jFKiKzm668htfG06p9caWa-NicxBp42HKB0w9RRBOddnfWk65d9JTI89clgoLxxz7kbuZIyWAh-Cp1h3ckX7XZmknTNqncq4Y2_PSlcTsJ5aoIL7pIgFQ89NkaHImALYI7IOS8nojgCJnJ74un4F6pzt5IQyvFPVXeODPf2UhMEIEyX3GEcK3ryrD_DciJCze3qjtcjR1mBd6zvAGOUtt6XHSY7UHJ3gg";
        var jwt1 = new Jwt(jwtEncoded1);
        var jwt2 = new Jwt(jwtEncoded2);
        var publicKey = Sign2n.forgePublicKeys(jwt1, jwt2);
        publicKey.stream().map(Rsa::publicKeyToPem).forEach(System.out::println);
    }

}
