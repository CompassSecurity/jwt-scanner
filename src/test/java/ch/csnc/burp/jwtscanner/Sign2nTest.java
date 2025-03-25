package ch.csnc.burp.jwtscanner;

import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class Sign2nTest {

    @Test
    void test() throws Exception {
        var jwtEncoded1 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.IDcgYnWIJ0my4FurSqfiAAbYBz2BfImT-uSqKKnk-JfncL_Nreo8Phol1KNn9fK0ZmVfcvHL-pUvVUBzI5NrJNCFMiyZWxS7msB2VKl6-jAXr9NqtVjIDyUSr_gpk51xSzHiBPVAnQn8m1Dg3dR0YkP9b5uJ70qpZ37PWOCKYAIfAhinDA77RIP9q4ImwpnJuY3IDuilDKOq9bsb6zWB8USz0PAYReqWierdS4TYAbUFrhuGZ9mPgSLRSQVtibyNTSTQYtfghYkmV9gWyCJUVwMGCM5l1xlylHYiioasBJA1Wr_NAf_sr4G8OVrW1eO01MKhijpaE8pR6DvPYNrTMQ";
        var jwtEncoded2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODEsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.AH-6ZBGA38IjQdBWbc9mPSPwdHGBcNUw1fT-FhhRA-DnX7A7Ecyaip0jt7gOkuvlXfSBXC91DU6FH7rRcnwgs474jgWCAQm6k5hOngOIce_pKQ_Pk1JU_jFKiKzm668htfG06p9caWa-NicxBp42HKB0w9RRBOddnfWk65d9JTI89clgoLxxz7kbuZIyWAh-Cp1h3ckX7XZmknTNqncq4Y2_PSlcTsJ5aoIL7pIgFQ89NkaHImALYI7IOS8nojgCJnJ74un4F6pzt5IQyvFPVXeODPf2UhMEIEyX3GEcK3ryrD_DciJCze3qjtcjR1mBd6zvAGOUtt6XHSY7UHJ3gg";
        var jwt1 = new Jwt(jwtEncoded1);
        var jwt2 = new Jwt(jwtEncoded2);
        var publicKeys = Sign2n.forgePublicKeys(jwt1, jwt2).get(2, TimeUnit.MINUTES);

        assertThat(publicKeys.stream().map(Rsa::publicKeyToPem).collect(Collectors.joining("\n")), equalTo("""
                -----BEGIN PUBLIC KEY-----
                MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEBQ/AsFcXHk2jLnRpaysTG
                bFck+3xTw+BI7/gsS5khQm3HF7JpL4tt1Me67iPM+OhT8q1h9xUeETW4ltMSeYJm
                fqfboDNw7whKX9kin8kK7tKyl9SFAaZYHqt+xSieJgcteN03vt17pXtGzx3ZQYzR
                7gNnG3/2cZBoWcX82k/1vJS0kOkvO6lznzW9iY62CwpYWB698UuC6gcl8onR2smC
                IY1sjsE1SPB11zjZNa6qYmCgxxcGzLje3vUFRyzgVD7INwWn1+RyRDKSP20NDliu
                LeoV8GsbNRc6L4aA5R7/D7E0MbH5Vs9bCLIYXZ7rJnJseA4Gmt7A3zxDwKitlcvT
                QgIDAQAB
                -----END PUBLIC KEY-----
                
                -----BEGIN PUBLIC KEY-----
                MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAofgWCuLjybRlzo0tZWJj
                NiuSfb4p4fAkd/wWJcyQoTbji9k0l8W26mPddxHmfHQp+Vaw+4qPCJrcS2mJPMEz
                P1Pt0Bm4d4QlL+yRT+SFd2lZS+pCgNMsD1W/YpRPEwOWvG6b32690r2jZ47soMZo
                9wGzjb/7OMg0LOL+bSf63kpaSHSXndS5z5rexMdbBYUsLA9e+KXBdQOS+UTo7WTB
                EMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6/I5IhlJH7aGhyxX
                FvUK+DWNmoudF8NAco9/h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXp
                oQIDAQAB
                -----END PUBLIC KEY-----
                """));
    }

}
