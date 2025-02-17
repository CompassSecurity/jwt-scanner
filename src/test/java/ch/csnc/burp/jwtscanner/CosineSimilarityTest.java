package ch.csnc.burp.jwtscanner;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.lessThan;

public class CosineSimilarityTest {

    @Test
    void testSimilarityGreaterThan90Perc() {
        var res1 = """
                HTTP/1.1 200 OK
                content-type: application/json; charset=utf-8
                date: Mon, 17 Feb 2025 13:03:17 GMT
                content-language: de-CH
                x-envoy-upstream-service-time: 9
                vary: Accept-Encoding
                Strict-Transport-Security: max-age=31536000; includeSubDomains
                Content-Length: 13558
                
                {"userId":12345,"name":"Alice Smith","age":28,"isStudent":false,"email":"alice.smith@example.com","phoneNumbers":[{"type":"home","number":"555-1234"},{"type":"work","number":"555-5678"}],"courses":[{"courseName":"Mathematics","grade":"A"},{"courseName":"Physics","grade":"B"},{"courseName":"Literature","grade":"A-"},{"courseName":"Chemistry","grade":"B+"}],"address":{"street":"123 Main St","city":"Springfield","state":"IL","zip":"62701"},"preferences":{"newsletter":true,"notifications":false}}""";

        var res2 = """
                HTTP/1.1 200 OK
                content-type: application/json; charset=utf-8
                date: Mon, 17 Feb 2025 16:59:21 GMT
                content-language: de-CH
                x-envoy-upstream-service-time: 9
                vary: Accept-Encoding
                Strict-Transport-Security: max-age=31536000; includeSubDomains
                Content-Length: 13557
                
                {"userId":12345,"name":"Alice Smith","age":28,"isStudent":false,"email":"alice.smith@example.com","phoneNumbers":[{"type":"home","number":"555-1234"},{"type":"work","number":"555-5678"}],"courses":[{"courseName":"Mathematics","grade":"A"},{"courseName":"Physics","grade":"B"},{"courseName":"Literature","grade":"A-"},{"courseName":"Chemistry","grade":"B+"}],"address":{"street":"123 Main St","city":"Springfield","state":"IL","zip":"62701"},"preferences":{"newsletter":true,"notifications":true}}""";

        var similarity = CosineSimilarity.of(res1, res2).doubleValue();
        assertThat(similarity, greaterThan(0.9));
    }

    @Test
    void testSimilarityLessThan90Perc() {
        var res1 = """
                HTTP/1.1 200 OK
                content-type: application/json; charset=utf-8
                date: Mon, 17 Feb 2025 13:03:17 GMT
                content-language: de-CH
                x-envoy-upstream-service-time: 9
                vary: Accept-Encoding
                Strict-Transport-Security: max-age=31536000; includeSubDomains
                Content-Length: 13558
                
                {"userId":12345,"name":"Alice Smith","age":28,"isStudent":false,"email":"alice.smith@example.com","phoneNumbers":[{"type":"home","number":"555-1234"},{"type":"work","number":"555-5678"}],"courses":[{"courseName":"Mathematics","grade":"A"},{"courseName":"Physics","grade":"B"},{"courseName":"Literature","grade":"A-"},{"courseName":"Chemistry","grade":"B+"}],"address":{"street":"123 Main St","city":"Springfield","state":"IL","zip":"62701"},"preferences":{"newsletter":true,"notifications":false}}""";

        var res2 = """
                HTTP/1.1 401 Unauthorized
                content-length: 0
                date: Thu, 20 Feb 2025 13:03:57 GMT
                x-envoy-upstream-service-time: 2
                Strict-Transport-Security: max-age=31536000; includeSubDomains
                
                """;

        var similarity = CosineSimilarity.of(res1, res2).doubleValue();
        assertThat(similarity, lessThan(0.9));
    }

}
