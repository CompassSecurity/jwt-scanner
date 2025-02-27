package ch.csnc.burp.jwtscanner;

import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.closeTo;

public class CosineSimilarityTest {

    @Test
    void test0Perc() {
        var similarity = CosineSimilarity.of("Hello World", "Say Goodbye");
        assertThat(similarity, closeTo(new BigDecimal("0.0"), new BigDecimal("0.01")));
    }

    @Test
    void test50Perc() {
        var similarity = CosineSimilarity.of("Elon Musk", "Colon Musk");
        assertThat(similarity, closeTo(new BigDecimal("0.5"), new BigDecimal("0.01")));
    }

    @Test
    void testWithHttpResponses() {
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

        var similarity = CosineSimilarity.of(res1, res2);
        System.out.println(similarity);
        assertThat(similarity, closeTo(new BigDecimal("0.9"), new BigDecimal("0.01")));
    }

    @Test
    void test100Perc() {
        var similarity = CosineSimilarity.of("""
                        At nunc si ad aliquem bene nummatum tumentemque ideo honestus advena salutatum introieris, primitus 
                        tamquam exoptatus suscipieris et interrogatus multa coactusque mentiri, miraberis numquam 
                        antea visus summatem virum tenuem te sic enixius observantem, ut paeniteat ob haec bona tamquam 
                        praecipua non vidisse ante decennium Romam.""",
                """
                        At nunc si ad aliquem bene nummatum tumentemque ideo honestus advena salutatum introieris, primitus 
                        tamquam exoptatus suscipieris et interrogatus multa coactusque mentiri, miraberis numquam 
                        antea visus summatem virum tenuem te sic enixius observantem, ut paeniteat ob haec bona tamquam 
                        praecipua non vidisse ante decennium Romam.""");
        assertThat(similarity, closeTo(new BigDecimal("1.0"), new BigDecimal("0.01")));
    }

}
