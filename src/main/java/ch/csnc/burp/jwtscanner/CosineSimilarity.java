package ch.csnc.burp.jwtscanner;

import java.math.BigDecimal;
import java.math.MathContext;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * This class implements the Cosine Similarity algorithm to compare two strings.
 * Two strings are considered similar if the algorithm returns a value close to 1.
 */
public abstract class CosineSimilarity {

    public static BigDecimal of(String s1, String s2) {
        var aVec = Arrays.stream(s1.split("\\s+")).collect(Collectors.toMap(word -> word, word -> BigDecimal.ONE, BigDecimal::add)).values().stream().toList();
        var bVec = Arrays.stream(s2.split("\\s+")).collect(Collectors.toMap(word -> word, word -> BigDecimal.ONE, BigDecimal::add)).values().stream().toList();
        var ab = new ArrayList<BigDecimal>();
        for (var i = 0; i < Math.max(aVec.size(), bVec.size()); i++) {
            var a = i >= aVec.size() ? BigDecimal.ZERO : aVec.get(i);
            var b = i >= bVec.size() ? BigDecimal.ZERO : bVec.get(i);
            ab.add(a.multiply(b));
        }
        var dividend = ab.stream().reduce(BigDecimal::add).orElse(BigDecimal.ZERO);
        var divisorLeft = aVec.stream().map(d -> d.pow(2)).reduce(BigDecimal::add).map(d -> d.sqrt(MathContext.DECIMAL32)).orElse(BigDecimal.ZERO);
        var divisorRight = bVec.stream().map(d -> d.pow(2)).reduce(BigDecimal::add).map(d -> d.sqrt(MathContext.DECIMAL32)).orElse(BigDecimal.ZERO);
        var divisor = divisorLeft.multiply(divisorRight);
        if (BigDecimal.ZERO.equals(divisor)) {
            return BigDecimal.ZERO;
        }
        return dividend.divide(divisor, 8, RoundingMode.HALF_UP);
    }
}
