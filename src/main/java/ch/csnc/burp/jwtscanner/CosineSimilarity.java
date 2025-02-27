package ch.csnc.burp.jwtscanner;

import java.math.BigDecimal;
import java.math.MathContext;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * This class implements the Cosine Similarity algorithm to compare two strings.
 * Two strings are considered similar if the algorithm returns a value close to 1.
 *
 * <img src="https://wikimedia.org/api/rest_v1/media/math/render/svg/15d11df2d48da4787ee86a4b8c14551fbf0bc96a>
 */
public abstract class CosineSimilarity {

    public static BigDecimal of(String s1, String s2) {
        var words1 = Arrays.stream(s1.split("\\s+")).toList();
        var words2 = Arrays.stream(s2.split("\\s+")).toList();
        var dict = Stream.concat(words1.stream(), words2.stream()).collect(Collectors.toSet());

        var wordCount1 = dict.stream().collect(Collectors.toMap(word -> word, word -> BigDecimal.ZERO, BigDecimal::add, LinkedHashMap::new));
        var wordCount2 = dict.stream().collect(Collectors.toMap(word -> word, word -> BigDecimal.ZERO, BigDecimal::add, LinkedHashMap::new));
        words1.forEach(word -> wordCount1.compute(word, (__, count) -> count.add(BigDecimal.ONE)));
        words2.forEach(word -> wordCount2.compute(word, (__, count) -> count.add(BigDecimal.ONE)));

        var aVec = List.copyOf(wordCount1.values());
        var bVec = List.copyOf(wordCount2.values());

        var abVec = new ArrayList<BigDecimal>();
        for (var i = 0; i < Math.max(aVec.size(), bVec.size()); i++) {
            var a = i >= aVec.size() ? BigDecimal.ZERO : aVec.get(i);
            var b = i >= bVec.size() ? BigDecimal.ZERO : bVec.get(i);
            abVec.add(a.multiply(b));
        }

        var dividend = abVec.stream().reduce(BigDecimal::add).orElse(BigDecimal.ZERO);
        var divisorLeft = aVec.stream().map(d -> d.pow(2)).reduce(BigDecimal::add).map(d -> d.sqrt(MathContext.DECIMAL32)).orElse(BigDecimal.ZERO);
        var divisorRight = bVec.stream().map(d -> d.pow(2)).reduce(BigDecimal::add).map(d -> d.sqrt(MathContext.DECIMAL32)).orElse(BigDecimal.ZERO);
        var divisor = divisorLeft.multiply(divisorRight);
        if (BigDecimal.ZERO.equals(divisor)) {
            return BigDecimal.ZERO;
        }
        return dividend.divide(divisor, 8, RoundingMode.HALF_UP);
    }
}
