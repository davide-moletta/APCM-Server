package it.unitn.APCM.ACME.Guard;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import io.jsonwebtoken.security.Keys;
import it.unitn.APCM.ACME.ServerCommon.CryptographyPrimitive;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import javax.crypto.SecretKey;

@Service
public class JWT_Utils {

    private static final SecretKey SECRET_KEY = Keys.hmacShaKeyFor((new CryptographyPrimitive().getSymmetricKey()).getEncoded());
    private static int EXP_TIME = 1000 * 60 * 30 * 1;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractDate(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String extractGroups(String token) {
        final Claims claims = extractAllClaims(token);
        return (String) claims.get("groups");
    }

    public int extractAdmin(String token) {
        final Claims claims = extractAllClaims(token);
        return (int) claims.get("admin");
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().verifyWith(SECRET_KEY)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private Boolean isTokenExpired(String token) {
        return extractDate(token).before(new Date());
    }

    public String generateToken(User userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("groups", userDetails.getGroups());
        claims.put("admin", userDetails.getAdmin());
        return createToken(claims, userDetails.getEmail());
    }

    private String createToken(Map<String, Object> claims, String subject) {
        long start_time = System.currentTimeMillis();
        return Jwts.builder().claims(claims).subject(subject).issuedAt(new Date(start_time))
                .expiration(new Date(start_time + EXP_TIME))
                .signWith(SECRET_KEY).compact();
    }

    public Boolean validateToken(String token, String email) {
        final String username = extractUsername(token);
        return (username.equals(email) && !isTokenExpired(token));
    }
}
