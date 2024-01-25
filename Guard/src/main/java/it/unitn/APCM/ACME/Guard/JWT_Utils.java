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

    // Secret key to encrypt and decrypt the token
    private static final SecretKey SECRET_KEY = Keys
            .hmacShaKeyFor((new CryptographyPrimitive().getSymmetricKey()).getEncoded());
    // Token expiration time => mills * seconds * minutes * hours
    private static int EXP_TIME = 1000 * 60 * 30 * 1;

    // Extract the username from the token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Extract the expiration date from the token
    public Date extractDate(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // Extract the claims from the token
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Extract the groups from the token
    public String extractGroups(String token) {
        final Claims claims = extractAllClaims(token);
        return (String) claims.get("groups");
    }

    // Extract the admin from the token
    public int extractAdmin(String token) {
        final Claims claims = extractAllClaims(token);
        return (int) claims.get("admin");
    }

    // Extract all the claims from the token
    private Claims extractAllClaims(String token) {
        return Jwts.parser().verifyWith(SECRET_KEY)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private Boolean isTokenExpired(String token) {
        return extractDate(token).before(new Date());
    }

    // Generate the token
    public String generateToken(User userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("groups", userDetails.getGroups());
        claims.put("admin", userDetails.getAdmin());
        return createToken(claims, userDetails.getEmail());
    }

    // Create the token
    private String createToken(Map<String, Object> claims, String subject) {
        long start_time = System.currentTimeMillis();
        return Jwts.builder().claims(claims).subject(subject).issuedAt(new Date(start_time))
                .expiration(new Date(start_time + EXP_TIME))
                .signWith(SECRET_KEY).compact();
    }

    // Validate the token
    public Boolean validateToken(String token, String email) {
        final String username = extractUsername(token);
        return (username.equals(email) && !isTokenExpired(token));
    }
}
