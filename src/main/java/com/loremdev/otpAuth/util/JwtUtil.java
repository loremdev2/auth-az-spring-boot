package com.loremdev.otpAuth.util;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;


@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String SECRET_KEY;

    public String generateToken(UserDetails userDetails){
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails.getUsername());
    }

    private String createToken(Map<String, Object> claims, String email) {
        byte[] keyBytes = SECRET_KEY.getBytes(StandardCharsets.UTF_8);
        Key signingKey = Keys.hmacShaKeyFor(keyBytes);                       // ← use a Key

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(email)  // Email is passed as Subject
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 10))
                .signWith(signingKey, SignatureAlgorithm.HS256)                  // ← pass Key + alg
                .compact();
    }

    private Claims extractAllClaims(String token) {
        // re-build the exact same Key you used to sign
        byte[] keyBytes = SECRET_KEY.getBytes(StandardCharsets.UTF_8);
        Key signingKey = Keys.hmacShaKeyFor(keyBytes);

        // use the new parserBuilder API!
        return Jwts.parser()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }


    private <T> T extractClaim(String token, Function<Claims, T> claimResolver){
        final Claims claims= extractAllClaims(token);
        return claimResolver.apply(claims);

    }

    public String extractEmail(String token){
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token){
        return extractClaim(token, Claims::getExpiration);
    }

    private boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    public boolean validateToken(String token ,UserDetails userDetails){
        final String email = extractEmail(token);
        return (email.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

}
