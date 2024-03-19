package com.example.oauthdemo.services;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * This service is minimalistic implementation of JWT-related functionality based on
 * io.jsonwebtoken libraries.
 * This service is not in focus of the demo, contains multiple shortcuts and vulnerabilities and should not be used as example
 */
@Service
public class JwtService {

    // Key is store in sources: critically unsafe.
    public static final String SECRET = "357638792F423F4428472B4B6250655368566D597133743677397A2443264629";

    public JwtParser getTokenParser() {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignKey())
                .build();
    }

    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, username);
    }


    private String createToken(Map<String, Object> claims, String username) {

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 5)) // Expires in 5 minutes ( number is in milliseconds)
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
    }

    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
