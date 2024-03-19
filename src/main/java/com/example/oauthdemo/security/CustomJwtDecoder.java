package com.example.oauthdemo.security;

import com.example.oauthdemo.services.JwtService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * This class provides implementation of Spring Security interface for JWT decoding
 * with the help of io.jsonwebtoken.
 * You would need to implement similar class in  cases like those:
 * - You want to use non-standard JWT library
 * - You need to decode multiple types of JWTs with the same library (i. e. they obtain keys in different ways,
 *   or one of them should invoke additional logic during decoding, etc)
 *
 *   On pattern level this class is an adapter between JWT library and Spring Security.
 *   Try to provide proper exception handling and conversion to avoid leaking JWT library logic into Spring Security.
 */
@Component
public class CustomJwtDecoder implements JwtDecoder {

    private final JwtService jwtService;

    public CustomJwtDecoder(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        JwtParser parser = jwtService.getTokenParser();
        try {
            Jws<Claims> jwt = parser.parseClaimsJws(token);
            Claims claims = jwt.getBody();
            Instant issuedAt = claims.getIssuedAt().toInstant();
            Instant expiresAt = claims.getExpiration().toInstant();
            JwsHeader header = jwt.getHeader();
            // Note, that both Header and Claims extend Map<String,Object> and thus can be passed to Spring Security JWT directly
            return new Jwt(token, issuedAt, expiresAt, header, claims);
        } catch (UnsupportedJwtException e) {
            throw new JwtException("Attempt to authorize with JWT of unsupported type", e);
        } catch (MalformedJwtException e) {
            throw new JwtException("Attempt to authorize with malformed JWT", e);
        } catch (SignatureException e) {
            throw new JwtException("Attempt to authorize with JWT with invalid signature", e);
        } catch (ExpiredJwtException e) {
            throw new JwtException("Attempt to authorize with expired JWT", e);
        } catch (IllegalArgumentException e) {
            throw new JwtException("Attempt to authorize with empty/blank JWT", e);
        }
    }
}
