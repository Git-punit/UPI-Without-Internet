package com.upioffline.backend;

import com.upioffline.protocol.PaymentInstruction;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;

/**
 * Username/password login handing out opaque bearer tokens. Opaque tokens (not JWTs) so logout really ends
 * the session: the server can delete them.
 */
// shortcut: no login rate limiting or lockout (BCrypt only slows guessing); add before exposing to the internet.
@RestController
@RequestMapping("/api/v1")
public class AuthController {

    public record Credentials(String username, String password) {
    }

    public static final String USER_ATTR = "upi.username";
    private static final Duration SESSION_TTL = Duration.ofDays(30);
    private static final SecureRandom RANDOM = new SecureRandom();
    private final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder();
    // Compared against when the user doesn't exist, so login takes the same time either way.
    private final String dummyHash = bcrypt.encode("dummy-password");

    private final JdbcClient jdbc;
    private final Ledger ledger;
    private final long startingBalance;

    public AuthController(JdbcClient jdbc, Ledger ledger, @Value("${upi.mock.starting-balance-minor}") long startingBalance) {
        this.jdbc = jdbc;
        this.ledger = ledger;
        this.startingBalance = startingBalance;
    }

    @PostMapping("/auth/register")
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, String> register(@RequestBody Credentials c) {
        if (!PaymentInstruction.isValidId(c.username()))
            throw ApiException.badRequest("username: 1-64 letters, digits, . _ -");
        if (c.password() == null || c.password().length() < 8 || c.password().getBytes(StandardCharsets.UTF_8).length > 72)
            throw ApiException.badRequest("password must be 8-72 characters");
        try {
            ledger.registerUser(c.username(), bcrypt.encode(c.password()), startingBalance);
        } catch (DuplicateKeyException e) {
            throw new ApiException(HttpStatus.CONFLICT, "USERNAME_TAKEN", "username already registered");
        }
        return Map.of("username", c.username());
    }

    @PostMapping("/auth/login")
    public Map<String, String> login(@RequestBody Credentials c) {
        String hash = c.username() == null ? null : jdbc.sql("SELECT password_hash FROM users WHERE username = ?")
                .param(c.username()).query(String.class).optional().orElse(null);
        boolean ok = bcrypt.matches(c.password() == null ? "" : c.password(), hash == null ? dummyHash : hash);
        if (!ok || hash == null)
            throw new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS", "wrong username or password");

        byte[] raw = new byte[32];
        RANDOM.nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        Instant expires = Instant.now().plus(SESSION_TTL);
        jdbc.sql("INSERT INTO sessions (token_hash, username, expires_at) VALUES (?, ?, ?)")
                .params(sha256(token), c.username(), Timestamp.from(expires)).update();
        return Map.of("token", token, "username", c.username(), "expiresAt", expires.toString());
    }

    @PostMapping("/auth/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(HttpServletRequest request) {
        jdbc.sql("DELETE FROM sessions WHERE token_hash = ?").param(sha256(bearer(request))).update();
    }

    @GetMapping("/me")
    public Map<String, Object> me(@RequestAttribute(USER_ATTR) String username) {
        long balance = jdbc.sql("SELECT balance_minor FROM accounts WHERE username = ?").param(username).query(Long.class).single();
        return Map.of("username", username, "balanceMinor", balance);
    }

    static String bearer(HttpServletRequest request) {
        String h = request.getHeader("Authorization");
        if (h == null || !h.startsWith("Bearer ") || h.length() < 8)
            throw new ApiException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "log in first (Authorization: Bearer <token>)");
        return h.substring(7);
    }

    static String sha256(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Every /api/v1 endpoint needs a valid token except register, login and the public backend key. */
    @Configuration
    static class RequireLogin implements WebMvcConfigurer {
        private final JdbcClient jdbc;

        RequireLogin(JdbcClient jdbc) {
            this.jdbc = jdbc;
        }

        @Override
        public void addInterceptors(InterceptorRegistry registry) {
            registry.addInterceptor(new HandlerInterceptor() {
                @Override
                public boolean preHandle(HttpServletRequest req, HttpServletResponse res, Object handler) {
                    String username = jdbc.sql("SELECT username FROM sessions WHERE token_hash = ? AND expires_at > ?")
                            .params(sha256(bearer(req)), Timestamp.from(Instant.now()))
                            .query(String.class).optional()
                            .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "session expired or invalid; log in again"));
                    req.setAttribute(USER_ATTR, username);
                    return true;
                }
            }).addPathPatterns("/api/v1/**")
              .excludePathPatterns("/api/v1/auth/register", "/api/v1/auth/login", "/api/v1/keys/backend", "/api/v1/webhooks/razorpay");
        }
    }
}
