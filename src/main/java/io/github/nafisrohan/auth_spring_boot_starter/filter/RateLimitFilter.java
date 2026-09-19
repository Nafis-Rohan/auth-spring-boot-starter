package io.github.nafisrohan.auth_spring_boot_starter.filter;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class RateLimitFilter extends OncePerRequestFilter {

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();
    private final Map<String, Long> lastAccess = new ConcurrentHashMap<>();
    private final int limit;
    private final Duration window;

    public RateLimitFilter(int limit, Duration window) {
        this.limit = limit;
        this.window = window;
    }



    private void cleanupStaleEntries() {
        long cutoff = System.currentTimeMillis() - (window.toMillis() * 2);
        lastAccess.entrySet().removeIf(entry -> {
            if (entry.getValue() < cutoff) {
                buckets.remove(entry.getKey());
                return true;
            }
            return false;
        });
    }

    private Bucket createBucket() {
        Bandwidth bandwidth = Bandwidth.classic(limit, Refill.intervally(limit, window));
        return Bucket.builder().addLimit(bandwidth).build();
    }

    private String resolveClientIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String path = request.getServletPath();
//      System.out.println("DEBUG - RateLimitFilter saw path: [" + path + "]");
        boolean isLoginEndpoint = path.equals("/login")
                || path.equals("/auth/login")
                || path.equals("/auth/jwt/login")
                || path.equals("/auth/unified-login")
                || path.equals("/auth/mfa/verify");

        if (!isLoginEndpoint) {
            chain.doFilter(request, response);
            return;
        }

        String ip = resolveClientIp(request);
        Bucket bucket = buckets.computeIfAbsent(ip, k -> createBucket());
        lastAccess.put(ip, System.currentTimeMillis());
        cleanupStaleEntries();

        if (bucket.tryConsume(1)) {
            chain.doFilter(request, response);
        } else {
            response.setStatus(429);
            response.setHeader("Retry-After", String.valueOf(window.getSeconds()));
            response.setContentType("text/plain");
            response.getWriter().write("Too many requests — please try again later.");
        }
    }


}