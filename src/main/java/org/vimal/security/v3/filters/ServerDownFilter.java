package org.vimal.security.v3.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.getunleash.Unleash;
import io.getunleash.variant.Variant;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.vimal.security.v3.enums.FeatureFlags.SERVER_DOWN;

@Component
@RequiredArgsConstructor
public class ServerDownFilter extends OncePerRequestFilter {
    private final Unleash unleash;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        Variant variant = unleash.getVariant(SERVER_DOWN.name());
        if (variant.isEnabled()) {
            response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            response.setContentType("application/json");
            Map<String, String> message = new HashMap<>();
            message.put("message", "Service Unavailable");
            if (variant.getPayload().isPresent()) {
                message.put("reason", variant.getPayload()
                        .get()
                        .getValue());
            } else {
                message.put("reason", "Unknown");
            }
            objectMapper.writeValue(
                    response.getWriter(),
                    message
            );
            return;
        }
        filterChain.doFilter(
                request,
                response
        );
    }
}
