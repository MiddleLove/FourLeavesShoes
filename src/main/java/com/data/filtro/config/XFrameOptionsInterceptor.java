package com.data.filtro.config;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

public class XFrameOptionsInterceptor implements HandlerInterceptor {
    private static final String STRICT_TRANSPORT_SECURITY_HEADER_NAME = "Strict-Transport-Security";
    private static final String STRICT_TRANSPORT_SECURITY_HEADER_VALUE = "max-age=31536000; includeSubDomains";
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        response.setHeader("X-Frame-Options", "SAMEORIGIN");
        response.setHeader("Content-Security-Policy", "script-src 'self' https://stackpath.bootstrapcdn.com " +
                "https://code.jquery.com " +
                "https://cdn.jsdelivr.net " +
                "https://cdnjs.cloudflare.com 'unsafe-inline'; ");
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("Expect-CT", "max-age=86400");
        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
    }
}
