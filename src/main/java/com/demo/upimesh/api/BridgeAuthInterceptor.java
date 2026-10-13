package com.demo.upimesh.api;

import com.demo.upimesh.service.BridgeGate;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Authenticates and rate-limits bridge calls BEFORE the body is parsed or validated,
 * so anonymous callers learn nothing about the packet format and cost us nothing.
 */
@Configuration
public class BridgeAuthInterceptor implements HandlerInterceptor, WebMvcConfigurer {

    public static final String BRIDGE_ID_ATTR = "meshpay.bridgeId";

    private final BridgeGate gate;

    public BridgeAuthInterceptor(BridgeGate gate) {
        this.gate = gate;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(this).addPathPatterns("/api/v1/bridge/**");
    }

    @Override
    public boolean preHandle(HttpServletRequest req, HttpServletResponse res, Object handler) {
        String bridgeId = gate.authenticate(req.getHeader(HttpHeaders.AUTHORIZATION));
        gate.checkRate(bridgeId);
        req.setAttribute(BRIDGE_ID_ATTR, bridgeId);
        return true;
    }
}
