package com.example.demo;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;


public class JwtTokenFilter extends OncePerRequestFilter{

    private final JwtTokenUtil jwtTokenUtil;

    public JwtTokenFilter(JwtTokenUtil jwtTokenUtil) {
        this.jwtTokenUtil = jwtTokenUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String originalUri = request.getHeader("X-Original-URI");

        //인증이 필요없을 경우
        if (originalUri != null && !originalUri.contains("/auth")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = request.getHeader("Authorization");

        // Header의 Authorization의 값이 비어있거나 Bearer 로 시작하지 않으면 오류
        if (token == null || !token.startsWith("Bearer ")) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Invalid Token");
            return;
        }

        String jwtToken = token.replace("Bearer ", "");
        // 전송받은 Jwt Token이 만료되었으면 오류
        if (jwtTokenUtil.isExpired(jwtToken)) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Invalid Token");
            return;
        }

        // Jwt Token에서 loginId 추출
        String loginId = jwtTokenUtil.getLoginId(jwtToken);
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("text/plain");
        response.setHeader("X-Authoization-Id", loginId);

        filterChain.doFilter(request, response);
    }

}
