package com.example.demo;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

public class JwtTokenFilter extends OncePerRequestFilter{

    private final JwtTokenUtil jwtTokenUtil;
    private static final Set<String> SKIP_AUTH_PATHS = new HashSet<>();

    public JwtTokenFilter(JwtTokenUtil jwtTokenUtil) {
        this.jwtTokenUtil = jwtTokenUtil;
    }

    static {
        SKIP_AUTH_PATHS.add("/notice/externalact/");
        SKIP_AUTH_PATHS.add("/notice/externalact/keyword");
        SKIP_AUTH_PATHS.add("/recommend/univ");
        SKIP_AUTH_PATHS.add("/recommend/external");
        SKIP_AUTH_PATHS.add("/notice/univactivity/");
        SKIP_AUTH_PATHS.add("/notice/univactivity/department");
        SKIP_AUTH_PATHS.add("/notice/univactivity/keyword");
        SKIP_AUTH_PATHS.add("/notice/univactivity/department/keyword");
        SKIP_AUTH_PATHS.add("/member/join");
        SKIP_AUTH_PATHS.add("/member/login");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String originalUri = request.getHeader("X-Original-URI");
        if (originalUri != null && !originalUri.contains("/auth")) {
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("text/plain");
            response.getWriter().write(originalUri);
            return;
        }

//        if(shouldSkipAuth(originalUri)){
//            response.setStatus(HttpServletResponse.SC_OK);
//            response.setContentType("text/plain");
//            response.getWriter().write(originalUri);
//            return;
//        }

        String token = request.getHeader("Authorization");

        System.out.println("Original token: " + token);
        System.out.println("Original Path: " + originalUri);

        // Header의 Authorization의 값이 비어있으면 오류
        if (token == null || !token.startsWith("Bearer ")) {
            System.out.println("1");

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Invalid Token1");
            return;
        }

        String jwtToken = token.replace("Bearer ", "");
        // 전송받은 Jwt Token이 만료되었으면 오류
        if (jwtTokenUtil.isExpired(jwtToken)) {
            System.out.println("2");


            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Invalid Token1");
            return;
        }
        System.out.println("3");

        // Jwt Token에서 loginId 추출
        String loginId = jwtTokenUtil.getLoginId(jwtToken);
        System.out.println("loginId");
        //return
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("text/plain");
        response.setHeader("X-Authoization-Id", loginId);
        response.getWriter().write("success");
        return;
        //filterChain.doFilter(request, response);
    }

//    public static boolean shouldSkipAuth(String path) {
//        // Extract path without query parameters
//        String pathWithoutQuery = path.split("\\?")[0];
//
//        for (String skipPath : SKIP_AUTH_PATHS) {
//            if (pathWithoutQuery.equals(skipPath) || (skipPath.endsWith("/") && pathWithoutQuery.startsWith(skipPath))) {
//                return true;
//            }
//        }
//        return false;
//    }
}
