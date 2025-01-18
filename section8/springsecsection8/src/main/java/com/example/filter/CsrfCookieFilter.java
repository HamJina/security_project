package com.example.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//csrf: 라이브러리가 요청의 일부로 필터를 한번만 실행하도록 관리한다. (필터가 불필요하게 실행되지 않음)
public class CsrfCookieFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        //csrf값 수동으로 읽기
        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        //Render the token value to a cookie by causing the deferred token to be loaded
        csrfToken.getToken();
        filterChain.doFilter(request, response);
    }
}
