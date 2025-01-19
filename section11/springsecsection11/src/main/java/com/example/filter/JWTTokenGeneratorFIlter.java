package com.example.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//jwt토큰 생성 필터
//이 필터가 로그인 작업 중에만 실행되어야 함(초기 로그인 작업 완료후 JWT토큰 생성, 이후의 요청에서는 필터가 호출되지 않아야 함)
public class JWTTokenGeneratorFIlter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return !request.getServletPath().equals("/user"); //false를 반환하면 JWTTokenGeneratorFilter가 실행됨, true를 반환하는 경우에만 Filter가 실행안됨
        // user외 다른 경로에 대한 요청에 대해서는 이 필터가 실행되지 않음
    }
}
