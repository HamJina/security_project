package com.example.filter;

import com.example.constants.ApplicationConstants;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.stream.Collectors;

//jwt토큰 생성 필터
//이 필터가 로그인 작업 중에만 실행되어야 함(초기 로그인 작업 완료후 JWT토큰 생성, 이후의 요청에서는 필터가 호출되지 않아야 함)
public class JWTTokenGeneratorFIlter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //현재 인증된 세부 정보 읽기
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(null!=authentication){
            Environment env = getEnvironment();
            if(null!=env) {
                String secret = env.getProperty(ApplicationConstants.JWT_SECRET_KEY, ApplicationConstants.JWT_SECRET_DEFAULT_VALUE);
                SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)); //시크릿키 준비하기

                //jwt토큰 생성하기
                String jwt = Jwts.builder().issuer("Eazy Bank").subject("JWT Token")
                        .claim("username", authentication.getName()) //key, value
                        .claim("authorities", authentication.getAuthorities().stream().map(
                                GrantedAuthority::getAuthority).collect(Collectors.joining(",")))
                        .issuedAt(new Date())
                        .expiration(new Date((new Date()).getTime() + 30000000))
                        .signWith(secretKey).compact();
                response.setHeader(ApplicationConstants.JWT_HEADER, jwt);
            }

        }
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return !request.getServletPath().equals("/user"); //false를 반환하면 JWTTokenGeneratorFilter가 실행됨, true를 반환하는 경우에만 Filter가 실행안됨
        // user외 다른 경로에 대한 요청에 대해서는 이 필터가 실행되지 않음
    }
}
