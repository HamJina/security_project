package com.example.config;

import com.example.exceptionhandling.CustomAccessDeniedHandler;
import com.example.exceptionhandling.CustomBasicAuthenticationEntryPoint;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@Profile("prod")
public class ProjectSecurityProdConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration config = new CorsConfiguration();
                        config.setAllowedOrigins(Collections.singletonList("https://localhost:4200"));
                        config.setAllowedMethods(Collections.singletonList("*"));
                        config.setAllowCredentials(true);
                        config.setAllowedHeaders(Collections.singletonList("*"));
                        config.setMaxAge(3600L);
                        return config;
                    }
                }))
                .sessionManagement(smc -> smc.invalidSessionUrl("/invalidSession").maximumSessions(1).maxSessionsPreventsLogin(true)) //세션이 최대갯수에 도달하면 더이상 인증x, 첫번째 세션 유효
                .requiresChannel(rcc -> rcc.anyRequest().requiresSecure()) //HTTPS허용
                .csrf(csrfConfig -> csrfConfig.disable())
                .authorizeHttpRequests((requests) -> {requests
                        .requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT") //단일 권한 부여
                        .requestMatchers("/myBalance").hasAnyAuthority("VIEWBALANCE","VIEWACCOUNT") //여러 권한 부여
                        .requestMatchers("/myLoans").hasAuthority("VIEWLOANS")
                        .requestMatchers("/myCards").hasAuthority("VIEWCARDS")
                        .requestMatchers("/user").authenticated() //조건을 궈한 규칙의 일부로 강제해야 하는 경우 (access사용)
                        .requestMatchers("/notices","/contact","/error","register","/invalidSession").permitAll(); //웹 애플리케이션 내의 모든 요청 보안x

        });
        http.formLogin(Customizer.withDefaults());
        http.httpBasic(hbc -> hbc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
        http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler())); //전역설정
        return (SecurityFilterChain)http.build();
    }

    /*@Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
       return new JdbcUserDetailsManager(dataSource);
    }*/

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }
}
