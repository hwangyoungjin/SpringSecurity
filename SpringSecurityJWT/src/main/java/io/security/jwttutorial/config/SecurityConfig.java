package io.security.jwttutorial.config;

import io.security.jwttutorial.jwt.JwtAccessDeniedHandler;
import io.security.jwttutorial.jwt.JwtAuthenticationEntryPoint;
import io.security.jwttutorial.jwt.JwtSecurityConfig;
import io.security.jwttutorial.jwt.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
@RequiredArgsConstructor
//메소드 인가방식의 @PreAuthorize 어노테이션을 추가하기위하여 적용
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    //passwordEncoder Bean등록
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    
    @Override
    public void configure(WebSecurity web) throws Exception {
        web
                .ignoring()
                .antMatchers(
                        "/h2-console/**",
                        "/favicon.ico"
                );
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                //토큰을 사용하기 떄문에 csrf 설정은 disable
                .csrf().disable()

                //Exception을 핸들링할때 만들었던 클래스 추가
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

        .and()
                //h2-console을 위한 설정
                .headers()
                .frameOptions()
                .sameOrigin()

        .and()
                //세션을 사용하지 않기 떄문에 세션설정을 stateless로
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

        .and()
                // 모든 요청의 보안설정
                .authorizeRequests()
                .antMatchers("/api/hello").permitAll() //해당 url은 허가

                //로그인 API, 회원가입 API는 토큰이 없는 상태에서
                //요청이 들어오기 때문에 모두 permitAll 설정
                .antMatchers("/api/authenticate").permitAll()
                .antMatchers("/api/signup").permitAll()
                .anyRequest().authenticated() //나머지는 모두 인증필요

        .and()
                //JwtFilter를 addFilterBefore로 등록했던 JwtSecurityConfig 클래스 적용
                .apply(new JwtSecurityConfig());
    }
}
