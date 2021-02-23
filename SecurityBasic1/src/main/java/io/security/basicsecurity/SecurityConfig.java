package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
//                .antMatcher() 생략 : 모든 요청에 대해
                .authorizeRequests() // 권한 보안을 설정
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('SYS') or hasRole('ADMIN')")
                .anyRequest().authenticated(); //이외 모든 요청은 인증(로그인)이 되어야 접근가능
        http // (로그인) 인증은 Form방식으로
                .formLogin();
    }

    /**
     * 사용자를 생성하고 권한을 설정할 수 있는 메소드
     * 메모리상 정보를 이용하거나, JDBC, LDAP등의 정보를 이용해서 인증 처리가 가능
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //메모리 방식으로 사용자 3명 생성
        //1. user
        auth.inMemoryAuthentication()
                .withUser("user")
                .password("{noop}1111") //암호화 방식을 prefix로 설정해야함
                                        // {noop}을 그냥 1111을 그대로 비번으로 사용하겠다는 의미
                                        // -> 추후에는 passwordEncoder 사용
                .roles("USER");
        //2. sys
        auth.inMemoryAuthentication()
                .withUser("sys")
                .password("{noop}1111").roles("SYS","USER");
        //3. admin
        auth.inMemoryAuthentication()
                .withUser("admin")
                .password("{noop}1111").roles("ADMIN","SYS","USER");
    }

}
