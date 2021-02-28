package io.securiy.security.mySecurity.config;

import io.securiy.security.mySecurity.provider.CustomAuthenticationProvider;
import io.securiy.security.mySecurity.service.CustomUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

//    /**
//     * 메모리 방식으로
//     * 사용자 추가하기
//     */
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        //패스워드는 암호화 된 방식을 사용
//        String password = passwordEncoder().encode("1111");
//
//        auth.inMemoryAuthentication().withUser("user").password(password).roles("USER");
//        auth.inMemoryAuthentication().withUser("manager").password(password).roles("MANAGER","USER");
//        auth.inMemoryAuthentication().withUser("amdin").password(password).roles("ADMIN","MANAGER","USER");
//    }

    @Autowired
    private CustomUserDetailService customUserDetailService;

    //Bean으로 만들고
    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new CustomAuthenticationProvider();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }



    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                //생량-> 모든 url에 대해
                .authorizeRequests() // 인가 설정
                .antMatchers("/","/users").permitAll() // home은 권한/인증 없이 모든 사용자 접근 가능
                .antMatchers("/mypage").hasRole("USER") // mypage는 USER 권한의 인증된 사용자만 접근 가능
                .antMatchers("/messages").hasRole("MANAGER") // messages는 MANAGER 권한의 인증된 사용자만 접근 가능
                .antMatchers("/config").hasRole("ADMIN") // config는 ADMIN 권환의 인증된 사용자만 접근가능
                .anyRequest().authenticated() // 설정이외 모든요청은 권한과 무관하고 인증된 사용
        .and()
                .formLogin() //인증은form 방식
                .loginPage("/login") // 시큐리티가 로그인 요청하는 url 이는 컨트롤러가 받는다.
                .loginProcessingUrl("/login_proc") // login.html의 form에서 action url
                .defaultSuccessUrl("/") // 로그인 성공 시 이동하는 url
                .permitAll(); //위 "/login"은 인증 필요 없이 접근가능
    }


    @Bean
    protected PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

}
