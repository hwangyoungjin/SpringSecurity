package net.codejava;


import net.codejava.api.CustomApiUrlAuthenticationSuccessHandler;
import net.codejava.api.CustomUsernamePasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.Filter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private UserServices userServices;

	@Autowired
	private CustomUrlAuthenticationSuccessHandler customUrlAuthenticationSuccessHandler;

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	/**
	 * 내가만든 UserDetailsService 클래스 사용하기
	 */
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userServices);
	}

//	@Override
//	protected void configure(HttpSecurity http) throws Exception {
//		http.authorizeRequests()
//			.antMatchers("/users").authenticated()
//			.anyRequest().permitAll()
//			.and()
//			.formLogin()
//				.usernameParameter("email")
//				.defaultSuccessUrl("/")
//				.successHandler(customUrlAuthenticationSuccessHandler)
//				.permitAll()
//			.and()
//			.logout().logoutSuccessUrl("/").permitAll();
//	}

	@Autowired
	CustomApiUrlAuthenticationSuccessHandler customApiUrlAuthenticationSuccessHandler;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		http.authorizeRequests()
				.antMatchers("/api/login").permitAll();
		http.formLogin().disable();
		http.logout().logoutSuccessUrl("/").permitAll();

		//새로구현한 filter 등록
		http.addFilter(getAuthenticationFilter());
	}

	private CustomUsernamePasswordAuthenticationFilter getAuthenticationFilter() {
		CustomUsernamePasswordAuthenticationFilter authFilter
				= new CustomUsernamePasswordAuthenticationFilter();
		try{
			//해당 필터는 "/api/login" 요청 들어올때 실행
			authFilter.setFilterProcessesUrl("/api/login");
			authFilter.setAuthenticationManager(this.authenticationManagerBean());
			authFilter.setUsernameParameter("email");
			authFilter.setPasswordParameter("password");
			//로그인 성공시 실행되는 핸들러
			authFilter.setAuthenticationSuccessHandler(customApiUrlAuthenticationSuccessHandler);

		}catch(Exception e){
			e.printStackTrace();
		}
		return authFilter;
	}
}
