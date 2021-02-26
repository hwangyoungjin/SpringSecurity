# SpringSecurity
스프링시큐리티

---
### 순서
```java
1. Spring Security의 보안설정 API와 연계된 각 Filter
2. Spring Security 내부 아키텍처와 각 객체의 역할 및 처리과정
3. Spring Security를 활용한 간단한 Project (아래 4개 사용)
	- Spring Boot
	- Spring MVC
	- Spring Data JPA
	- Thymeleaf
```
1. ### CoreSpringSecurityProject
	1. #### 환경설정
	```java
	1. 인텔리제이
	2. mysql	
	3. jdk 11
	4. maven
	5. springboot 2.4.3
	```

	2. #### 의존성 추가
	```java	
	 - web
	 - thymeleaf
	 - security
	 - springdataJPA
	 - lombok
	 - mysql 
	 - devtools
	 - @configurationproperties 사용을 위해 아래 의존성 추가
	        <dependency>
	            <groupId>org.springframework.boot</groupId>
	            <artifactId>spring-boot-configuration-processor</artifactId>
	        </dependency>
	- modelmapper
	        <dependency>
	            <groupId>org.modelmapper</groupId>
	            <artifactId>modelmapper</artifactId>
	            <version>2.3.9</version>
	            <scope>runtime</scope>
	            <optional>true</optional>
	        </dependency>
	```

	3. #### Mysql 연결
	```java
	mysql의 corespringsecurity 스키마 생성, 'security'이름의 administation 계정 생성 후
	application.properties에 아래 내용 추가
	## MySQL
	# corespringsecurity는 테이블명
	spring.datasource.url=jdbc:mysql://localhost:3306/corespringsecurity?useUnicode=true&useJDBCCompliantTimezoneShift=true&useLegacyDatetimeCode=false&serverTimezone=UTC
	# workbench에서 만든 administration 계정
	spring.datasource.username=security
	# 해당 계정 비번
	spring.datasource.password=!soaka8525
	spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
	```

	4. #### [view 파일 다운로드](https://github.com/onjsdnjs/corespringsecurityfinal)
	
	5. #### SecurityConfig설정
	```java
	1. config설정 
	2. passwordEncoder 빈으로 추가
	3. inMemory로 테스트 계정만들기
	
	@Configuration
	@EnableWebSecurity
	public class SecurityConfig extends WebSecurityConfigurerAdapter {
	    @Override
	    protected void configure(HttpSecurity http) throws Exception {
	        http
	           //.antMatchers("~~") 생략 -> 모든 url에 대해
	                .authorizeRequests() // 인가 설정
	                .antMatchers("/").permitAll() // home은 권한/인증 없이 모든 사용자 접근 가능
	                .antMatchers("/mypage").hasRole("USER") // mypage는 USER 권한의 인증된 사용자만 접근 가능
	                .antMatchers("/messages").hasRole("MANAGER") // messages는 MANAGER 권한의 인증된 사용자만 접근 가능
	                .antMatchers("/config").hasRole("ADMIN") // config는 ADMIN 권환의 인증된 사용자만 접근가능
	                .anyRequest().authenticated() // 설정이외 모든요청은 권한과 무관하고 인증된 사용
	        .and()
	                .formLogin(); //인증은 form 방식
	    }
	
	    /**
	     * 메모리 방식으로
	     * 사용자 추가하기
	     */
	    @Override
	    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	        //패스워드는 암호화 된 방식을 사용
	        String password = passwordEncoder().encode("1111");
	
	        auth.inMemoryAuthentication().withUser("user").password(password).roles("USER");
	        auth.inMemoryAuthentication().withUser("manager").password(password).roles("MANAGER");
	        auth.inMemoryAuthentication().withUser("amdin").password(password).roles("ADMIN");
	    }
	
	    @Bean
	    protected PasswordEncoder passwordEncoder() {
	        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	    }
	}
	```

	6. #### WebIgnore : 보안 필터 없는 ( .js / .css / image )정적리소스 설정
	```java
	    @Override
	    public void configure(WebSecurity web) throws Exception {
	        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
	    }

	   cf.
	public enum StaticResourceLocation {
	    CSS(new String[]{"/css/**"}),
	    JAVA_SCRIPT(new String[]{"/js/**"}),
	    IMAGES(new String[]{"/images/**"}),
	    WEB_JARS(new String[]{"/webjars/**"}),
	    FAVICON(new String[]{"/favicon.*", "/*/icon-*"});
	```

