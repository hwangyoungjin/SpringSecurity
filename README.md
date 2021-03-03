# SpringSecurity
스프링시큐리티

---
### 학습
```java
* Spring Security의 보안설정 API와 연계된 각 Filter 학습
* Spring Security 내부 아키텍처와 각 객체의 역할 및 처리과정 학습
* Spring Security를 활용한 간단한 Project 
	- CoreSpringSecurityProject (Form 인증처리)
	- CoreSpringDBSecurityProject (DB연동 인가처리)
	- SpringSecurityJWT (Tutorial)
```
1. ## CoreSpringSecurityProject (Form 인증처리)
	1. ### 환경설정
	```java
	1. 인텔리제이
	2. mysql	
	3. jdk 11
	4. maven
	5. springboot 2.4.3
	```

	2. ### 의존성 추가
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
	- Entity와 DTO 맵핑을 위해 modelmapper의존성 추가
	        <dependency>
	            <groupId>org.modelmapper</groupId>
	            <artifactId>modelmapper</artifactId>
	            <version>2.3.9</version>
	            <scope>runtime</scope>
	            <optional>true</optional>
	        </dependency>
	```

	3. ### Mysql 연결
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

	4. ### [view 파일 다운로드](https://github.com/onjsdnjs/corespringsecurityfinal)
	
	5. ### Form인증 처리하기
		1. ##### SecurityConfig설정
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
	
		2. ##### WebIgnore : 보안 필터 없는 ( .js / .css / image )정적리소스 설정
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
	
		3. ##### Account와 AccountDto 를 통해 회원가입 만들기
		```java
		1. JpaRepository 상속받아서 UserRepository 생성
		  ===생략===	
	
		2. UserService 인터페이스와 UserServiceImpl 구현
		  ===생략===
			
		3. UserController 구현
		 - Dto객체로 입력값 받고
		 - MoedlMapper를 통해 DTO->Entity 매핑하고
		 - passwordEncoder를 통해 암호화하고
		 - userService로 저장
		    @PostMapping("/users")
		    public String createUser(AccountDto accountDto){
		        //모델맵퍼 사용 : accountDto 정보가 account객체에 담김
		        ModelMapper modelMapper = new ModelMapper();
		        Account account = modelMapper.map(accountDto, Account.class);
		        account.setPassword(passwordEncoder.encode(account.getPassword()));
		        userService.createUser(account);
		        return "redirect:/";
		    }
		 - 이외 GetMapping은 생략
	
		* Applicatgino.properties의 
		spring.jpa.hibernate.ddl-auto=create 설정을 통해 
		DB에 따로 테이블 안만들어도 JPA가 자동으로 @Entity붙은 Account 테이블 만들어준다. 
		```
		
		4. ##### UserDetailsService 커스텀 ( + UserDetails 커스텀)
		```java
		1. config의 인메모리방식 삭제
		2. UserDetails의 구현체인 User클래스 상속받기
		 public class AccountContext extends User {
		     /**
		      * 나중에 필요시 참조할 수 있도록
		      */
		     private final Account account;
		
		     //생성자에서 id/pw가 아닌 account 객체로 받기
		     public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {
		         super(account.getUsername(), account.getPassword(), authorities);
		         this.account = account;
		     }
		 }
		3. UserDetailsService 구현하기 
		    @Service //빈으로 등록해야한다.
		    public class CustomUserDetailService implements UserDetailsService {
		    
		        @Autowired
		        private UserRepository userRepository;
		    
		        @Override
		        public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
		    
		            Account account = userRepository.findByUsername(s);
		    
		            //null인경우
		            if(account == null){
		                throw new UsernameNotFoundException("UsernameNotFoundException");
		            }
		    
		            //권한 설정
		            List<GrantedAuthority> roles = new ArrayList<>();
		            roles.add(new SimpleGrantedAuthority(account.getRole()));
		    
		            AccountContext accountContext = new AccountContext(account,roles);
		    
		            return accountContext;
		        }
		    }
		4. config를 통해 시큐리티에서 내가만든 CustomUserDetailsService 사용하도록 설정
		    @Autowired
		    private CustomUserDetailService customUserDetailService;
	
		    @Override
		    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		        auth.userDetailsService(customUserDetailService);
		    }
		```
	
		5. ##### AuthenticationProvider 커스텀
		```java
		* AuthenticationProvider 구현시 2개의 메소드를 구현해야한다.
	
			public class CustomAuthenticationProvider implements AuthenticationProvider {
		        @Autowired
		        private CustomUserDetailService customUserDetailService;
		    
		        @Autowired
		        private PasswordEncoder passwordEncoder;
		    
		        @Override
		        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		            String username = authentication.getName(); // 인증전 사용자가 입력한 id
		            String password = (String)authentication.getCredentials(); // 인증전 사용자가 입력한 pw
	    	
	    	        //인증된 UserDetails 타입의 AccountContext 객체
	    	        AccountContext accountContext = (AccountContext) customUserDetailService.loadUserByUsername(username);
	    	
	    	        if(!passwordEncoder.matches(password,accountContext.getPassword())){
	    	            throw  new BadCredentialsException("BadCredentialsException");
	    	        }
	    		
	    	        //인증된 account 객체, pw는 null처리,
	    	        UsernamePasswordAuthenticationToken authenticationToken =
	    	                new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null,accountContext.getAuthorities());
    		
    		        return authenticationToken;
    		    }
    		
    		    @Override
    		    public boolean supports(Class<?> aClass) {
    		        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(aClass);
    		    }
    		}
	
		* 내가만든 CustomProvider를 스프링시큐리티가 사용할 수 있도록 설정	
		    //Bean으로 만들고
		    @Bean
		    public AuthenticationProvider authenticationProvider() {
		        return new CustomAuthenticationProvider();
		    }
		
		    @Override
		    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		        auth.authenticationProvider(authenticationProvider());
		    }
		```
		
		6. ##### 로그인 설정
		```java
		1. login.html 설정
		  == 생략 ==
		2. config 클래스의 config 메소드 내용 추가
		    {
		       http
		                .formLogin() //인증은form 방식
		                .loginPage("/login") // 시큐리티가 로그인 요청하는 url, 이는 컨트롤러가 받는다.
	            		    .loginProcessingUrl("/login_proc") // login.html의 form에서 action url
	             	   .defaultSuccessUrl("/") // 로그인 성공 시 이동하는 url
	             		   .permitAll(); //위 "/login"은 인증 필요 없이 접근가능
		    }
		
		3. controller에서 .loginpage("/login") 요청 받아서 처리
		@GetMapping("/login")
		public String login() throws Exception {
			return "login";
		}
		```
	
		7. ##### Security의 LogoutFilter 사용안하고 로그아웃 설정
		```java
		* <form>에서 POST로 "/logout" 요청시 시큐리티 로그아웃필터 자동 적용
		* <a>에서 GET방식으로 요청시 자동으로 필터 적용X -> Controller에서 코드 추가 필요
		
		1. 의존성 추가
		        <dependency>
		            <groupId>org.thymeleaf.extras</groupId>
		            <artifactId>thymeleaf-extras-springsecurity5</artifactId>
		        </dependency>
		2. html 태그의 
		    xmlns:sec="http://www.thymeleaf.org/thymeleaf-extras-springsecurity5"> 추가
		3. view에서 isAnonymous(), isAuthenticated() 사용
		    <li class="nav-item" sec:authorize="isAnonymous()"><a class="nav-link text-light" th:href="@{/users}">회원가입</a></li>
	                 <li class="nav-item" sec:authorize="isAuthenticated()"><a class="nav-link text-light" th:href="@{/logout}">로그아웃</a></li>
		   
		4. <a>태그의 get 요청 처리할 Controller ->필터가 적용안되고 해당 컨트롤러가 /logout 처리함
		    @GetMapping("/logout")
		    public String logout(HttpServletRequest request, HttpServletResponse response) throws Exception{
		
		        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		
		        //자동으로 필터작동 될때 Logout 필터에서 해당 부분을 사용해서 logout한다.
		        if(authentication != null){
		            new SecurityContextLogoutHandler().logout(request,response,authentication);
		        }
		
		        return "redirect:/login";
		    }
		
		```
2. ## CoreSpringDBSecurityProject (DB 연동 인가처리)
	1. ### 환경설정
	```java
	1. 인텔리제이
	2. mysql	
	3. jdk 11
	4. maven
	5. springboot 2.4.3
	```

	2. ### 의존성 추가
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
	- Entity와 DTO 맵핑을 위해 modelmapper의존성 추가
	        <dependency>
	            <groupId>org.modelmapper</groupId>
	            <artifactId>modelmapper</artifactId>
	            <version>2.3.9</version>
	        </dependency>
	```

	3. ### Mysql 연결
	```java
	mysql의 dbsecurity 스키마 생성, 'dbsecurity'이름의 administation 계정 생성 후
	application.properties에 아래 내용 추가
	## MySQL
	# dbsecurity는 테이블명
	spring.datasource.url=jdbc:mysql://localhost:3306/dbsecurity?useUnicode=true&useJDBCCompliantTimezoneShift=true&useLegacyDatetimeCode=false&serverTimezone=UTC
	# workbench에서 만든 administration 계정
	spring.datasource.username=dbsecurity
	# 해당 계정 비번
	spring.datasource.password=!soaka8525
	spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
	```

	4. ### [view 파일 다운로드](https://github.com/onjsdnjs/corespringsecurityfinal)
	
	5. ### ERD, RDB, DCD 을 바탕으로 domain 설정 (Entity+DTO)
	- <img src="https://user-images.githubusercontent.com/60174144/109475588-3f089e80-7ab9-11eb-971a-9ad61e3586c1.png" width="50%" height="50%">
	- <img src="https://user-images.githubusercontent.com/60174144/109475834-84c56700-7ab9-11eb-9e44-73cd27b10daf.png" width="50%" height="50%">
	- <img src="https://user-images.githubusercontent.com/60174144/109475935-a6bee980-7ab9-11eb-948f-7560cb3419c5.png" width="50%" height="50%">

3. ## SpringSecurityJWT Tutorial
	1. ### JWT (Json Web Token)
	```java
	* JWT : JSON 객체를 사용해서 토큰 자체에 정보들을 저장하고 있는 WebToken
	
	* Header, Payload, Signature 3개의 부분을 구성
	  1. Header는 Signature를 해싱하기 위한 알고리즘 정보들이 담겨있다.
	  2. Payload는 서버와 클라이언트가 주고받는, 시스템에서 실제로 사용될 정보에 대한 내용을 담고있다.
	  3. Signature는 토큰의 유효성 검증을 위한 문자열
	     -> 이 문자열을 통해 서버에서 해당 토큰이 유효한 토큰인지를 검증할 수 있다.

	* JWT의 장점
	  1. 중앙의 인증서버, 데이터스토어에 대한 의존성X
	     -> 시스템 수평 확장이 유리
	  2. Base64 URL Safe Encoding
	     -> URL, Cookie, Header 모두 사용가능 [범용성]
	    
	* JWT의 장점
	  1. Payload의 정보가 많아지면 네트워크 사용량이 증가
	     -> 데이터 설계 고려가 필요하다
	  2. 토큰이 클라이언트에 저장
	     -> 서버에서 클라이언트의 토큰을 조작할 수 없다.
	```
	2. ### Security설정, Data설정
	```java
	* 환경설정
	  - spring
	  - gradle
	  - jdk 11
	
	* 의존성
	  - Web
	  - Spring security
	  - Spring data JPA
	  - H2
	  - Lombok : 프로젝트 설정에서 AnnotationProcessors 을 Enable annotation processing 체크
	  - Validation
	```

	3. ### JWT 코드, Security 설정 추가
		1. #### 기본 RestController로 api 요청시 401 unauthorized 에러 발생
		```java
		@RestController
		@RequestMapping("/api")
		public class HelloController {
		    @GetMapping("/hello")
		    public ResponseEntity<String> hello(){
		        return ResponseEntity.ok("hello");
		    }
		}
		```

		2. #### 401 unauthorized 해결을 위한 SecurityConfig 설정
		```java
		* 기본 SecurityConfig 설정
		@EnableWebSecurity
		public class SecurityConfig extends WebSecurityConfigurerAdapter {
		    @Override
		    protected void configure(HttpSecurity http) throws Exception {
		        http
		                .authorizeRequests() // 모든 요청의 보안설정
		                .antMatchers("/api/hello").permitAll() //해당 url은 허가
		                .anyRequest().authenticated(); //나머지는 모두 인증필요
		    }
		}
		```

		3. #### 인메모리, Datasource, JPA 설정
		```java
		* application.properties 설정

		# h2 콘솔 인메모리로 사용 설정
		spring.h2.console.enabled=true
		spring.datasource.url= jdbc:h2:mem:testdb
		spring.datasource.username=sa
		spring.datasource.password=
		spring.datasource.driver-class-name=org.h2.Driver

		spring.jpa.database-platform=org.hibernate.dialect.H2Dialect

		# SeesionFactory가 시작될때 Drop->Create->Alter, 종료될때 Drop
		spring.jpa.hibernate.ddl-auto=create-drop

		# Query 편하게 보기
		spring.jpa.show-sql=true
		spring.jpa.properties.hibernate.format_sql=true
		spring.jpa.properties.hibernate.default_batch_fetch_size=100
		logging.level.org.hibernate.type.descriptor.sql=trace
		```

		4. #### RDB 기반 Entity 생성
		- <img src="https://user-images.githubusercontent.com/60174144/109839389-66fb2c00-7c8a-11eb-8d86-57caafa6c62a.png" width="70%" height="70%">

		5. #### H2-Console 접근 가능하도록 SecurityConfig 설정
		```java
		    @Override
		    public void configure(WebSecurity web) throws Exception {
		        web
		                .ignoring()
		                .antMatchers(
		                        "/h2-console/**",
		                        "/favicon.ico"
		                );
		    }
		```

		6. #### init Data 설정
		```java
		* resource 안 data.sql 파일 추가
		* Spring Boot는 시작될때 root classpath location에 위치한 
		  schema.sql, data.sql 파일의 내용들을 수행하게 되어 있다.
		
		/*data.sql*/
		INSERT INTO ACCOUNT (ID, USERNAME,PASSWORD,NICKNAME,ACTIVATED)
		 VALUES (1, 'admin', '123123','YOUNG',1);

		INSERT INTO AUTHORITY (ID, AUTHORITY_NAME) VALUES (1,'ROLE_USER');
		INSERT INTO AUTHORITY (ID, AUTHORITY_NAME) VALUES (2,'ROLE_ADMIN');

		INSERT INTO ACCOUNT_AUTHORITY (ACCOUNT_ID,AUTHORITY_ID) VALUES (1,1);
		INSERT INTO ACCOUNT_AUTHORITY (ACCOUNT_ID,AUTHORITY_ID) VALUES (1,2);
		```		

		7. #### H2 Console 결과 확인
		- <img src="https://user-images.githubusercontent.com/60174144/109839977-faccf800-7c8a-11eb-965c-4727b76c7d56.png" width="50%" height="50%">


	4. ### DTO, Repository 로그인

	5. ### 회원가입, 권한 인증


