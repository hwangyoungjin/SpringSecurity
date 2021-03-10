# SpringSecurity
스프링시큐리티

---
## 학습
1. ### Spring Security의 보안설정 API와 연계된 각 Filter 학습
2. ### Spring Security 내부 아키텍처와 각 객체의 역할 및 처리과정 학습
3. ### Spring Security를 활용한 간단한 Project 
	- #### [CoreSpringSecurityProject (Form 인증처리)](https://github.com/hwangyoungjin/SpringSecurity#corespringsecurityproject-form-%EC%9D%B8%EC%A6%9D%EC%B2%98%EB%A6%AC)
	- #### [CoreSpringDBSecurityProject (DB연동 인가처리)](https://github.com/hwangyoungjin/SpringSecurity#corespringdbsecurityproject-db-%EC%97%B0%EB%8F%99-%EC%9D%B8%EA%B0%80%EC%B2%98%EB%A6%AC)
	- #### [SpringSecurityJWT (Tutorial)](https://github.com/hwangyoungjin/SpringSecurity#springsecurityjwt-tutorial)
	- #### [SpringBootEmailVerification](https://github.com/hwangyoungjin/SpringSecurity#SpringBootEmailVerification)

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
	```properties
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
	```properties
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
		```properties
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

		5. #### H2-Console 접근 가능하도록 SecurityConfig WebIgnore 설정
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
		/*password는 passwordEncode.encoder("123123")의 값이다.*/
		INSERT INTO ACCOUNT (ID, USERNAME,PASSWORD,NICKNAME,ACTIVATED)
		 VALUES (1, 'admin', '$2a$10$w3jqc54wmRtvfrvcvdG6SuclMZVg7uvhZvhH4nRo0/MaKWj2CWkHm','YOUNG',1);

		INSERT INTO AUTHORITY (ID, AUTHORITY_NAME) VALUES (1,'ROLE_USER');
		INSERT INTO AUTHORITY (ID, AUTHORITY_NAME) VALUES (2,'ROLE_ADMIN');

		INSERT INTO ACCOUNT_AUTHORITY (ACCOUNT_ID,AUTHORITY_ID) VALUES (1,1);
		INSERT INTO ACCOUNT_AUTHORITY (ACCOUNT_ID,AUTHORITY_ID) VALUES (1,2);
		```		

		7. #### H2 Console 결과 확인
		- <img src="https://user-images.githubusercontent.com/60174144/109839977-faccf800-7c8a-11eb-965c-4727b76c7d56.png" width="50%" height="50%">

	3. ### JWT설정, JWT관련코드, Security 설정 추가
		1. jwt관련 라이브러리 추가
		```java
		    compile group: 'io.jsonwebtoken',name:'jjwt-api',version:'0.11.2'
		    runtime group: 'io.jsonwebtoken',name:'jjwt-impl',version:'0.11.2'
		    runtime group: 'io.jsonwebtoken',name:'jjwt-jackson',version:'0.11.2'		
		``` 

		2. #### application.propertiest의 내용추가
		```properties
		* H2 알고리즘 사용하기 떄문에 SecretKey는 64Byte 이상되어야 한다.

		#JWT 설정
		jwt.header=Authorization
		#spring-framework-springboot-security-jwt-tutorial-hwang-young-jin을 온라인에서 Base64으로 인코딩
		jwt.secret=c3ByaW5nLWZyYW1ld29yay1zcHJpbmdib290LXNlY3VyaXR5LWp3dC10dXRvcmlhbA==
		#토큰만료시간
		jwt.token-validity-in-seconds=86400
		```

		3. #### 토큰생성,  토킁의 유효성 검증한 TokenProvider 생성
		```java
		@Component
		public class TokenProvider implements InitializingBean {

		    private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

		    private static final String AUTHORITIES_KEY = "auth";
		
		    private final String secret;

		    private final long tokenValidityInMilliseconds;

		    private Key key;

		    /**
		     * SpEL 사용해서 properties 값 불러오기
		     */
		    public TokenProvider(
		            @Value("${jwt.secret}") String secret,
		            @Value("${jwt.token-validity-in-seconds}") long tokenValidityInMilliseconds) {
		        this.secret = secret;
		        this.tokenValidityInMilliseconds = tokenValidityInMilliseconds * 1000;
		    }

		    @Override
		    public void afterPropertiesSet() throws Exception {
		        //Secret값 디코딩해서 key변수에 할당
		        byte[] keyBytes = Decoders.BASE64.decode(secret);
		        this.key = Keys.hmacShaKeyFor(keyBytes);
		    }
		
		    /**
		     * 인증받은 객체의 권한 정보를 추가해서 토큰생성
		     */
		    public String createToken(Authentication authentication) {
		        //권한 뺴오기
		        String authorities = authentication.getAuthorities().stream()
		                .map(GrantedAuthority::getAuthority)
		                .collect(Collectors.joining(","));

		        //만료시간 설정
		        long now = (new Date()).getTime();
		        Date validity = new Date(now + this.tokenValidityInMilliseconds);
		
		        //jwt 토큰 생성해서 리턴
		        return Jwts.builder()
		                .setSubject(authentication.getName())
		                .claim(AUTHORITIES_KEY, authorities)
		                .signWith(key, SignatureAlgorithm.HS512)
		                .setExpiration(validity)
		                .compact();
		    }

		    /**
		     * 토큰을 받아 토큰에 담겨있는 정보를 이용해
		     * 인증된 Authentication타입 객체를 리턴
		     */
		    public Authentication getAuthentication(String token) {
		        Claims claims = Jwts
		                .parserBuilder()
		                .setSigningKey(key)
		                .build()
		                .parseClaimsJws(token)
		                .getBody();

		        Collection<? extends GrantedAuthority> authorities =
		                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
		                        .map(SimpleGrantedAuthority::new)
		                        .collect(Collectors.toList());
		
		        User principal = new User(claims.getSubject(), "", authorities);
		
		        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
		    }

		    /**
		     * 토큰의 유효성 검증을 수행
		     */
		    public boolean validateToken(String token){
		        try{
		            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
		            return true;
		        } catch (io.jsonwebtoken.security.SignatureException | MalformedJwtException e){
		            logger.info("잘못된 JWT 서명입니다.");
		        } catch (ExpiredJwtException e){
		            logger.info("만료된 JWT 토큰입니다.");
		        } catch (UnsupportedJwtException e){
		            logger.info("지원되지 않는 JWT 토큰입니다.");
		        } catch (IllegalArgumentException e){
		            logger.info("JWT 토큰이 잘못되었니다.");
		        }
		        return false;
		    }
		```

		4. #### JWT를 위한 커스텀 필터 생성
		```java
		@RequiredArgsConstructor
		public class JwtFilter extends GenericFilterBean {
		
		    private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);
		
		    public static final String AUTHORICATION_HEADER = "Authorization";
		
		    private final TokenProvider tokenProvider;


		    /**
		     * 토큰의 인증정보를 SecurityContext에 저장하는 역할 수행
		     */
		    @Override
		    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
		            throws IOException, ServletException {
		        //request에서 토큰받아
		        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
		        String jwt = resolveToken(httpServletRequest);
		        String requestURI = httpServletRequest.getRequestURI();

		        // 해당 토큰 유효성 검사 후 정상이면 SecurityContext에 Authentication 객체 저장장
		       if(StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)){
		            Authentication authentication = tokenProvider.getAuthentication(jwt);
		            SecurityContextHolder.getContext().setAuthentication(authentication);
		            logger.debug("Securty Contextdp '{}' 인증 벙보를 저장했습니다. uri: {}",authentication.getName(), requestURI);
		        } else {
		            logger.debug("유효한 JWT 토큰이 없습니다. uri: {}", requestURI);
		        }
		
		        chain.doFilter(request,response);
		    }
		
		    /**
		     * Request Header에서 토큰정보 꺼내오기
		     */
		    private String resolveToken(HttpServletRequest request) {
		        String bearerToken = request.getHeader(AUTHORICATION_HEADER);
		        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
		            return bearerToken.substring(7);
		        }
		        return null;
		    }
		}
		```

		5. #### 만든 Provider, Filter를 SecurityConfig에 적용할때 사용할 JwtSecurityConfig 클래스 생성
		```java
		* SecurityConfigurerAdapter를 extends하고 TokenProvider를 주입받아서
		  JwtFilter를 통해 Security로직에 필터를 등록하는 역할
		* JwtFilter는 UsernamePasswordAuthenticationFilter 보다 한단계 먼저 실행된다.

		@RequiredArgsConstructor
		public class JwtSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

		    private TokenProvider tokenProvider;

		    @Override
		    public void configure(HttpSecurity builder) throws Exception {
		        JwtFilter customFilter = new JwtFilter(tokenProvider);
		        builder.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
		    }
		}
		```

		6. #### 유요한 자격 없이 접근할때 401 Unauthorized 에러를 리턴 할 클래스 생성 
		```java
		* 해당 클래스는 ExceptionTranslationFilter가 사용
		
		@Component
		public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
		
		    @Override
		    public void commence(HttpServletRequest request,
		                         HttpServletResponse response,
		                         AuthenticationException authException)
		            throws IOException, ServletException {
			//401 Unauthorized 에러를 보낸다.
		        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
		    }
		}
		```

		7. #### 필요한 권한이 존재하지 않는 경우에 403 Forbidden 에러를 리턴할 클래스 생성
		```java
		* 해당 클래스는 ExceptionTranslationFilter가 사용

		@Component
		public class JwtAccessDeniedHandler implements AccessDeniedHandler {
		    @Override
		    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
		        response.sendError(HttpServletResponse.SC_FORBIDDEN);
		    }
		}
		```

		8. #### 지금까지 만든 클래스 SecurityConfig에 적용
		```java

		@EnableWebSecurity
		@RequiredArgsConstructor
		//메소드 인가방식의 @PreAuthorize 어노테이션을 추가하기위하여 적용
		@EnableGlobalMethodSecurity(prePostEnabled = true)
		public class SecurityConfig extends WebSecurityConfigurerAdapter {

		    private final TokenProvider tokenProvider;
		    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
		    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

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
		                .apply(new JwtSecurityConfig(tokenProvider));
		    }
		}
		```

		9. #### WeakKey에러
		```properties
		* properties의 secret 값을 길게 했더니 성공
		#1111에서 spring-framework-springboot-security-jwt-tutorial-hwang-young-jin으로 변경 (온라인에서 Base64으로 인코딩)
		jwt.secret=c3ByaW5nLWZyYW1ld29yay1zcHJpbmdib290LXNlY3VyaXR5LWp3dC10dXRvcmlhbC1od2FuZy15b3VuZy1qaW4=
		```

	4. ### DTO, Repository 로그인 
		1. #### 외부와의 통신에 사용할 DTO 클래스 생성
		```java
		* 로그인시 사용할 LoginDto
		* 토큰 정보 Response할때 사용할 TokenDto
		* 회원가입시 사용할 AccountDto
		```

		2. #### Repository 관련 코드 생성
		```java
		public interface AccountRepository extends JpaRepository<Account,Long> {

		    /**
		     * EntitiyGraph는 쿼리 수행될때 LAZY조회가 아닌 EAGER조회로 수행
		     * username에 해당하는 account를 가져올때 Authorities도 같이 가져온다
		     */
		    @EntityGraph(attributePaths = "authorities")
		    Optional<Account> findOneWithAuthoritiesByUsername(String username);
		}
		```

		```java
		* Provider의 authenticate(authentication) 메소드에 의해 실행되는 3가지 검증
		1. ID검증 - UserDetailsService의 loadUserByUsername 메소드 실행된다.
		2. PW검증 - passwordEncoder.match() 를 통해 입력pw와 DB객체의 pw비교 - DaoAuthenticationProvider 에서 실행됨
		3. 추가 검증
		```

		3. #### UserDetailsService 커스텀
		```java

		@Service("UserDetailsService")
		@RequiredArgsConstructor
		public class CustomUserDetailsService implements UserDetailsService {
		
		    private final AccountRepository accountRepository;

		    @Override
		    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		        //DB에서 username에 해당하는 account객체 가져오고
		        return accountRepository.findOneWithAuthoritiesByUsername(username)
		                // 해당 객체를 UserDetails 인터페이스의 구현체인 User타입으로 변환
		                // 변환은 createAccount 메소드 사용
		                .map(account -> createAccount(username,account))
		                .orElseThrow(()-> new UsernameNotFoundException(
		                                username+" -> DB에 존재하지 않습니다."));
		    }

		    /**
		     * username과 Account객체를 받아
		     * Security가 지원하는 UserDetails의 구현체인
		     * User 타입 객체 반환하는 메소드
		     */
		    private User createAccount(String username, Account account) {
		        if(!account.isActivated()){
		            throw new RuntimeException(username + " -> 활성화되어 있지 않습니다.");
		        }

		        //활성화 상태인 경우 권한 정보 가져와서
		        List<GrantedAuthority> grantedAuthorityList
		                = account.getAuthorities().stream()
		                .map(authority -> new SimpleGrantedAuthority(authority.getAuthorityName()))
		                .collect(Collectors.toList());

		        //id,pw,권한정보 저장한 User 객체 반환
		        return new User(account.getUsername(),account.getPassword(),grantedAuthorityList);
		    }
		}
		```
		4. #### 로그인 API, 관련 로직 Controller 생성
		```java
		@RestController
		@RequestMapping("/api")
		@RequiredArgsConstructor
		public class AuthController {

		    private final TokenProvider tokenProvider;
		    private final AuthenticationManagerBuilder authenticationManagerBuilder;
		
		    @PostMapping("/authenticate")
		    public ResponseEntity<TokenDto> authorize(
		            @Valid @RequestBody LoginDto loginDto){
		        //파라미터로 받은 id와 pw로 토큰 생성
		        UsernamePasswordAuthenticationToken authenticationToken =
		                new UsernamePasswordAuthenticationToken(loginDto.getUsername(),loginDto.getPassword());
		
		        //authenticate(authenticationToken) 실행될 때
		        //UserDetailsService의 loadUserByUsername 메소드 실행된다.
		        //이후 인증의 성공하면 Account객체와 권한정보 담긴 UserDetails 타입의 구현체 리턴 받는다.
		        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
		
		        //리턴 받았다는것은 인증에 성공한것이므로 Context의 Authentication 객체 저장
		        SecurityContextHolder.getContext().setAuthentication(authentication);
		
		        //Authentication 객체 정보를 통해 jwt Token 생성
		        String jwt = tokenProvider.createToken(authentication);
		
		        HttpHeaders httpHeaders = new HttpHeaders();

		        //JWT 토큰을 Response Header에 넣고
		        httpHeaders.add(JwtFilter.AUTHORICATION_HEADER, "Beaer "+jwt);

		        //TokenDto를 이용하여서 넣어주고 그것을 Response Body에 넣어서 리턴
		       return new ResponseEntity<>(new TokenDto(jwt), httpHeaders, HttpStatus.OK);
		    }
		}
		```

		5. #### postMan으로 테스트
		- <img src="https://user-images.githubusercontent.com/60174144/109982283-1b598880-7d45-11eb-9f76-8657e82b3a7e.png" width="70%" height="70%">

	5. ### 회원가입, 권한 인증
		```JAVA
		* 추후 추가 예정
		```

1. ## SpringBootEmailVerificationt [Email 인증처리](https://www.codejava.net/frameworks/spring-boot/email-verification-example)
	1. ### 환경설정
	```xml
	* springboot 2.3.4
	* maven
	* jdk 11
	* spring-data-jpa
	* spring-security
	* thymeleaf
	* web
	* devtools
	* lombok
	* mysql
	* bootstrap
	```
	2. ### 이메일 의존성추가
	```xml
	<!--스프링부트는 추가빈 선언 필요 없음 -->
	<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-mail</artifactId>
	</dependency>
	```
	3. ### view파일추가
	```java
	0. login,logout 화면은 springSecurity에서 제공하는 화면 사용
	1. index.html
	2. register_success.html - 가입성공화면으로 이메일 인증후 login 화면으로
	3. signup_form.html - 가입화면
	4. users.html - 인증된 사용자에게만 접근가능
	5. verify_fail.html - 메일인증 실패시 return
	6. verify_success.html - 메일인증 성공시 return
	```
	4. ### application.properties 설정
	```properties
	# mysql 연결
	spring.jpa.hibernate.ddl-auto=create-drop
	spring.datasource.url=jdbc:mysql://localhost:3306/emailverification?useUnicode=true&useJDBCCompliantTimezoneShift=true&useLegacyDatetimeCode=false&serverTimezone=UTC
	spring.datasource.username=root
	spring.datasource.password= 생략
	spring.jpa.properties.hibernate.format_sql=true

	# 구글 이메일 인증사용
	spring.mail.host=smtp.gmail.com
	spring.mail.port=587
	# username과 password는 이메일을 보낼때 보낸이가 된다.
	# SMTP를 사용할 수 있도록 허용해야 한다
	# 브라우저에서 메일 발송자가 될 구글 계정에 접속하시고 아래 URL을 클릭
	# https://myaccount.google.com/lesssecureapps
	spring.mail.username=yohoee770@gmail.com
	spring.mail.password=생략
	spring.mail.properties.mail.smtp.auth=true
	spring.mail.properties.mail.smtp.starttls.enable=true
	```
	5. ### Entitiy
	```java
	@Entity
	@Table(name = "users")
	@Getter @Setter
	@NoArgsConstructor
	public class User {
		
		@Id
		@GeneratedValue(strategy = GenerationType.IDENTITY)
		private Long id;
		
		@Column(nullable = false, unique = true, length = 45)
		private String email;
		
		@Column(nullable = false, length = 64)
		private String password;
		
		@Column(name = "first_name", nullable = false, length = 20)
		private String firstName;
		
		@Column(name = "last_name", nullable = false, length = 20)
		private String lastName;
		
		/**
		* 인증의 사용할 String 코드값
		*/
		@Column(name = "verification_code", length = 64)
		private String verificationCode;
		
		private boolean enabled;
		
	}
	```
	6. ### Repository
	```java
	public interface UserRepository extends JpaRepository<User, Long> {
		@Query("SELECT u FROM User u WHERE u.email = ?1")
		public User findByEmail(String email);
	
		@Query("SELECT u FROM User u WHERE u.verificationCode = ?1")
		public User findByVerificationCode(String code);
	}
	```

	7. ### UserDetails의 구현체인 User 객체 상속받아 구현
	```java
	@Data
	public class CustomUserDetails extends org.springframework.security.core.userdetails.User {

		private User user;

		public CustomUserDetails(User myUser,
								Collection<? extends GrantedAuthority> authorities) {
			super(myUser.getFirstName(), myUser.getPassword(), authorities);
			this.user = myUser;
		}

		public String getFullName() {
			return user.getFirstName() + " " + user.getLastName();
		}
	}
	```

	8. ### UserDetailsService 상속받아 구현
	```java
	@Service
	public class UserServices implements UserDetailsService {

		
		@Autowired
		private PasswordEncoder passwordEncoder;
		
		@Autowired
		private JavaMailSender mailSender;

		@Autowired
		private UserRepository userRepository;

		/**
		* 모든 User 조회
		*/
		public List<User> listAll() {
			return userRepository.findAll();
		}

		/**
		* 가입 요청시 실행되는 메소드로 이메일을 발송요청
		* 이용은 불가하나 DB에 저장된다.
		*/
		public void register(User user, String siteURL) 
				throws UnsupportedEncodingException, MessagingException {
			//패스워드 암호
			String encodedPassword = passwordEncoder.encode(user.getPassword());
			user.setPassword(encodedPassword);

			//랜덤코드
			String randomCode = RandomString.make(64);
			user.setVerificationCode(randomCode);

			//아직 이용 불가
			user.setEnabled(false);

			//DB에 저장
			userRepository.save(user);

			//메일보내기
			sendVerificationEmail(user, siteURL);
		}


		/**
		* 실질적으로 이메일을 발송시키는 메소드
		*/
		private void sendVerificationEmail(User user, String siteURL) 
				throws MessagingException, UnsupportedEncodingException {
			String toAddress = user.getEmail(); //수신자 이메일
			String fromAddress = "yohoee770"; //발신자 이메일
			String senderName = "hicompany"; //발신자 이름
			String subject = "Please verify your registration"; // 메일 제목
			String content = "Dear [[name]],<br>" //메일내용
					+ "Please click the link below to verify your registration:<br>"
					+ "<h3><a href=\"[[URL]]\" target=\"_self\">VERIFY</a></h3>"
					+ "Thank you,<br>"
					+ "Your company name.";
			
			// 메일 보내기위해 필요한 객체
			MimeMessage message = mailSender.createMimeMessage();
			MimeMessageHelper helper = new MimeMessageHelper(message,"utf-8");
			
			// 메일 발신자 정보(주소,이름)와 수신자메일주소, 메일제목 담기
			helper.setFrom(fromAddress, senderName);
			helper.setTo(toAddress);
			helper.setSubject(subject);
			
			// html 내용 replace
			content = content.replace("[[name]]", user.getLastName());
			String verifyURL = siteURL + "/verify?code=" + user.getVerificationCode();
			content = content.replace("[[URL]]", verifyURL);
			
			//본문 담기, true는 html 형식으로 보내겠다는 의미
			helper.setText(content, true);
			
			//메일 발송
			mailSender.send(message);
			
			System.out.println("Email has been sent");
		}

		/**
		* 인증 코드 받아서 db와 비교
		*/
		public boolean verify(String verificationCode) {
			User user = userRepository.findByVerificationCode(verificationCode);

			//db의 없는 계정 or 해당 user가 이미 승인받은경우 false return
			if (user == null || user.isEnabled()) {
				return false;
			} else {

				//인증되었으니 Enable true
				//기존 verificationCode null
				user.setVerificationCode(null);
				user.setEnabled(true);
				//업데이트
				userRepository.save(user);
				return true;
			}
		}

		/**
	 	* 로그인시 실행되는 메소드
	 	*/
		@Override
		public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
			User user = userRepository.findByEmail(username);
			if (user == null) {
				throw new UsernameNotFoundException("User not found");
			}

			//해당프로젝트에서 roles은 설정 안했으므로 null
			List<GrantedAuthority> roles = new ArrayList<>();
			roles.add(new SimpleGrantedAuthority("null"));

			return new CustomUserDetails(user,roles);
		}
	}
	```

	9. ### Controller 구현
	```java
	@Controller
	public class AppController {

		@Autowired
		private UserServices service;
		
		@GetMapping("")
		public String viewHomePage() {
			return "index";
		}

		/**
		* 맨처음 가입 요청시 실행
		*/
		@GetMapping("/register")
		public String showRegistrationForm(Model model) {
			model.addAttribute("user", new User());
			return "signup_form";
		}

		/**
		* 처음 가입 요청을 했던 사용자가 가입 내용을 적고 form 요청을 했을때 실행
		*/
		@PostMapping("/process_register")
		public String processRegister(User user, HttpServletRequest request) 
				throws UnsupportedEncodingException, MessagingException {
			service.register(user, getSiteURL(request));		
			return "register_success";
		}

		/**
		* 로그인시 실행되는 processRegister 핸들러에 의해 실행되며
		* path()를 return 한다
		* 해당 path는 이메일 버튼의 path로 들어간다.
		* sendmail에서 버튼 url은 path의 verify + User의 VerificationCode가 붙여진다.
		*/
		private String getSiteURL(HttpServletRequest request) {
			String siteURL = request.getRequestURL().toString();
			return siteURL.replace(request.getServletPath(), "");
		}

		/**
		* 버튼클릭시 실행되는 메소드로 인증여부를 거친 뒤 결과(html파일)를 리턴한다.
		*/
		@GetMapping("/verify")
		public String verifyUser(@Param("code") String code) {
			if (service.verify(code)) {
				//승인된 경우
				return "verify_success";
			} else {
				return "verify_fail";
			}
		}

		/**
		* 가입 된 사용자에게 사용자 목록(users.html)을 리턴
		*/
		@GetMapping("/users")
		public String listUsers(Model model) {
			List<User> listUsers = service.listAll();
			model.addAttribute("listUsers", listUsers);

			return "users";
		}
	}
	```

	10. ### SecurityConfig 설정 
	```java
	@Configuration
	@EnableWebSecurity
	public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

		@Autowired
		private UserServices userServices;

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

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.authorizeRequests()
				.antMatchers("/users").authenticated()
				.anyRequest().permitAll()
				.and()
				.formLogin()
					.usernameParameter("email")
					.defaultSuccessUrl("/users")
					.permitAll()
				.and()
				.logout().logoutSuccessUrl("/").permitAll();
		}
		
	}
	```