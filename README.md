# SpringSecurity
스프링시큐리티

---
### 학습
```java
* Spring Security의 보안설정 API와 연계된 각 Filter 학습
* Spring Security 내부 아키텍처와 각 객체의 역할 및 처리과정 학습
* Spring Security를 활용한 간단한 Project 
	- CoreSpringSecurityProject
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
	- Entity와 DTO 맵핑을 위해 modelmapper의존성 추가
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

	7. #### Account와 AccountDto 를 통해 회원가입 만들기
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
	
	8. #### UserDetailsService 커스텀 ( + UserDetails 커스텀)
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

	9. #### AuthenticationProvider 커스텀
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

	10. 로그인 설정
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
