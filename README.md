# SpringSecurity
스프링시큐리티

---
### 개발환경
```java
- jdk 11
- IntelliJ
- Postgres
``` 

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
	1. 환경설정
	```java
	1. 인텔리제이
	2. mysql	
	3. jdk 11
	4. maven
	5. springboot 2.4.3
	```
	2. 의존성 추가
	```java	
	 - web, thymeleaf, security, springdataJPA, lombok, mysql 의존성 추가
		- @configurationproperties 사용을 위해 아래 의존성 추가
		        <dependency>
		            <groupId>org.springframework.boot</groupId>
		            <artifactId>spring-boot-configuration-processor</artifactId>
		        </dependency>
	```
	3. Mysql 연결
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