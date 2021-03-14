package net.codejava.api;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
public class CustomUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    /**
     * Form 요청이 들어오면 기존과 동일하게 적용하고
     *
     * JSON 요청이 들어오면 request의 buffer를 읽어
     * 요청을 파싱하고 map에 데이터를 보관(Key값은 id로 들어오는 email과 pw인 password)하고
     * 사용자가 입력한 파라미터명과 동일한 키값으로
     * 기존과 동일하게 UsernamePasswordAuthenticationToken을 만들어
     * AuthenticationManager가 authentication 과정을 진행 할 수 있도록 구현
     *
     * 이후 UserDetailsService에서 요청에 포함된 Username을
     * 기준으로 DB에서 사용자를 찾고 AuthenticationManger에 등록된 PasswordEncoder로 패스워드를 비교하여
     * 로그인 과정을 진행 할 것것     */

    /**
     * 오버라이딩하는 메소드는 4개로
     * 1. obtainUsername
     * 2. obtainPassword
     * 3. attemptAuthentication
     * 4. SetPostOnly
     */

    private boolean postOnly = true;
    private HashMap<String,String> jsonRequest;

    @Override
    protected String obtainPassword(HttpServletRequest request) {
        String passwordParameter = super.getPasswordParameter();
        //json요청이면 password를 hashmap에서 가져와서 반환
        if(request.getHeader("Content-Type").equals(MediaType.APPLICATION_JSON_VALUE)){
            return jsonRequest.get(passwordParameter);
        }
        return request.getParameter(passwordParameter);
    }

    @Override
    protected String obtainUsername(HttpServletRequest request) {
        String usernameParameter = super.getUsernameParameter();
        //json요청이면 username을 hashmap에서 가져와서 반환
        if(request.getHeader("Content-Type").equals(MediaType.APPLICATION_JSON_VALUE)){
            return jsonRequest.get(usernameParameter);
        }
        return request.getParameter(usernameParameter);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if(postOnly && !request.getMethod().equals("POST")){
            throw new AuthenticationServiceException("Authentication method not supported:"+request.getMethod());
        }
        if(request.getHeader("Content-Type").equals(MediaType.APPLICATION_JSON_VALUE)){
            ObjectMapper mapper = new ObjectMapper();
            try{
                this.jsonRequest = mapper.readValue(request.getReader().lines().collect(Collectors.joining()), new TypeReference<HashMap<String,String>>(){});
            }catch (IOException e){
                e.printStackTrace();
                throw  new AuthenticationServiceException("Request Content-Type(application/json) Pasing Error");
            }
        }

        String username = obtainUsername(request);
        String password = obtainPassword(request);

        log.info("[LOGIN_REQUEST] [email: {}, password: *******]",username);

        if(username == null){
            username="";
        }
        if(password==null){
            password="";
        }
        username = username.trim();

        UsernamePasswordAuthenticationToken authRequest
                = new UsernamePasswordAuthenticationToken(username,password);

        //Allow subclasses to set "details" property
        setDetails(request,authRequest);

        return this.getAuthenticationManager().authenticate(authRequest);
    }

    @Override
    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }
}
