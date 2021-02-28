package io.securiy.security.mySecurity.provider;


import io.securiy.security.domain.Account;
import io.securiy.security.mySecurity.service.AccountContext;
import io.securiy.security.mySecurity.service.CustomUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;


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
