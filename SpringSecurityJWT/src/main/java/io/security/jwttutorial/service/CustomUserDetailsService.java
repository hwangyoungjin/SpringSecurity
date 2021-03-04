package io.security.jwttutorial.service;

import io.security.jwttutorial.entitiy.Account;
import io.security.jwttutorial.repository.AccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.w3c.dom.stylesheets.LinkStyle;

import java.awt.*;
import java.awt.font.TextHitInfo;
import java.util.List;
import java.util.stream.Collectors;

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
