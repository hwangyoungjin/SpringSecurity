package io.security.jwttutorial.controller;

import io.security.jwttutorial.dto.LoginDto;
import io.security.jwttutorial.dto.TokenDto;
import io.security.jwttutorial.jwt.JwtFilter;
import io.security.jwttutorial.jwt.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

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
