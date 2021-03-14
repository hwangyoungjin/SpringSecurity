package net.codejava.api;

import net.codejava.User;
import net.codejava.UserRepository;
import net.codejava.UserServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.repository.query.Param;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpSession;

@RestController
@RequestMapping("/api")
public class LoginApiController {

    @Autowired
    UserRepository userRepository;

    @Autowired
    UserServices userServices;

    @GetMapping("/loginsuccess")
    public String login(){
        return "로그인완료";
    }

    @GetMapping("/loginfail")
    public String loginfail(){
        return "이메일을 인증하세요";
    }

}
