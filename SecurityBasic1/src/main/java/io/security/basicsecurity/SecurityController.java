package io.security.basicsecurity;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return "home";
    }

    @GetMapping("/user")
    public String user(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        return "User";
    }

    @GetMapping("/admin/pay")
    public String adminPay(){
        return "AdminPay";
    }

    @GetMapping("/admin/**")
    public String admin(){
        return "AdminAndSys";
    }
}
