package io.security.basicsecurity;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index(){
        return "home";
    }

    @GetMapping("/user")
    public String user(){
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
