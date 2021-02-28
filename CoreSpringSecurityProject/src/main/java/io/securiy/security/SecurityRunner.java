package io.securiy.security;

import io.securiy.security.domain.Account;
import io.securiy.security.mySecurity.service.CustomUserDetailService;
import io.securiy.security.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class SecurityRunner implements ApplicationRunner {
    @Autowired
    UserService userService;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        Account account = new Account();
        account.setUsername("user");
        account.setPassword(passwordEncoder.encode("1111"));
        account.setRole("ROLE_USER");
        userService.createUser(account);
    }
}
