package net.codejava;

import net.bytebuddy.utility.RandomString;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.core.parameters.P;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class AppRunner implements ApplicationRunner {

    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    UserRepository userRepository;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        User user = new User();
        user.setEmail("innovation950302@gmail.com");
        user.setPassword(passwordEncoder.encode("123123"));
        user.setEnabled(false);
        user.setFirstName("youngjin");
        user.setId(1l);
        user.setLastName("hwang");

        //랜덤코드
        String randomCode = RandomString.make(64);
        user.setVerificationCode(randomCode);

        userRepository.save(user);
    }
}
