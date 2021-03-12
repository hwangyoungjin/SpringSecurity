package net.codejava;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomUrlAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    //리다이렉션을 위한 클래스
    RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Autowired
    UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        //인증된 User의 firstName을 받아 DB에서 해당 이름의 객체 꺼내기
        String userFirstName = authentication.getName();
        User user = userRepository.findByFirstName(userFirstName);

        //해당 User의 isEnable 값을 통해 Redirection
        if(user.isEnabled()){
            redirectStrategy.sendRedirect(request,response,"/users");
        } else {
            redirectStrategy.sendRedirect(request,response,"/verify");
        }
    }
}
