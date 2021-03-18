package io.security.session.api;

import io.security.session.dto.AccountDto;
import io.security.session.service.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;

import javax.mail.MessagingException;
import javax.servlet.http.HttpSession;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;

@RestController
@RequestMapping("/api")
public class AccountApiController {

    @Autowired
    AccountService accountService;

    /**
     * 이메일받아서 인증보내기
     */
    @GetMapping("/email")
    public ResponseEntity<String> email(@RequestBody AccountDto accountDto,
                                        HttpSession httpSession) 
            throws UnsupportedEncodingException, MessagingException {
        
        //email 받아서
        String email = accountDto.getEmail();

        //메일보내고 인증코드 받아서
        String randomCode = accountService.sendVerificationEmail(email);

        //인증코드는 받은 AccountDto에 저장하고 
        accountDto.setVerificationCode(randomCode);
        
        //세션에 받은 이메일을 key로 AccountDTO 객체 Session의 저장
        httpSession.setAttribute(accountDto.getEmail(),accountDto);

        return ResponseEntity.ok("email send finished");
    }

    /**
     * 코드,이메일을 받아서 인증 하고 맞으면 TRUE 반환, 틀리면 FALSE 반환
     * 
     * 이메일을 받지 않은 사용자가 verify 신청한경우는 발생하지 않아야 한다.
     * 클라이언트에선 이메일로 인증코드 받은 경우만 verify 신청 할 수 있도록 해야한다.
     * 
     */
    @GetMapping("/verify")
    public boolean verify(@RequestBody AccountDto newAccountDto,
                          HttpSession httpSession){

        //쿠키의 맞는 세션을 받아 해당 세션에서 파라미터로 받은 이메일의 해당하는 ACCOUNT객체 꺼내고
        //해당 객체의 코드와 파라미터로 받은 accountDto의 code를 비교
        AccountDto originAcountDto = (AccountDto) httpSession.getAttribute(newAccountDto.getEmail());
        
        if(newAccountDto == null){ //쿠키가 없는경우 
            return false;
        }

        //세션에서 꺼내온 newAccountDTO와 기존에있던 originAcountDto code가 같으면
        if(newAccountDto.getVerificationCode().contains(originAcountDto.getVerificationCode())){
            //인증 완료 했으므로 세션에서 지우기
            httpSession.removeAttribute(newAccountDto.getEmail());
            return true;
        } else{ // 다르면
            return false;
        }
    }

    /**
     * 이메일 인증된 사용자 가입 [아직미완성]
     */
    @PostMapping("/register")
    public String register(@ModelAttribute AccountDto accountDto){
        return null;
    }

}
