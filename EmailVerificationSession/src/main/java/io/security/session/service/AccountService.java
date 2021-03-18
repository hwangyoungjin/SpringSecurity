package io.security.session.service;

import io.security.session.config.CustomUserDetails;
import io.security.session.model.Account;
import io.security.session.repository.AccountRepository;
import net.bytebuddy.utility.RandomString;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

@Service
public class AccountService implements UserDetailsService {


    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JavaMailSender mailSender;

    @Autowired
    private AccountRepository accountRepository;

    /**
     * 모든 account 조회
     */
    public List<Account> listAll() {
        return accountRepository.findAll();
    }

//    /**
//     * 메소드로 이메일을 발송요청
//     * DB에 저장하지 않고 메일 보낸다.
//     */
//    public void register(String email, String siteURL)
//            throws UnsupportedEncodingException, MessagingException {
//        //패스워드 암호
//        String encodedPassword
//                = passwordEncoder.encode(account.getPassword());
//        account.setPassword(encodedPassword);
//
//        //랜덤코드
//        String randomCode = RandomString.make(64);
//        account.setVerificationCode(randomCode);
//
//        //아직 이용 불가
//        account.setEnabled(false);
//
//        //DB에 저장
//        accountRepository.save(account);
//
//        //메일보내기
//        sendVerificationEmail(account, siteURL);
//    }


    /**
     * 실질적으로 이메일을 발송시키는 메소드
     * 인증코드를 리턴
     */
    public String sendVerificationEmail(String email)
            throws MessagingException, UnsupportedEncodingException {
        String fromAddress = "yohoee770"; //발신자 이메일
        String senderName = "CampusContact"; //발신자 이름
        String subject = "Please verify your registration"; // 메일 제목
        String content = "Dear [[name]],<br>" //메일내용
                + "Please input the Code below to verify your registration:<br>"
                + "<h3>Code = [[code]]</h3>"
                + "Thank you,<br>"
                + "CampusContact";

        // 메일 보내기위해 필요한 객체
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message,"utf-8");

        // 메일 발신자 정보(주소,이름)와 수신자메일주소, 메일제목 담기
        helper.setFrom(fromAddress, senderName);
        helper.setTo(email);
        helper.setSubject(subject);

        //랜덤코드
        Random random = new Random();
        StringBuffer buffer = new StringBuffer();
        int num = 0;

        while(buffer.length() < 6) {
            num = random.nextInt(10);
            buffer.append(num);
        }
        String randomCode = buffer.toString();

        // html 내용 replace
        content = content.replace("[[name]]", email);
        content = content.replace("[[code]]", randomCode);

        //본문 담기, true는 html 형식으로 보내겠다는 의미
        helper.setText(content, true);

        //메일 발송
        mailSender.send(message);

        System.out.println("Email has been sent");

        return randomCode;
    }

    /**
     * 로그인시 실행되는 메소드
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = accountRepository.findByEmail(username);
        if (account == null) {
            throw new UsernameNotFoundException("account not found");
        }

        //해당프로젝트에서 roles은 설정 안했으므로 null
        List<GrantedAuthority> roles = new ArrayList<>();
        roles.add(new SimpleGrantedAuthority("null"));

        return new CustomUserDetails(account,roles);
    }
}