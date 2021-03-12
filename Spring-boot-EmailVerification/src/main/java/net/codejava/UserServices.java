package net.codejava;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;
import javax.servlet.http.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.stereotype.Service;

import net.bytebuddy.utility.RandomString;

@Service
public class UserServices implements UserDetailsService {

	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private JavaMailSender mailSender;

	@Autowired
	private UserRepository userRepository;

	/**
	 * 모든 User 조회
	 */
	public List<User> listAll() {
		return userRepository.findAll();
	}

	/**
	 * 가입 요청시 실행되는 메소드로 이메일을 발송요청
	 * 이용은 불가하나 DB에 저장된다.
	 */
	public void register(User user, String siteURL) 
			throws UnsupportedEncodingException, MessagingException {
		//패스워드 암호
		String encodedPassword = passwordEncoder.encode(user.getPassword());
		user.setPassword(encodedPassword);

		//랜덤코드
		String randomCode = RandomString.make(64);
		user.setVerificationCode(randomCode);

		//아직 이용 불가
		user.setEnabled(false);

		//DB에 저장
		userRepository.save(user);

		//메일보내기
		sendVerificationEmail(user, siteURL);
	}


	/**
	 * 실질적으로 이메일을 발송시키는 메소드
	 */
	private void sendVerificationEmail(User user, String siteURL) 
			throws MessagingException, UnsupportedEncodingException {
		String toAddress = user.getEmail(); //수신자 이메일
		String fromAddress = "yohoee770"; //발신자 이메일
		String senderName = "hicompany"; //발신자 이름
		String subject = "Please verify your registration"; // 메일 제목
		String content = "Dear [[name]],<br>" //메일내용
				+ "Please click the link below to verify your registration:<br>"
				+ "<h3><a href=\"[[URL]]\" target=\"_self\">VERIFY</a></h3>"
				+ "Thank you,<br>"
				+ "Your company name.";
		
		// 메일 보내기위해 필요한 객체
		MimeMessage message = mailSender.createMimeMessage();
		MimeMessageHelper helper = new MimeMessageHelper(message,"utf-8");
		
		// 메일 발신자 정보(주소,이름)와 수신자메일주소, 메일제목 담기
		helper.setFrom(fromAddress, senderName);
		helper.setTo(toAddress);
		helper.setSubject(subject);
		
		// html 내용 replace
		content = content.replace("[[name]]", user.getLastName());
		String verifyURL = siteURL + "/verify?code=" + user.getVerificationCode();
		content = content.replace("[[URL]]", verifyURL);
		
		//본문 담기, true는 html 형식으로 보내겠다는 의미
		helper.setText(content, true);
		
		//메일 발송
		mailSender.send(message);
		
		System.out.println("Email has been sent");
	}

	/**
	 * 인증 코드 받아서 db와 비교
	 */
	public boolean verify(String verificationCode) {
		User user = userRepository.findByVerificationCode(verificationCode);

		//db의 없는 계정 or 해당 user가 이미 승인받은경우 false return
		if (user == null || user.isEnabled()) {
			return false;
		} else {

			//인증되었으니 Enable true
			//기존 verificationCode null
			user.setVerificationCode(null);
			user.setEnabled(true);
			//업데이트
			userRepository.save(user);
			return true;
		}
	}

	/**
	 * 로그인시 실행되는 메소드
	 */
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userRepository.findByEmail(username);
		if (user == null) {
			throw new UsernameNotFoundException("User not found");
		}

		//해당프로젝트에서 roles은 설정 안했으므로 null
		List<GrantedAuthority> roles = new ArrayList<>();
		roles.add(new SimpleGrantedAuthority("null"));

		return new CustomUserDetails(user,roles);
	}
}
