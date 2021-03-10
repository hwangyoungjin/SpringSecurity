package net.codejava;

import java.io.UnsupportedEncodingException;
import java.util.List;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import net.bytebuddy.utility.RandomString;

@Service
public class UserServices {

	@Autowired
	private UserRepository repo;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private JavaMailSender mailSender;
	
	public List<User> listAll() {
		return repo.findAll();
	}

	/**
	 *
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
		repo.save(user);

		//메일보내기
		sendVerificationEmail(user, siteURL);
	}


	private void sendVerificationEmail(User user, String siteURL) 
			throws MessagingException, UnsupportedEncodingException {
		String toAddress = user.getEmail();
		String fromAddress = "yohoee770";
		String senderName = "hicompany";
		String subject = "Please verify your registration";
		String content = "Dear [[name]],<br>"
				+ "Please click the link below to verify your registration:<br>"
				+ "<h3><a href=\"[[URL]]\" target=\"_self\">VERIFY</a></h3>"
				+ "Thank you,<br>"
				+ "Your company name.";
		
		MimeMessage message = mailSender.createMimeMessage();
		MimeMessageHelper helper = new MimeMessageHelper(message,"utf-8");
		
		helper.setFrom(fromAddress, senderName);
		helper.setTo(toAddress);
		helper.setSubject(subject);
		
		content = content.replace("[[name]]", user.getFullName());
		String verifyURL = siteURL + "/verify?code=" + user.getVerificationCode();
		
		content = content.replace("[[URL]]", verifyURL);
		
		helper.setText(content, true);
		
		mailSender.send(message);
		
		System.out.println("Email has been sent");
	}

	/**
	 * 코드 받아서 db와 비교
	 */
	public boolean verify(String verificationCode) {
		User user = repo.findByVerificationCode(verificationCode);

		//db의 없는 계정 or 해당 user가 이미 승인받은경우 false return
		if (user == null || user.isEnabled()) {
			return false;
		} else {

			//인증되었으니 Enable true
			//기존 verificationCode null
			user.setVerificationCode(null);
			user.setEnabled(true);
			//업데이트
			repo.save(user);
			return true;
		}
		
	}
	
}
