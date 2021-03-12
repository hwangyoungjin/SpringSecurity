package net.codejava;

import java.io.UnsupportedEncodingException;
import java.util.List;

import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class AppController {

	@Autowired
	private UserServices service;
	
	@GetMapping("")
	public String viewHomePage() {
		return "index";
	}


	/**
	 * 맨처음 가입 요청시 실행
	 */
	@GetMapping("/register")
	public String showRegistrationForm(Model model) {
		model.addAttribute("user", new User());
		return "signup_form";
	}

	/**
	 * 처음 가입 요청을 했던 사용자가 가입 내용을 적고 form 요청을 했을때 실행
	 */
	@PostMapping("/process_register")
	public String processRegister(User user, HttpServletRequest request) 
			throws UnsupportedEncodingException, MessagingException {
		service.register(user, getSiteURL(request));		
		return "register_success";
	}

	/**
	 * 로그인시 실행되는 processRegister 핸들러에 의해 실행되며
	 * path()를 return 한다
	 * 해당 path는 이메일 버튼의 path로 들어간다.
	 * sendmail에서 버튼 url은 path의 verify + User의 VerificationCode가 붙여진다.
	 */
	private String getSiteURL(HttpServletRequest request) {
		String siteURL = request.getRequestURL().toString();
		return siteURL.replace(request.getServletPath(), "");
	}

	/**
	 * 버튼클릭시 실행되는 메소드로 인증여부를 거친 뒤 결과(html파일)를 리턴한다.
	 */
	@GetMapping("/verify")
	public String verifyUser(@Param("code") String code) {
		if (service.verify(code)) {
			//승인된 경우
			return "verify_success";
		} else {
			return "verify_fail";
		}
	}


	/**
	 * 가입 된 사용자에게 사용자 목록(users.html)을 리턴
	 */
	@GetMapping("/users")
	public String listUsers(Model model) {
		List<User> listUsers = service.listAll();
		model.addAttribute("listUsers", listUsers);

		return "users";
	}
}
