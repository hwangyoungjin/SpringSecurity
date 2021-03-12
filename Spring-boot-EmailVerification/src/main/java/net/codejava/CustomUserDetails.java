package net.codejava;

import java.util.Collection;

import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

@Getter @Setter
public class CustomUserDetails extends org.springframework.security.core.userdetails.User {

	private User user;

	public CustomUserDetails(User myUser,
							 Collection<? extends GrantedAuthority> authorities) {
		super(myUser.getFirstName(), myUser.getPassword(), authorities);
		this.user = myUser;
	}

	public String getFullName() {
		return user.getFirstName() + " " + user.getLastName();
	}
}
