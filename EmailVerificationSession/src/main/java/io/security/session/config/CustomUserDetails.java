package io.security.session.config;

import io.security.session.model.Account;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@Data
public class CustomUserDetails extends org.springframework.security.core.userdetails.User {

    private Account account;

    public CustomUserDetails(Account myUser,
                             Collection<? extends GrantedAuthority> authorities) {
        super(myUser.getFirstName(), myUser.getPassword(), authorities);
        this.account = myUser;
    }

    public String getFullName() {
        return account.getFirstName() + " " + account.getLastName();
    }
}