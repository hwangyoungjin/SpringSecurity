package io.securiy.security.service;

import io.securiy.security.domain.Account;
import org.springframework.stereotype.Service;

public interface UserService {
    public void createUser(Account account);
}
