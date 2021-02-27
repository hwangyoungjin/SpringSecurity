package io.securiy.security.service.impl;

import io.securiy.security.domain.Account;
import io.securiy.security.repository.UserRepository;
import io.securiy.security.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public void createUser(Account account) {
        userRepository.save(account);
    }
}
