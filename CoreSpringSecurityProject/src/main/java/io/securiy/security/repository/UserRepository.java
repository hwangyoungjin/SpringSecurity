package io.securiy.security.repository;

import io.securiy.security.domain.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Account,Long> {
    Account findByUsername(String s);
}
