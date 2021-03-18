package io.security.session.repository;

import io.security.session.model.Account;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface AccountRepository extends JpaRepository<Account, Long> {
    @Query("SELECT u FROM Account u WHERE u.email = ?1")
    public Account findByEmail(String email);

    @Query("SELECT u FROM Account u WHERE u.verificationCode = ?1")
    public Account findByVerificationCode(String code);

    public Account findByFirstName(String firstname);
}
