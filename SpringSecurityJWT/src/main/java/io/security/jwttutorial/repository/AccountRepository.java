package io.security.jwttutorial.repository;

import io.security.jwttutorial.entitiy.Account;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AccountRepository extends JpaRepository<Account,Long> {

    /**
     * EntitiyGraph는 쿼리 수행될때 LAZY조회가 아닌 EAGER조회로 수행
     * username에 해당하는 account를 가져올때 Authorities도 같이 가져온다
     */
    @EntityGraph(attributePaths = "authorities")
    Optional<Account> findOneWithAuthoritiesByUsername(String username);
}
