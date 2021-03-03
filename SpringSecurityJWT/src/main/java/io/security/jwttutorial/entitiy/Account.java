package io.security.jwttutorial.entitiy;

import lombok.*;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@Getter @Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Account{

    @Id
    @GeneratedValue
    private Long id;

    private String username;

    private String password;

    private String nickname;

    private boolean activated;

    @ManyToMany
    @JoinTable(
            name = "account_authority", //조인된 테이블 명
            joinColumns = @JoinColumn(name = "account_id"),
            inverseJoinColumns = @JoinColumn(name="authority_id"))
    private List<Authority> authorities = new ArrayList<>();
}
