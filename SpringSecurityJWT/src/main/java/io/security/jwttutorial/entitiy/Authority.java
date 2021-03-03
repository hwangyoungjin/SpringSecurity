package io.security.jwttutorial.entitiy;

import lombok.*;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import java.util.ArrayList;
import java.util.List;

@Entity
@Getter @Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Authority {

    @Id
    @GeneratedValue
    private Long id;

    private String authorityName;

    @ManyToMany(mappedBy = "authorities")
    private List<Account> accounts = new ArrayList<>();
}
