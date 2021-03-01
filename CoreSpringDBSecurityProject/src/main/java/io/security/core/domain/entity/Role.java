package io.security.core.domain.entity;

import lombok.*;

import javax.persistence.*;
import java.io.Serializable;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.ArrayList;
import java.util.Set;

@Entity
@Table(name = "ROLE")
@Data
@ToString(exclude = {"accounts","resourcesSet"})
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(of = "id")
@Builder
public class Role implements Serializable {

    @Id
    @GeneratedValue
    @Column(name = "role_id")
    private Long id;

    @Column(name = "role_name")
    private String roleName;

    @Column(name = "role_desc")
    private String roleDesc;

    @ManyToMany(fetch = FetchType.LAZY, mappedBy = "roleSet")
    @OrderBy("ordernum desc")
    private List<Resources> resourcesSet = new ArrayList<>();

    @ManyToMany(fetch = FetchType.LAZY, mappedBy = "userRoles")
    private List<Account> accounts = new ArrayList<>();

}


