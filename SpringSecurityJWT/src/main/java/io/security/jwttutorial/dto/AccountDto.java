package io.security.jwttutorial.dto;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter @Setter
public class AccountDto {

    @NotNull
    @Size(min = 3 ,max = 50)
    private String username;

    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @NotNull
    @Size(min = 3 ,max = 100)
    private String password;

    @NotNull
    @Size(min = 3 ,max = 50)
    private String nickname;
}
