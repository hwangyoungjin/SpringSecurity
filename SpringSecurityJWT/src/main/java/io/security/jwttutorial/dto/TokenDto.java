package io.security.jwttutorial.dto;


import lombok.*;

@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter @Setter
public class TokenDto {
    private String token;
}
