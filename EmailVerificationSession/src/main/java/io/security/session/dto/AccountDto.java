package io.security.session.dto;

import lombok.Data;

@Data
public class AccountDto {
    Long id;
    String email;
    String pw;
    String verificationCode;
}
