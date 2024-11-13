package com.spring_security.jwt_auth.demo.security.token;

import com.spring_security.jwt_auth.demo.model.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder
public class Token {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String accessToken;
    private String refreshToken;
    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;
    private boolean isRevoked = false;
    private boolean isExpired = false;
}
