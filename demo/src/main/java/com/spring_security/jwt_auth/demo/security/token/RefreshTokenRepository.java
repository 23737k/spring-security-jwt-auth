package com.spring_security.jwt_auth.demo.security.token;

import com.spring_security.jwt_auth.demo.model.User;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    void deleteByUser(User user);
    @Transactional
    void deleteByUserEmail(String email);
    boolean existsByToken(String refreshToken);
}

