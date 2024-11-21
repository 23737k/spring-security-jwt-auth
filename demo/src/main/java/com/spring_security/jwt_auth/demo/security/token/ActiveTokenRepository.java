package com.spring_security.jwt_auth.demo.security.token;

import com.spring_security.jwt_auth.demo.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

public interface ActiveTokenRepository extends JpaRepository<ActiveToken, Long> {
    void deleteByUser(User user);
    @Transactional
    void deleteByUserEmail(String email);
    boolean existsByToken(String refreshToken);
}

