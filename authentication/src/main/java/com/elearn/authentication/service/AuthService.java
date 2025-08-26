package com.elearn.authentication.service;

import com.elearn.authentication.dto.AuthResponse;
import com.elearn.authentication.dto.LoginRequest;
import com.elearn.authentication.dto.RegisterRequest;
import com.elearn.authentication.model.RefreshToken;
import com.elearn.authentication.model.Role;
import com.elearn.authentication.model.User;
import com.elearn.authentication.repository.RefreshTokenRepository;
import com.elearn.authentication.repository.UserRepository;
import com.elearn.authentication.security.JwtUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthService(UserRepository userRepository,
                       RefreshTokenRepository refreshTokenRepository,
                       PasswordEncoder passwordEncoder,
                       JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    public User register(RegisterRequest req) {
        if (userRepository.findByUsername(req.getUsername()).isPresent()) {
            throw new IllegalArgumentException("username already exists");
        }
        if (req.getEmail() != null && userRepository.findByEmail(req.getEmail()).isPresent()) {
            throw new IllegalArgumentException("email already exists");
        }
        Role role = Role.USER;
        if ("ADMIN".equalsIgnoreCase(req.getRole())) role = Role.ADMIN;
        User u = User.builder()
                .username(req.getUsername())
                .email(req.getEmail())
                .password(passwordEncoder.encode(req.getPassword()))
                .role(role)
                .enabled(true)
                .build();
        return userRepository.save(u);
    }

    public AuthResponse login(LoginRequest req) {
        User user = userRepository.findByUsername(req.getUsername()).orElseThrow(() -> new IllegalArgumentException("invalid credentials"));
        if (!passwordEncoder.matches(req.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException("invalid credentials");
        }

        String accessToken = jwtUtil.generateAccessToken(user.getId(), user.getUsername(), user.getRole().name());
        String refreshToken = jwtUtil.generateRefreshToken(user.getId());

        RefreshToken rt = RefreshToken.builder()
                .token(refreshToken)
                .userId(user.getId())
                .expiryDate(Instant.now().plusMillis(jwtUtil.parseRefreshToken(refreshToken).getBody().getExpiration().getTime() - System.currentTimeMillis()))
                .revoked(false)
                .build();

        // store refresh token
        refreshTokenRepository.save(rt);

        return new AuthResponse(accessToken, refreshToken, Long.parseLong(System.getProperty("jwt.access-exp-ms", String.valueOf(900000L))));
    }

    public AuthResponse refresh(String refreshToken) {
        var opt = refreshTokenRepository.findByToken(refreshToken);
        if (opt.isEmpty()) throw new IllegalArgumentException("Invalid refresh token");
        RefreshToken rt = opt.get();
        if (rt.isRevoked() || rt.getExpiryDate().isBefore(Instant.now())) {
            throw new IllegalArgumentException("Refresh token expired or revoked");
        }
        var claims = jwtUtil.parseRefreshToken(refreshToken).getBody();
        String userId = claims.getSubject();
        User user = userRepository.findById(userId).orElseThrow();

        // revoke old token and create new (rotation)
        rt.setRevoked(true);
        refreshTokenRepository.save(rt);

        String newAccess = jwtUtil.generateAccessToken(user.getId(), user.getUsername(), user.getRole().name());
        String newRefresh = jwtUtil.generateRefreshToken(user.getId());

        RefreshToken newRt = RefreshToken.builder()
                .token(newRefresh)
                .userId(user.getId())
                .expiryDate(Instant.now().plusMillis(jwtUtil.parseRefreshToken(newRefresh).getBody().getExpiration().getTime() - System.currentTimeMillis()))
                .revoked(false)
                .build();
        refreshTokenRepository.save(newRt);

        return new AuthResponse(newAccess, newRefresh, Long.parseLong(System.getProperty("jwt.access-exp-ms", String.valueOf(900000L))));
    }

    public void logout(String refreshToken) {
        refreshTokenRepository.findByToken(refreshToken).ifPresent(rt -> {
            rt.setRevoked(true);
            refreshTokenRepository.save(rt);
        });
    }
}
