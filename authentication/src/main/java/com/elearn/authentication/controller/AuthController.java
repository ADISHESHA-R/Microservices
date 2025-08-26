package com.elearn.authentication.controller;

import com.elearn.authentication.dto.AuthResponse;
import com.elearn.authentication.dto.LoginRequest;
import com.elearn.authentication.dto.RefreshRequest;
import com.elearn.authentication.dto.RegisterRequest;
import com.elearn.authentication.model.User;
import com.elearn.authentication.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) { this.authService = authService; }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest req) {
        User user = authService.register(req);
        // never return password
        user.setPassword(null);
        return ResponseEntity.ok(user);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest req) {
        AuthResponse res = authService.login(req);
        return ResponseEntity.ok(res);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshRequest req) {
        AuthResponse res = authService.refresh(req.getRefreshToken());
        return ResponseEntity.ok(res);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@Valid @RequestBody RefreshRequest req) {
        authService.logout(req.getRefreshToken());
        return ResponseEntity.ok().build();
    }
}
