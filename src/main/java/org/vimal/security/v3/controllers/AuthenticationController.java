package org.vimal.security.v3.controllers;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.vimal.security.v3.services.AuthenticationService;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestParam String usernameOrEmail,
                                                     @RequestParam String password,
                                                     HttpServletRequest request) throws Exception {
        return ResponseEntity.ok(authenticationService.login(
                        usernameOrEmail,
                        password,
                        request
                )
        );
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(HttpServletRequest request) throws Exception {
        return ResponseEntity.ok(authenticationService.logout(request));
    }

    @PostMapping("/logout/allDevices")
    public ResponseEntity<Map<String, String>> logoutAllDevices() throws Exception {
        return ResponseEntity.ok(authenticationService.logoutAllDevices());
    }

    @PostMapping("/refresh/accessToken")
    public ResponseEntity<Map<String, Object>> refreshAccessToken(@RequestParam String refreshToken,
                                                                  HttpServletRequest request) throws Exception {
        return ResponseEntity.ok(authenticationService.refreshAccessToken(
                refreshToken,
                request
        ));
    }

    @PostMapping("/revoke/accessToken")
    public ResponseEntity<Map<String, String>> revokeAccessToken(HttpServletRequest request) throws Exception {
        return ResponseEntity.ok(authenticationService.revokeAccessToken(request));
    }

    @PostMapping("/revoke/refreshToken")
    public ResponseEntity<Map<String, String>> revokeRefreshToken(@RequestParam String refreshToken) throws Exception {
        return ResponseEntity.ok(authenticationService.revokeRefreshToken(refreshToken));
    }

    @PostMapping("/mfa/requestTo/toggle")
    public ResponseEntity<Object> requestToToggleMfa(@RequestParam String type,
                                                     @RequestParam String toggle) throws Exception {
        return authenticationService.requestToToggleMfa(
                type,
                toggle
        );
    }

    @PostMapping("/mfa/verifyTo/toggle")
    public ResponseEntity<Map<String, String>> verifyToggleMfa(@RequestParam String type,
                                                               @RequestParam String toggle,
                                                               @RequestParam String otpTotp) throws Exception {
        return ResponseEntity.ok(authenticationService.verifyToggleMfa(
                        type,
                        toggle,
                        otpTotp
                )
        );
    }

    @PostMapping("/mfa/requestTo/login")
    public ResponseEntity<Map<String, String>> requestToLoginMfa(@RequestParam String type,
                                                                 @RequestParam String stateToken) throws Exception {
        return ResponseEntity.ok(authenticationService.requestToLoginMfa(
                        type,
                        stateToken
                )
        );
    }

    @PostMapping("/mfa/verifyTo/login")
    public ResponseEntity<Map<String, Object>> verifyMfaToLogin(@RequestParam String type,
                                                                @RequestParam String stateToken,
                                                                @RequestParam String otpTotp,
                                                                HttpServletRequest request) throws Exception {
        return ResponseEntity.ok(authenticationService.verifyMfaToLogin(
                        type,
                        stateToken,
                        otpTotp,
                        request
                )
        );
    }
}
