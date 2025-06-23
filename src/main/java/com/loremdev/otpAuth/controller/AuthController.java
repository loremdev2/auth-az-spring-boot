package com.loremdev.otpAuth.controller;

import com.loremdev.otpAuth.entity.UserEntity;
import com.loremdev.otpAuth.io.AuthRequest;
import com.loremdev.otpAuth.io.AuthResponse;
import com.loremdev.otpAuth.service.AppUserDetailsService;
import com.loremdev.otpAuth.service.ProfileService;
import com.loremdev.otpAuth.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final AppUserDetailsService appUserDetailsService;
    private final ProfileService profileService;
    private final JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest authRequest) {
        try {
            authenticate(authRequest.getEmail(), authRequest.getPassword());

            // load security principal (for JWT)
            UserDetails userDetails =
                    appUserDetailsService.loadUserByUsername(authRequest.getEmail());

            // load JPA entity to get the name
            UserEntity userEntity =
                    appUserDetailsService.loadUserEntityByEmail(authRequest.getEmail());

            // generate token
            String jwtToken = jwtUtil.generateToken(userDetails);

            // set cookie
            ResponseCookie cookie = ResponseCookie.from("jwt", jwtToken)
                    .httpOnly(true)
                    .path("/")
                    .maxAge(Duration.ofDays(1))
                    .secure(false)
                    .sameSite("Strict")
                    .build();

            // build response with name
            AuthResponse body = new AuthResponse(
                    userEntity.getEmail(),
                    userEntity.getName(),   // ← include the name here
                    jwtToken
            );

            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, cookie.toString())
                    .body(body);

        } catch (BadCredentialsException ex) {
            return buildError("Invalid credentials", HttpStatus.BAD_REQUEST);
        } catch (DisabledException ex) {
            return buildError("Account is disabled", HttpStatus.UNAUTHORIZED);
        } catch (Exception ex) {
            ex.printStackTrace();
            return buildError("Authentication failed due to server error", HttpStatus.UNAUTHORIZED);
        }
    }

    private void authenticate(String email, String password) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, password)
        );
    }

    @GetMapping("/is-authenticated")
    public ResponseEntity<Boolean> isAuthenticated(@CurrentSecurityContext(expression = "authentication?.name") String email) {
        return ResponseEntity.ok(email!=null);
    }

    @PostMapping("/send-reset-otp")
    public void sendResetOtpEmail(@RequestParam String email) {
        try{
            profileService.sendResetOtp(email);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Unable to send reset OTP email", e);
        }
    }

    private ResponseEntity<Map<String, Object>> buildError(String message, HttpStatus status) {
        Map<String, Object> error = new HashMap<>();
        error.put("error", true);
        error.put("message", message);
        return ResponseEntity.status(status).body(error);
    }
}
