package com.loremdev.otpAuth.controller;

import com.loremdev.otpAuth.io.ProfileRequest;
import com.loremdev.otpAuth.io.ProfileResponse;
import com.loremdev.otpAuth.service.EmailService;
import com.loremdev.otpAuth.service.ProfileService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class ProfileController {


    private final ProfileService profileService;
    private final EmailService emailService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public ProfileResponse register(@Valid @RequestBody ProfileRequest request){

        ProfileResponse response= profileService.createProfile(request);
        // Send a welcome email after successful registration
        emailService.sendWelcomeEmail(response.getEmail(), response.getName());
        return response;
    }

    @GetMapping("/test")
    @ResponseStatus(HttpStatus.OK)
    public String test(){
        return "Auth is Working ! Test successful!";
    }


    @GetMapping("/profile")
    public ProfileResponse getProfile(@CurrentSecurityContext (expression = "authentication?.name") String email) {
        // Fetch the profile using the email from the security context
        return profileService.getProfile(email);
    }


}
