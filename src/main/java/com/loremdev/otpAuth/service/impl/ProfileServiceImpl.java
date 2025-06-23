package com.loremdev.otpAuth.service.impl;

import com.loremdev.otpAuth.entity.UserEntity;
import com.loremdev.otpAuth.io.ProfileRequest;
import com.loremdev.otpAuth.io.ProfileResponse;
import com.loremdev.otpAuth.repository.UserRepository;
import com.loremdev.otpAuth.service.EmailService;
import com.loremdev.otpAuth.service.ProfileService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

@Service
@RequiredArgsConstructor
public class ProfileServiceImpl implements ProfileService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final EmailService emailService;

    @Override
    @Transactional
    public ProfileResponse createProfile(ProfileRequest request) {
        UserEntity newProfile= convertToUserEntity(request);

        // Check if the email already exists
        if (!userRepository.existsByEmail(newProfile.getEmail())) {
            newProfile=userRepository.save(newProfile);
            return convertToProfileResponse(newProfile);
        }
        throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");
    }

    @Override
    public ProfileResponse getProfile(String email) {
        UserEntity existingUser= userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));

        return convertToProfileResponse(existingUser);
    }


    @Override
    public void sendResetOtp(String email) {
        UserEntity existingEntity= userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
        //  Generate 6 digit OTP
        String otp= String.valueOf(ThreadLocalRandom.current().nextInt(100000, 999999));

        // calculate expiry time (current+ 15 min in milliseconds)
        long expiryTime= System.currentTimeMillis()+(15 * 60 * 1000);

        // update the profile entity
        existingEntity.setResetOtp(otp);
        existingEntity.setResetOtpExpiredAt(expiryTime);

        // Save the updated entity back to the repository
        userRepository.save(existingEntity);

        try{
            // Reset otp email
            emailService.sendResetOtpEmail(existingEntity.getEmail(), otp);
        } catch (Exception e) {
            throw new RuntimeException("Unable to send reset OTP email", e);
        }

    }

    @Override
    public void resetPassword(String email, String otp, String newPassword) {
        UserEntity existingUser= userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
        if(existingUser.getResetOtp()==null || !existingUser.getResetOtp().equals(otp)){
            throw new RuntimeException("Invalid OTP");
        }
        if(existingUser.getResetOtpExpiredAt()< System.currentTimeMillis()){
            throw new RuntimeException("OTP expired");
        }

        existingUser.setPassword(passwordEncoder.encode(newPassword));
        existingUser.setResetOtp(null);
        existingUser.setResetOtpExpiredAt(0L);
        userRepository.save(existingUser);
    }

    private UserEntity convertToUserEntity(ProfileRequest request) {
        return UserEntity.builder()
                .userId(UUID.randomUUID().toString())         // generate a unique user identifier
                .name(request.getName())                      // user’s full name
                .email(request.getEmail())                    // user’s email (must be unique)
                .password(passwordEncoder.encode(request.getPassword()))              // you’ll probably want to encode this!
                .isAccountVerified(false)                     // new users start un-verified
                .verifyOtp(null)                              // no OTP sent yet
                .verifyOtpExpireAt(null)                      // or a timestamp if you prefer 0L
                .resetOtp(null)                               // no reset OTP yet
                .resetOtpExpiredAt(0L)                        // not expired (or use null)
                .build();                                     // <-- don’t forget to build!
    }


    private ProfileResponse convertToProfileResponse(UserEntity newProfile){
        return ProfileResponse.builder()
                .name(newProfile.getName())
                .email(newProfile.getEmail())
                .userId(newProfile.getUserId())
                .isAccountVerified(newProfile.getIsAccountVerified())
                .build();
    }
}
