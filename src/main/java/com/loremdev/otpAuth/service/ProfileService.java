package com.loremdev.otpAuth.service;

import com.loremdev.otpAuth.io.ProfileRequest;
import com.loremdev.otpAuth.io.ProfileResponse;

public interface ProfileService {
    ProfileResponse createProfile(ProfileRequest request);

    ProfileResponse getProfile(String email);

    public void sendResetOtp(String email);

    void resetPassword(String email, String otp, String newPassword);
}
