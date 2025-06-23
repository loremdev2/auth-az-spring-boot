package com.loremdev.otpAuth.filter;

import com.loremdev.otpAuth.service.AppUserDetailsService;
import com.loremdev.otpAuth.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtRequestFilter extends OncePerRequestFilter {

    private final AppUserDetailsService appUserDetailsService;
    private final JwtUtil jwtUtil;

    private static List<String> PUBLIC_URLS = List.of(
            "login",
            "register",
            "send-reset-otp",
            "reset-password",
            "logout"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        String path= request.getServletPath();
        if(PUBLIC_URLS.contains(path)){
            filterChain.doFilter(request, response);
            return;
        }

        String jwtToken= null;
        String email = null;
        // 1. Check for Authorization header
        final String authHeader = request.getHeader("Authorization");
        if(authHeader !=null && authHeader.startsWith("Bearer ")){
            jwtToken= authHeader.substring(7);  // gives the token after "Bearer "

        }

        // 2. If Authorization is not found, check for JWT cookies
        if(jwtToken == null || jwtToken.isEmpty()){
            Cookie[] cookies = request.getCookies();
            if(cookies!=null){
                for(Cookie cookie : cookies){
                    if(cookie.getName().equals("jwt")){
                        jwtToken= cookie.getValue();
                        break;
                    }
                }
            }
        }

        // 3. Validate the JWT token and set the security context


        if(jwtToken!=null && !jwtToken.isEmpty()){
            email = jwtUtil.extractEmail(jwtToken);
           if(email!=null && !email.isEmpty() && SecurityContextHolder.getContext().getAuthentication()==null){
               // Load user details
               UserDetails userDetails= appUserDetailsService.loadUserByUsername(email);
               if(jwtUtil.validateToken(jwtToken, userDetails)){
                   UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                   authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                   SecurityContextHolder.getContext().setAuthentication(authenticationToken);
               }
           }
        }

        filterChain.doFilter(request, response);
    }
}
