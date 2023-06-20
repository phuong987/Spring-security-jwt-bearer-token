package com.spring.security.phuongo.controllers;

import com.spring.security.phuongo.config.JwtUtils;
import com.spring.security.phuongo.dao.UserDao;
import com.spring.security.phuongo.dto.AuthenticationRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationManager authenticationManager;
    private final UserDao userDao;
    private final JwtUtils jwtUtils;

    @PostMapping("/authenticate")
    public ResponseEntity<String> authenticate(
            @RequestBody AuthenticationRequest request
    ){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername()
                        , request.getPassword())
        );
        final UserDetails user = userDao.findUserByUsername(request.getUsername());
        if (user!=null){
            return ResponseEntity.ok(jwtUtils.generateToken(user, new HashMap<>()));
        }
        return ResponseEntity.status(400).body("Some error has occurred");
    }
}
