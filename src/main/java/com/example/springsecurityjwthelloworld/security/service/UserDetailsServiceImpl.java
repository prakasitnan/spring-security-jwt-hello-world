package com.example.springsecurityjwthelloworld.security.service;

import com.example.springsecurityjwthelloworld.models.User;
import com.example.springsecurityjwthelloworld.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (!userOpt.isPresent()){
            throw new UsernameNotFoundException("User Not Found with username: " + username);
        }
        User user = userOpt.get();

        return UserDetailsImpl.build(user);
    }
}
