package com.example.springsecurityjwthelloworld.repository;

import com.example.springsecurityjwthelloworld.models.ERole;
import com.example.springsecurityjwthelloworld.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository <Role, Long> {
    Optional<Role> findByName(ERole name);
}
