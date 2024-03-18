package com.example.oauthdemo.configurations;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class UserDetailsConfiguration {


    /**
     * NOT SAFE FOR PRODUCTION
     *
     * @return User details service, that allows to authenticate
     * two users with fixed usernames and passwords,
     * one would have a USER role, and another ADMIN role
     * to demonstrate role based authorization
     */
    @Bean
    public UserDetailsService staticUsers() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(
                User.withDefaultPasswordEncoder().username("user").password("password").roles("USER").build()
        );
        manager.createUser(
                User.withDefaultPasswordEncoder().username("admin").password("admin_password").roles("ADMIN", "USER").build()
        );
        return manager;
    }


}
