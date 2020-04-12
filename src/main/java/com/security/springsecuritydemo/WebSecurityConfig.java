package com.security.springsecuritydemo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//                .withUser("root").password("123").roles("ADMIN", "DBA")
//                .and()
//                .withUser("admin").password("123").roles("ADMIN", "USER")
//                .and().
//                withUser("jayden").password("123").roles("USER");
//    }
    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "/home").permitAll()
                .antMatchers("/admin/**")
                .access("hasAnyRole('ADMIN')")
                .antMatchers("/user/**")
                .access("hasAnyRole('ADMIN','USER')")
                .antMatchers("/db/**")
                .access("hasAnyRole('ADMIN') and hasAnyRole('DBA')")
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
                .logout()
                .permitAll();
    }

    @Bean
    @Override
    public UserDetailsService userDetailsService() {
        UserDetails user =
                User.builder()
                        .username("root")
                        .password("123")
                        .roles("ADMIN", "DBA")
                        .build();
        UserDetails user2 =
                User.builder()
                .username("admin")
                .password("123")
                .roles("ADMIN", "USER")
                .build();
        UserDetails user3 =
                User.builder()
                .username("hello")
                .password("123")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(user, user2, user3);
    }
}