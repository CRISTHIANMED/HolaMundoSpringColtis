package com.coltis.HolaMundoSpring.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{
     
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        
        auth.inMemoryAuthentication()
                .withUser("admin")
                .password("{noop}123456")
                .roles("ADMIN", "USER")
                .and()
                .withUser("user")
                .password("{noop}user123")
                .roles("USER");
    }
    
    @Override
    protected void configure(HttpSecurity htpp) throws Exception{
        
        htpp.authorizeHttpRequests()
                .antMatchers("/editar/**", "/agregar/**", "/eliminar")
                .hasRole("ADMIN")
                .antMatchers("/")
                .hasAnyRole("USER", "ADMIN")
                .and()
                .formLogin()
                .loginPage("/login")
                .and()
                .exceptionHandling()
                .accessDeniedPage("/errores/403");
    }
    
   
    
}
