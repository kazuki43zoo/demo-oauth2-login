package com.example.demooauth2login;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
        .antMatchers("/developer", "/developer/**").hasRole("DEVELOPER")
        .anyRequest().authenticated()
        .and()
        .logout().permitAll()
        .and()
        .oauth2Login()
        .loginPage("/login").permitAll()
        .userInfoEndpoint()
        .userAuthoritiesMapper(this.oauth2UserAuthoritiesMapper())
        .and()
        .and()
        .formLogin()
        .loginPage("/login").permitAll();
  }

  private GrantedAuthoritiesMapper oauth2UserAuthoritiesMapper() {
    return authorities -> {
      List<GrantedAuthority> mappedAuthorities = new ArrayList<>();
      for (GrantedAuthority authority : authorities) {
        mappedAuthorities.add(authority);
        if (OAuth2UserAuthority.class.isInstance(authority)) {
          mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_OAUTH_USER"));
          OAuth2UserAuthority oauth2UserAuthority = OAuth2UserAuthority.class.cast(authority);
          if (Map.class.isInstance(oauth2UserAuthority.getAttributes().get("plan")) &&
              "developer".equals(Map.class.cast(oauth2UserAuthority.getAttributes().get("plan")).get("name"))) {
            mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_DEVELOPER"));
          }
        }
      }
      return mappedAuthorities;
    };
  }

  @Bean
  public UserDetailsService userDetailsService() {
    User.UserBuilder users = User.withDefaultPasswordEncoder();
    InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
    manager.createUser(users.username("user").password("password").roles("USER").build());
    manager.createUser(users.username("admin").password("password").roles("USER", "ADMIN").build());
    return manager;
  }

}
