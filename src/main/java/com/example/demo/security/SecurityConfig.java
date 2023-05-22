package com.example.demo.security;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

@Configuration
@EnableWebSecurity
 public class SecurityConfig {

 @Value("${app.jwtSecret}")
 private  String secret ;
@Bean
public InMemoryUserDetailsManager user() {
 return new InMemoryUserDetailsManager(
         User.withUsername("javad")
                 .password("{noop}123")
                 .authorities("read")
                 .build());

 }
 @Bean
 public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
 return http
         .csrf(AbstractHttpConfigurer::disable)
         .authorizeRequests(auth-> auth.anyRequest().authenticated())
         .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
         .sessionManagement(s->s.sessionCreationPolicy( SessionCreationPolicy.STATELESS))
         .httpBasic(Customizer.withDefaults())
         .build();
 }


 @Bean
 JwtDecoder jwtDecoder(){
  SecretKey originalKey = new SecretKeySpec(secret.getBytes(), "HS256");
   return NimbusJwtDecoder.withSecretKey(originalKey).build();
 }

 @Bean
 JwtEncoder jwtEncoder(){
  SecretKey originalKey = new SecretKeySpec(secret.getBytes(), "HS256");
  JWKSource<SecurityContext> immutableSecret = new ImmutableSecret<SecurityContext>(originalKey);
  return new NimbusJwtEncoder(immutableSecret);
 }
}