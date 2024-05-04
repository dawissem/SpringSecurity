package com.teachCode.springSecurity.config;

import com.teachCode.springSecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
//L'annotation @EnableWebSecurity active la sécurité Web de Spring et configure les aspects
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final UserService userService;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                //Une liste blanche des requêtes {/api/v1/auth/**},
                .authorizeHttpRequests(request -> request.requestMatchers("/api/v1/auth/**")
                        //toute autre requête doit être authentifiée
                        .permitAll().anyRequest().authenticated())
                //Gestion sans état,
                // ce qui signifie que nous ne devrions pas stocker l'état d'authentification
                .sessionManagement(manager -> manager.sessionCreationPolicy(STATELESS))
                //DaoAuthenticationProvider - qui est responsable de récupérer les informations utilisateur
                // et d'encoder/décoder les mots de passe.
        //Ajout de JwtAuthenticationFilter avant UsernamePasswordAuthenticationFilter
                // car nous extrayons le nom d'utilisateur et le mot de passe,
        //puis les mettons à jour dans SecurityContextHolder dans JwtAuthenticationFilter.
                .authenticationProvider(authenticationProvider()).addFilterBefore(
                        jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    //Définition du bean passwordEncoder que Spring utilisera pour décoder les mots de passe
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    //Définition du bean authenticationProvider utilisé lors du processus d'authentification
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userService.userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    //Définition du bean authentication manager.
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
            throws Exception {
        return config.getAuthenticationManager();
    }
}

