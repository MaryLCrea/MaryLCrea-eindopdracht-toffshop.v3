
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(auth -> auth
//
////                                .requestMatchers(HttpMethod.POST, "/users").permitAll()
////                                .requestMatchers(HttpMethod.POST, "/auth").permitAll()
////
////                                .requestMatchers(HttpMethod.POST, "/contacts/**").permitAll()
////                                .requestMatchers(HttpMethod.POST, "/order-items/**").permitAll()
////                                .requestMatchers(HttpMethod.POST, "/image/**").permitAll()
////                                .requestMatchers(HttpMethod.POST, "/carts/**").permitAll()
////                                .requestMatchers(HttpMethod.POST, "/products/**").permitAll()
////
////                                .requestMatchers(HttpMethod.GET, "/home/**").permitAll()
////                                .requestMatchers(HttpMethod.GET, "/users/**").permitAll()
////                                .requestMatchers(HttpMethod.GET, "/contacts/**").permitAll()
////                                .requestMatchers(HttpMethod.GET, "/order-items/**").permitAll()
////                                .requestMatchers(HttpMethod.GET, "/image/**").permitAll()
////                                .requestMatchers(HttpMethod.GET, "/carts/**").permitAll()
////                                .requestMatchers(HttpMethod.GET, "/products/**").permitAll()
////
////                                .requestMatchers(HttpMethod.PUT, "/auth/**").permitAll()
////                                .requestMatchers(HttpMethod.PUT, "/users/**").permitAll()
////                                .requestMatchers(HttpMethod.PATCH, "/contacts/**").permitAll()
////                                .requestMatchers(HttpMethod.PUT, "/order-items/**").permitAll()
////                                .requestMatchers(HttpMethod.PUT, "/image/**").permitAll()
////                                .requestMatchers(HttpMethod.PUT, "/carts/**").permitAll()
////                                .requestMatchers(HttpMethod.PUT, "/products/**").permitAll()
////
////                                 .requestMatchers("/order_items").hasRole("ADMIN")
////                                .requestMatchers("/carts").authenticated()
////                                .requestMatchers("/contacts", "/ADMIN/*").authenticated()
////
////                                .requestMatchers("/carts").hasRole("ADMIN")
//
//                                .requestMatchers(HttpMethod.POST, "/users").permitAll()
//                                .requestMatchers(HttpMethod.POST, "/auth").permitAll()
////                                .requestMatchers("/secret").hasRole("ADMIN")
////                                .requestMatchers("/hello").authenticated()
////                                .requestMatchers("/profiles", "/profiles/*").authenticated()
//                        .anyRequest().denyAll()
//                )
//                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                .csrf(csrf -> csrf.disable())
//                .addFilterBefore(new JwtRequestFilter(jwtService, userDetailsService()), UsernamePasswordAuthenticationFilter.class);
//
//        return http.build();
//    }
//}

package toff.novi.eindopdrachttoffshop.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import toff.novi.eindopdrachttoffshop.repositories.UserRepository;

@Configuration
public class SecurityConfig {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    public SecurityConfig(JwtService jwtService, UserRepository userRepository) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public MyUserDetailsService userDetailsService() {
        return new MyUserDetailsService(userRepository);
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return new org.springframework.security.authentication.ProviderManager(authProvider);
    }

    @Bean
    public JwtRequestFilter jwtRequestFilter() {
        return new JwtRequestFilter(jwtService, userDetailsService());
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/auth").permitAll()
                        .requestMatchers(HttpMethod.POST, "/users").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtRequestFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}

