package com.lisha.Api.Gateway.configuration;

import com.lisha.Api.Gateway.filter.AuthenticationExceptionHandler;
import com.lisha.Api.Gateway.filter.AuthenticationFilter;
import com.lisha.Api.Gateway.utilities.PropertiesReader;
import com.lisha.Api.Gateway.utilities.StringConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfigurer  {

    @Autowired
    AuthenticationExceptionHandler authenticationExceptionHandler;
    @Autowired
    AuthenticationFilter authenticationFilter;

    private static final String USERNAME = PropertiesReader.getProperty(StringConstants.USERNAME);
    private static final String PASSWORD = PropertiesReader.getProperty(StringConstants.PASSWORD);
    private static final String ROLE = PropertiesReader.getProperty(StringConstants.ROLE);

    @Bean
    public SecurityFilterChain getSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests.requestMatchers("/actuators/**").hasRole(StringConstants.ROLE_ADMIN))
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(requests -> requests.anyRequest().permitAll())
                .logout(logout -> logout.logoutUrl("/logout").invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID"))
                .exceptionHandling(exception -> exception.authenticationEntryPoint(authenticationExceptionHandler))
                .httpBasic(withDefaults())
                .addFilterAfter(authenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();

    }
    @Bean
    public UserDetailsService userDetailsService()
    {
        UserDetails user1 = User.withUsername(USERNAME)
                .password(passwordEncoder().encode(PASSWORD))
                .roles(ROLE)
                .build();
        UserDetails user2 = User.withUsername("Jack")
                .password(passwordEncoder().encode("Jack@123"))
                .roles("USER")
                .build();
        //For H2 database UserDetailsService
        return new InMemoryUserDetailsManager(user1,user2); //InMemoryUserDetailsManager is a child of
        // UserDetailsService
    }
    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }

}
