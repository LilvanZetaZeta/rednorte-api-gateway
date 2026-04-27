package cl.rednorte.api_gateway.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
            // Desactivamos CSRF porque usaremos Tokens JWT
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            
            // Habilitamos CORS delegando la configuración al application.yml (¡Línea corregida!)
            .cors(Customizer.withDefaults())
            
            // Configuración de rutas
            .authorizeExchange(exchanges -> exchanges
                // Cualquier petición exige autenticación obligatoria
                .anyExchange().authenticated()
            )
            // Valida el JWT usando la configuración de Auth0
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
            
        return http.build();
    }
}