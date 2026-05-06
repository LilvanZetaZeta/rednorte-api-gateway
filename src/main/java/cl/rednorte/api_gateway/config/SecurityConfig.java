package cl.rednorte.api_gateway.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.reactive.function.client.WebClient;

import cl.rednorte.api_gateway.security.CustomJwtAuthenticationConverter;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Value("${SUPABASE_JWKS_URI}")
    private String jwkSetUri;

    @Value("${SUPABASE_ANON_KEY}")
    private String anonKey;

    @Autowired
    private CustomJwtAuthenticationConverter customJwtConverter;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeExchange(exchanges -> exchanges
                // RUTAS PÚBLICAS
                .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .pathMatchers("/actuator/health").permitAll()
                .pathMatchers(HttpMethod.POST, "/api/usuarios").permitAll()

                // RUTAS DE DIRECTOR
                .pathMatchers(HttpMethod.POST, "/api/centros-medicos/**").hasRole("DIRECTOR")
                .pathMatchers(HttpMethod.PUT, "/api/centros-medicos/**").hasRole("DIRECTOR")
                .pathMatchers(HttpMethod.DELETE, "/api/centros-medicos/**").hasRole("DIRECTOR")

                // RUTAS DE ADMINISTRATIVOS Y DIRECTORES
                .pathMatchers(HttpMethod.GET, "/api/lista-espera/centro/**").hasAnyRole("DIRECTOR", "ADMINISTRATIVO")

                // RUTAS DE MÉDICOS
                .pathMatchers(HttpMethod.GET, "/api/reservas/medico/**").hasRole("MEDICO")

                // ===== RUTAS DEL MS-PORTAL =====
                .pathMatchers(HttpMethod.GET, "/api/perfil-pacientes/**").hasAnyRole("PACIENTE", "ADMINISTRATIVO", "DIRECTOR")
                .pathMatchers(HttpMethod.POST, "/api/perfil-pacientes/**").hasAnyRole("PACIENTE", "ADMINISTRATIVO", "DIRECTOR")
                .pathMatchers(HttpMethod.PUT, "/api/perfil-pacientes/**").hasAnyRole("PACIENTE", "ADMINISTRATIVO", "DIRECTOR")
                .pathMatchers(HttpMethod.DELETE, "/api/perfil-pacientes/**").hasRole("DIRECTOR")

                .pathMatchers(HttpMethod.GET, "/api/historial-citas/**").hasAnyRole("PACIENTE", "MEDICO", "ADMINISTRATIVO", "DIRECTOR")
                .pathMatchers(HttpMethod.POST, "/api/historial-citas/**").hasAnyRole("ADMINISTRATIVO", "MEDICO", "DIRECTOR")

                // CUALQUIER OTRA RUTA
                .anyExchange().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(customJwtConverter))
            );

        return http.build();
    }

    @Bean
    public ReactiveJwtDecoder jwtDecoder() {
        WebClient webClient = WebClient.builder()
                .defaultHeader("apikey", anonKey)
                .build();

        return NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri)
                .webClient(webClient)
                .build();
    }
}