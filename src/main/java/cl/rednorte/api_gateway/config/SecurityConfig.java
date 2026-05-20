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
                
                // RUTAS PARA PORTAL PACIENTE
                .pathMatchers(HttpMethod.GET, "/api/especialidades/**").permitAll()
                .pathMatchers(HttpMethod.GET, "/api/centros-medicos/**").permitAll()
                .pathMatchers(HttpMethod.GET, "/api/usuarios/medicos/buscar").permitAll()

                //  RUTAS EXCLUSIVAS DE DIRECTOR
                .pathMatchers(HttpMethod.POST, "/api/usuarios/asignar-medico").hasRole("DIRECTOR")
                .pathMatchers(HttpMethod.POST, "/api/usuarios/asignar-admin").hasRole("DIRECTOR")
                .pathMatchers(HttpMethod.GET, "/api/usuarios/admins-disponibles").hasRole("DIRECTOR")
                .pathMatchers(HttpMethod.PATCH, "/api/usuarios/*/rol").hasRole("DIRECTOR")
                .pathMatchers(HttpMethod.POST, "/api/centros-medicos/**").hasRole("DIRECTOR")
                .pathMatchers(HttpMethod.PUT, "/api/centros-medicos/**").hasRole("DIRECTOR")
                .pathMatchers(HttpMethod.DELETE, "/api/centros-medicos/**").hasRole("DIRECTOR")
                .pathMatchers(HttpMethod.PUT, "/api/usuarios/**").hasRole("DIRECTOR")
                .pathMatchers(HttpMethod.DELETE, "/api/usuarios/**").hasRole("DIRECTOR")

                //  RUTAS DE DIRECTOR Y ADMINISTRATIVO LOCAL
                .pathMatchers(HttpMethod.GET, "/api/usuarios/staff").hasAnyRole("DIRECTOR", "ADMINISTRATIVO")
                
                //  RUTAS DE MÉTRICAS (Director, Administrativo y Secretaria)
                .pathMatchers(HttpMethod.GET, "/api/gestion/metricas/**").hasAnyRole("DIRECTOR", "ADMINISTRATIVO", "SECRETARIA")

                //  RUTAS DE OPERACIONES (Listas de espera y Agenda del centro)
                .pathMatchers("/api/lista-espera/**").hasAnyRole("DIRECTOR", "ADMINISTRATIVO", "SECRETARIA")
                .pathMatchers(HttpMethod.GET, "/api/reservas/centro/**").hasAnyRole("DIRECTOR", "ADMINISTRATIVO", "SECRETARIA")

                //  RUTAS DE MÉDICOS
                .pathMatchers(HttpMethod.GET, "/api/reservas/medico/**").hasRole("MEDICO")

                // ===== RUTAS DEL MS-PORTAL ===== 
                // Añadida la SECRETARIA a los permisos de perfiles y citas
                .pathMatchers(HttpMethod.GET, "/api/perfil-pacientes/**").hasAnyRole("PACIENTE", "ADMINISTRATIVO", "SECRETARIA", "DIRECTOR")
                .pathMatchers(HttpMethod.POST, "/api/perfil-pacientes/**").hasAnyRole("PACIENTE", "ADMINISTRATIVO", "SECRETARIA", "DIRECTOR")
                .pathMatchers(HttpMethod.PUT, "/api/perfil-pacientes/**").hasAnyRole("PACIENTE", "ADMINISTRATIVO", "SECRETARIA", "DIRECTOR")
                .pathMatchers(HttpMethod.DELETE, "/api/perfil-pacientes/**").hasRole("DIRECTOR")

                .pathMatchers(HttpMethod.GET, "/api/historial-citas/**").hasAnyRole("PACIENTE", "MEDICO", "ADMINISTRATIVO", "SECRETARIA", "DIRECTOR")
                .pathMatchers(HttpMethod.POST, "/api/historial-citas/**").hasAnyRole("ADMINISTRATIVO", "SECRETARIA", "MEDICO", "DIRECTOR")

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