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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.reactive.function.client.WebClient;

import cl.rednorte.api_gateway.security.CustomJwtAuthenticationConverter;

import java.util.Arrays;

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
            // Activamos la configuración de CORS para el frontend
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .authorizeExchange(exchanges -> exchanges
                
                // 1. RUTAS PÚBLICAS Y DE REGISTRO
                .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .pathMatchers("/actuator/health").permitAll()
                .pathMatchers(HttpMethod.POST, "/api/gestion/usuarios").permitAll()
                
                // 2. LECTURAS PÚBLICAS (MS-PORTAL)
                .pathMatchers(HttpMethod.GET, "/api/portal/especialidades/**").permitAll()
                .pathMatchers(HttpMethod.GET, "/api/portal/centros-medicos/**").permitAll()
                .pathMatchers(HttpMethod.GET, "/api/portal/usuarios/medicos/buscar").permitAll()

                // ==========================================
                // REGLAS ESTRICTAS DE BORRADO (SOLO DIRECTOR)
                // ==========================================
                .pathMatchers(HttpMethod.DELETE, "/**").hasRole("DIRECTOR")

                // ==========================================
                // RUTAS DE DIRECTOR
                // ==========================================
                .pathMatchers(HttpMethod.POST, "/api/gestion/centros-medicos/**").hasRole("DIRECTOR")
                .pathMatchers(HttpMethod.PUT, "/api/gestion/centros-medicos/**").hasRole("DIRECTOR")
                .pathMatchers(HttpMethod.PATCH, "/api/gestion/centros-medicos/**").hasRole("DIRECTOR")
                
                .pathMatchers(HttpMethod.POST, "/api/gestion/especialidades/**").hasRole("DIRECTOR")
                .pathMatchers(HttpMethod.PUT, "/api/gestion/especialidades/**").hasRole("DIRECTOR")

                .pathMatchers(HttpMethod.POST, "/api/gestion/usuarios/asignar-admin").hasRole("DIRECTOR")
                .pathMatchers(HttpMethod.GET, "/api/portal/usuarios/admins-disponibles").hasRole("DIRECTOR")
                .pathMatchers(HttpMethod.GET, "/api/portal/metricas/resumen").hasAnyRole("DIRECTOR","SECRETARIA")

                // ==========================================
                // RUTAS DE ADMINISTRADOR LOCAL Y DIRECTOR
                // ==========================================
                .pathMatchers(HttpMethod.POST, "/api/gestion/usuarios/asignar-medico").hasAnyRole("DIRECTOR", "ADMINISTRATIVO")
                .pathMatchers(HttpMethod.PATCH, "/api/gestion/usuarios/*/rol").hasAnyRole("DIRECTOR", "ADMINISTRATIVO")
                .pathMatchers(HttpMethod.PATCH, "/api/gestion/usuarios/*/centro").hasAnyRole("DIRECTOR", "ADMINISTRATIVO")
                .pathMatchers(HttpMethod.PATCH, "/api/gestion/usuarios/*/especialidades").hasAnyRole("DIRECTOR", "ADMINISTRATIVO")
                .pathMatchers(HttpMethod.PUT, "/api/gestion/usuarios/**").hasAnyRole("DIRECTOR", "ADMINISTRATIVO")
                .pathMatchers(HttpMethod.GET, "/api/portal/usuarios/staff").hasAnyRole("DIRECTOR", "ADMINISTRATIVO", "SECRETARIA")
                .pathMatchers(HttpMethod.GET, "/api/portal/metricas/centros").hasAnyRole("DIRECTOR", "ADMINISTRATIVO")

                // ==========================================
                // RUTAS DE SECRETARÍA (Y Superiores)
                // ==========================================
                .pathMatchers("/api/gestion/lista-espera/**").hasAnyRole("DIRECTOR", "ADMINISTRATIVO", "SECRETARIA")
                .pathMatchers(HttpMethod.GET, "/api/portal/lista-espera/**").hasAnyRole("DIRECTOR", "ADMINISTRATIVO", "SECRETARIA", "PACIENTE")
                .pathMatchers(HttpMethod.GET, "/api/portal/reservas/centro/**").hasAnyRole("DIRECTOR", "ADMINISTRATIVO", "SECRETARIA")
                .pathMatchers(HttpMethod.POST, "/api/gestion/reservas/reasignaciones/agenda/bloquear").hasAnyRole("DIRECTOR", "SECRETARIA")

                // ==========================================
                // RUTAS DE MÉDICOS
                // ==========================================
                .pathMatchers(HttpMethod.GET, "/api/portal/reservas/medico/**").hasRole("MEDICO")

                // ==========================================
                // RUTAS MIXTAS (PACIENTE Y STAFF)
                // ==========================================
                .pathMatchers(HttpMethod.POST, "/api/gestion/reservas").hasAnyRole("PACIENTE", "SECRETARIA", "DIRECTOR")
                .pathMatchers(HttpMethod.PUT, "/api/gestion/reservas/*/cancelar").hasAnyRole("PACIENTE", "SECRETARIA", "DIRECTOR")
                .pathMatchers(HttpMethod.PATCH, "/api/gestion/reservas/**").hasAnyRole("SECRETARIA", "MEDICO", "DIRECTOR")
                .pathMatchers(HttpMethod.GET, "/api/portal/reservas/paciente/**").hasAnyRole("PACIENTE", "DIRECTOR", "ADMINISTRATIVO", "SECRETARIA")

                .pathMatchers(HttpMethod.GET, "/api/portal/perfil-pacientes/**").hasAnyRole("PACIENTE", "ADMINISTRATIVO", "SECRETARIA", "DIRECTOR", "MEDICO")
                .pathMatchers(HttpMethod.POST, "/api/gestion/perfil-pacientes/**").hasAnyRole("PACIENTE", "ADMINISTRATIVO", "SECRETARIA", "DIRECTOR")
                .pathMatchers(HttpMethod.PUT, "/api/gestion/perfil-pacientes/**").hasAnyRole("PACIENTE", "ADMINISTRATIVO", "SECRETARIA", "DIRECTOR")

                .pathMatchers(HttpMethod.GET, "/api/portal/historial-citas/**").hasAnyRole("PACIENTE", "MEDICO", "ADMINISTRATIVO", "SECRETARIA", "DIRECTOR")
                .pathMatchers(HttpMethod.POST, "/api/gestion/historial-citas/**").hasAnyRole("MEDICO", "DIRECTOR")

                // CUALQUIER OTRA RUTA requiere autenticación
                .anyExchange().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(customJwtConverter))
            );

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // Permite orígenes desde tu frontend
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:5173", "http://127.0.0.1:5173"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "apikey"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
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