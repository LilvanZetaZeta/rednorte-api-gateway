package cl.rednorte.api_gateway.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import cl.rednorte.api_gateway.dto.UsuarioPerfilDto;

import java.util.Collections;

@Component
public class CustomJwtAuthenticationConverter implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {

    private final WebClient webClient;

    public CustomJwtAuthenticationConverter(
            WebClient.Builder webClientBuilder,
            // Ahora consultamos a MS_PORTAL porque él tiene las lecturas
            @Value("${MS_PORTAL_URL:http://localhost:8082}") String msPortalUrl) {
        this.webClient = webClientBuilder.baseUrl(msPortalUrl).build();
    }

    @Override
    public Mono<AbstractAuthenticationToken> convert(Jwt jwt) {
        String idAuth = jwt.getSubject();

        return webClient.get()
                // La nueva ruta refactorizada en MS_PORTAL
                .uri("/api/portal/usuarios/perfil/" + idAuth)
                .retrieve()
                .bodyToMono(UsuarioPerfilDto.class)
                .map(perfil -> {
                    GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + perfil.getRol());
                    return (AbstractAuthenticationToken) new JwtAuthenticationToken(jwt, Collections.singletonList(authority));
                })
                .defaultIfEmpty((AbstractAuthenticationToken) new JwtAuthenticationToken(jwt, Collections.emptyList()))
                .onErrorResume(e -> {
                    System.err.println("Error al obtener perfil desde ms_portal: " + e.getMessage());
                    return Mono.just((AbstractAuthenticationToken) new JwtAuthenticationToken(jwt, Collections.emptyList()));
                });
    }
}