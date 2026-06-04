package cl.rednorte.api_gateway.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import cl.rednorte.api_gateway.dto.UsuarioPerfilDto;

import java.util.Collections;

@Component
public class CustomJwtAuthenticationConverter implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {

    private static final Logger log = LoggerFactory.getLogger(CustomJwtAuthenticationConverter.class);

    private final WebClient webClient;

    public CustomJwtAuthenticationConverter(
            WebClient.Builder webClientBuilder,
            @Value("${MS_PORTAL_URL:http://localhost:8082}") String msPortalUrl) {
        this.webClient = webClientBuilder.baseUrl(msPortalUrl).build();
    }

    @Override
    public Mono<AbstractAuthenticationToken> convert(Jwt jwt) {
        String idAuth = jwt.getSubject();

        return webClient.get()
                .uri("/api/portal/usuarios/perfil/" + idAuth)
                .retrieve()
                .bodyToMono(UsuarioPerfilDto.class)
                .flatMap(perfil -> {
                    if (perfil == null || perfil.getRol() == null || perfil.getRol().isBlank()) {
                        log.warn("Perfil sin rol válido en ms_portal para idAuth={}", idAuth);
                        return Mono.error(new BadCredentialsException(
                                "El usuario autenticado no tiene un perfil o rol válido en el sistema."));
                    }
                    GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + perfil.getRol());
                    return Mono.just((AbstractAuthenticationToken) new JwtAuthenticationToken(jwt,
                            Collections.singletonList(authority)));
                })
                .onErrorMap(WebClientResponseException.class, ex -> {
                    if (ex.getStatusCode() == HttpStatus.NOT_FOUND) {
                        log.warn("Perfil no encontrado en ms_portal para idAuth={}", idAuth);
                        return new BadCredentialsException("Perfil de usuario no encontrado.");
                    }
                    log.error("Error HTTP al consultar perfil en ms_portal: status={}, body={}",
                            ex.getStatusCode(), ex.getResponseBodyAsString());
                    return new BadCredentialsException(
                            "No se pudo validar el perfil del usuario. Intente nuevamente.");
                })
                .onErrorMap(ex -> !(ex instanceof org.springframework.security.core.AuthenticationException), ex -> {
                    log.error("Error inesperado al obtener perfil desde ms_portal para idAuth={}", idAuth, ex);
                    return new BadCredentialsException("Error al validar el perfil del usuario.");
                });
    }
}
