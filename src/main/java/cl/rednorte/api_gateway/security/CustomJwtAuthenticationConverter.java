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
import java.util.List;

@Component
public class CustomJwtAuthenticationConverter implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {

    private final WebClient webClient;

    public CustomJwtAuthenticationConverter(
            WebClient.Builder webClientBuilder, 
            @Value("${MS_GESTION_URL:http://localhost:8081}") String baseUrl) {
        this.webClient = webClientBuilder.baseUrl(baseUrl).build();
    }

    @Override
    public Mono<AbstractAuthenticationToken> convert(Jwt jwt) {
        String idAuth = jwt.getSubject();

        return webClient.get()
                .uri("/api/usuarios/perfil/" + idAuth)
                .retrieve()
                .bodyToMono(UsuarioPerfilDto.class)
                .map(perfil -> {
                    GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + perfil.getRol());
                    List<GrantedAuthority> authorities = Collections.singletonList(authority);
                    return (AbstractAuthenticationToken) new JwtAuthenticationToken(jwt, authorities);
                })
                .defaultIfEmpty(new JwtAuthenticationToken(jwt, Collections.emptyList()))
                .onErrorResume(e -> Mono.just(new JwtAuthenticationToken(jwt, Collections.emptyList())));
    }
}