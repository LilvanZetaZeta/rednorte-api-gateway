# RedNorte - API Gateway

El API Gateway es la puerta de entrada unificada para todos los microservicios de la plataforma médica **RedNorte**. Está construido sobre **Spring Cloud Gateway** de forma reactiva y se encarga del enrutamiento de peticiones, la gestión de CORS y la autenticación perimetral mediante JWT con tokens de **Supabase**.

## Características Principales

*   **Enrutamiento Centralizado**: Redirecciona peticiones hacia los microservicios correspondientes según los prefijos de las rutas:
    *   `/api/gestion/**` -> `rednorte-ms-gestion` (Puerto 8081)
    *   `/api/portal/**` -> `rednorte-ms-portal` (Puerto 8082)
    *   `/api/reasignaciones/**` -> `rednorte-ms-reasignacion` (Puerto 8083)
    *   `/api/notificaciones/**` -> `rednorte-ms-notificaciones` (Puerto 8085)
*   **Seguridad y Autenticación**: Valida tokens JWT emitidos por el proveedor de autenticación de Supabase usando un Resource Server reactivo.
*   **Configuración de CORS**: Maneja cabeceras de seguridad y orígenes permitidos para el cliente frontend.

## Tecnologías Utilizadas

*   **Java 21**
*   **Spring Boot 3.2.5**
*   **Spring Cloud Gateway (Reactive)**
*   **Spring Boot Starter OAuth2 Resource Server**
*   **Spring Dotenv** (para cargar variables del archivo `.env`)
*   **Lombok**

## Requisitos Previos

*   Java 21 o superior.
*   Maven 3.8 o superior.
*   Archivo de variables de entorno `.env` en la raíz del directorio.

## Variables de Entorno (.env)

Crea un archivo `.env` en la raíz de este directorio con la siguiente estructura de variables (reemplaza los valores entre `<>` con tus configuraciones correspondientes):

```env
# Puerto en el que se ejecutará el API Gateway (por defecto 8080)
PORT=<puerto_api_gateway>

# URL base de tu proyecto de Supabase (ej: https://<project-id>.supabase.co)
SUPABASE_URL=<url_proyecto_supabase>

# URL base del Microservicio de Gestión (ej: http://localhost:8081)
MS_GESTION_URL=<url_microservicio_gestion>

# URL base del Microservicio Portal (ej: http://localhost:8082)
MS_PORTAL_URL=<url_microservicio_portal>

# URL base del Microservicio de Reasignación (ej: http://localhost:8083)
MS_REASIGNACION_URL=<url_microservicio_reasignacion>

# URL base del Microservicio de Notificaciones (ej: http://localhost:8085)
MS_NOTIFICACIONES_URL=<url_microservicio_notificaciones>

# URL base de la Aplicación Frontend (ej: http://localhost:5173)
MS_FRONTEND_URL=<url_frontend>

# URL de los JWKs de Supabase para validar los tokens JWT (ej: https://<project-id>.supabase.co/auth/v1/.well-known/jwks.json)
SUPABASE_JWKS_URI=<url_supabase_jwks>

# URI del emisor de tokens (issuer) para verificación (ej: https://<project-id>.supabase.co/auth/v1)
issuer-uri=<uri_emisor_tokens_supabase>
```

## Instrucciones de Ejecución

### Desarrollo Local

Para iniciar el servidor localmente en el puerto `8080`:

```bash
./mvnw spring-boot:run
```

### Ejecutar Pruebas

Para correr el suite de pruebas del gateway:

```bash
./mvnw test -Dnet.bytebuddy.experimental=true
```

## Dockerización

Construir la imagen de Docker:

```bash
docker build -t rednorte-api-gateway .
```
