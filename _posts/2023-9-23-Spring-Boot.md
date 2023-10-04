---
layout: post
title: Spring Boot
---
## Eureka Server
------
Add dependency:
```gradle
implementation group: 'org.springframework.cloud', name: 'spring-cloud-starter-netflix-eureka-server', version: '4.0.3'
```

Add @EnableEurekaServer
```java
@EnableEurekaServer
@SpringBootApplication
public class ServicediscoveryApplication {

	public static void main(String[] args) {
		SpringApplication.run(ServicediscoveryApplication.class, args);
	}

}
```

Update application config to prevent register itselft to the registry
```yml
eureka.client.register-with-eureka=false
eureka.client.fetch-registry=false
```

Access: [localhost:8761](http://localhost:8761)

## Eureka Client
------
Add dependency:
```gradle
implementation group: 'org.springframework.cloud', name: 'spring-cloud-starter-netflix-eureka-client', version: '4.0.3'
implementation group: 'org.springframework.boot', name: 'spring-boot-starter-web', version: '3.1.2'
```

Update application config to prevent register itselft to the registry
```yml
eureka.client.service-url.default-zone: http://localhost:8761/eureka
```

## Swagger
------
Add dependency:
```gradle
implementation 'org.springdoc:springdoc-openapi-starter-webmvc-ui:2.1.0'
```

[http://localhost:8081/v3/api-docs](http://localhost:8081/v3/api-docs)

[http://localhost:8081/swagger-ui/index.html](http://localhost:8081/swagger-ui/index.html)

## Lombok
------
Add dependency:
```gradle
compileOnly 'org.projectlombok:lombok:1.18.30'
annotationProcessor 'org.projectlombok:lombok:1.18.30'

testCompileOnly 'org.projectlombok:lombok:1.18.30'
testAnnotationProcessor 'org.projectlombok:lombok:1.18.30'
```

Anotations
```java
@NoArgsConstructor

@RequiredArgsConstructor

@AllArgsConstructor

@Getter/@Setter

@ToString

@EqualsAndHashCode

@Builder
```

## Rest Controller
------
```java
@RestController
@RequestMapping("/api")
public class MyRestController {
    @PostMapping("/users")
    public User createUser(@RequestBody User user) {
        // Logic to create a user
    }

    @PutMapping("/users/{id}")
    public User updateUser(@PathVariable("id") Long id, @RequestBody User user) {
        // Logic to update a user with the given ID
    }

    @DeleteMapping("/users/{id}")
    public void deleteUser(@PathVariable("id") Long id) {
        // Logic to delete a user with the given ID
    }

    @GetMapping("/users")
    public String getUser(@RequestParam("username") String username) {
        return "Hello, " + name + "!";
    }
}
```

## Mongodb
------
Docker-compose
```yaml
version: '3'
services:
  mongodb:
    image: mongo:latest
    container_name: "mongodb"
    environment:
      - MONGO_LOG_DIR=/dev/null
    ports:
      - 27017:27017
```

Add dependency:
```gradle
implementation 'org.springframework.boot:spring-boot-starter-data-mongodb'
```

```java
@EnableMongoAuditing
@SpringBootApplication
public class AuthApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthApplication.class, args);
	}

}
```

Entity
```java
@Data
@Document(collation = "users")
public class User {
    @Id
    private String id;
    
    @Field("username")
    private String userName;
    
    @CreatedDate
    private Instant createdAt;

    @LastModifiedDate
    private Instant updatedAt;
}

```

Repository
```java
@Repository
public interface UserRepository extends MongoRepository<User, String> {
    
}
```

Service
```java
@Service
@AllArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    public User create(User user) {
        return userRepository.save(user);
    }
}
```

## JWT
### Dependencies
```gradle
implementation 'org.springframework.boot:spring-boot-starter-security'
implementation 'io.jsonwebtoken:jjwt:0.9.1'
implementation "javax.xml.bind:jaxb-api:2.4.0-b180830.0359"
```
### Security Config
```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final MyUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final JwtAuthFilter jwtAuthFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(request -> request.requestMatchers(
                        "/users/register/**",
                                "/users/login/**",
                                "/swagger-ui/**", "/v3/api-docs/**").permitAll()
                        .anyRequest().authenticated())
                .sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .authenticationProvider(authenticationProvider());

        return http.build();
    }

    private AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder);
        return authenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}

```
### UserDetailsService
```java
@Service
@AllArgsConstructor
@Slf4j
public class MyUserDetailsService implements UserDetailsService {

    private UserService userService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var user = userService.findByUsername(username).map(MyUserDetails::new).orElseThrow(() -> new UsernameNotFoundException("Username not found"));

        return user;
    }
}
```
### Request Filter
```java
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {
    private static final String BEARER_HEADER = "Bearer";

    private final JwtTokenProvider jwtTokenProvider;
    private final UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith(BEARER_HEADER)) {
            filterChain.doFilter(request, response);
            return;
        }

        String jwtToken = authHeader.substring(BEARER_HEADER.length() + 1);

        if (jwtTokenProvider.validateToken(jwtToken)) {
            Claims claims = jwtTokenProvider.getClaimsFromJWT(jwtToken);
            String username = claims.getSubject();

            var authenToken = userService.findByUsername(username)
                    .map(MyUserDetails::new)
                    .map(myUserDetails -> {
                        return new UsernamePasswordAuthenticationToken(myUserDetails, null, myUserDetails.getAuthorities());
                    })
                    .orElse(null);

            SecurityContextHolder.getContext().setAuthentication(authenToken);
        } else {
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }
}
```
### JWT config
```java
@Data
@Component
@NoArgsConstructor
public class JwtConfig {
    @Value("${security.jwt.expiration:#{24*60*60}}")
    private int expiration;

    @Value("${security.jwt.secret:JwtSecretKey}")
    private String secret;
}
```
### JWT Service
```java
@Service
@RequiredArgsConstructor
@Slf4j
public class JwtTokenProvider {
    private final JwtConfig jwtConfig;

    public String generateToken(Authentication authentication) {
        long now = System.currentTimeMillis();
        long exp = now + jwtConfig.getExpiration() * 1_000;
        return Jwts.builder().setSubject(authentication.getName())
                .claim("authorities", authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(exp))
                .signWith(SignatureAlgorithm.HS512, jwtConfig.getSecret().getBytes())
                .compact();
    }

    public Claims getClaimsFromJWT(String token) {
        return Jwts.parser()
                .setSigningKey(jwtConfig.getSecret().getBytes())
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean validateToken(String authToken) {
        try {
            Jwts.parser()
                    .setSigningKey(jwtConfig.getSecret().getBytes())
                    .parseClaimsJws(authToken);

            return true;
        } catch (Exception ex) {
            log.error("Validate token err {}", ex);
        }

        return false;
    }
}
```
### Login
```java
@PostMapping("/login")
public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
    log.info("login {}", loginRequest);

    Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword(), new ArrayList<>()));
    String jwt = tokenProvider.generateToken(authentication);
    var res = new JwtAuthenticationResponse();
    res.setAccessToken(jwt);
    return ResponseEntity.ok(res);
}
```
