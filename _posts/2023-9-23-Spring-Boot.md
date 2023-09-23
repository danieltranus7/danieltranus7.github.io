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