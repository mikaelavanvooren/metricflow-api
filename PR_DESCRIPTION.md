# Migrate metricflow-api from Spring Boot 2.7 to 4.1.0

## Summary

Upgrades the MetricFlow API from **Spring Boot 2.7.18 (Java 11)** to **Spring Boot 4.1.0 (Java 17)**, migrating off the abandoned Springfox library to springdoc-openapi, moving from `javax.*` to `jakarta.*`, and adopting Spring Boot 4's new modular starters. The build compiles cleanly, the full test suite passes, and the repackaged executable jar builds.

## Why

Spring Boot 2.7 is end-of-life. This brings the service onto a supported, modern runtime (Spring Framework 7, Jakarta EE 11, Servlet 6.1) and replaces Springfox (unmaintained and incompatible with Boot 3+) with the actively maintained springdoc-openapi (OpenAPI 3).

## Version changes

| Component | Before | After |
|---|---|---|
| Spring Boot parent | 2.7.18 | 4.1.0 |
| Java baseline | 11 | 17 |
| API docs | `springfox-boot-starter` 3.0.0 | `springdoc-openapi-starter-webmvc-ui` 3.1.0 |
| Web starter | `spring-boot-starter-web` (deprecated in Boot 4) | `spring-boot-starter-webmvc` |
| Validation | (transitive) | `spring-boot-starter-validation` (added; web starter no longer bundles it) |
| JSON / Jackson | (transitive, Jackson 2) | `spring-boot-starter-jackson` (added; Boot 4 modularization) → Jackson 3 |
| Test starter | `spring-boot-starter-test` | `spring-boot-starter-webmvc-test` |
| Persistence namespace | `javax.persistence.*` | `jakarta.persistence.*` |
| Validation namespace | `javax.validation.*` | `jakarta.validation.*` |
| H2 | 1.x (managed) | 2.4.240 (managed by Boot 4 BOM) |
| Hibernate | 5.x | 7.4.1 (managed by Boot 4 BOM) |

## Changes

### Build (`pom.xml`)
- Parent → `spring-boot-starter-parent` 4.1.0; `java.version` → 17.
- Removed `io.springfox:springfox-boot-starter` (incompatible with Boot 3+/4).
- Added `springdoc-openapi-starter-webmvc-ui` 3.1.0.
- `spring-boot-starter-web` → `spring-boot-starter-webmvc` (Boot 4 modularization).
- Added `spring-boot-starter-validation` and `spring-boot-starter-jackson` (no longer pulled in transitively by the web starter in Boot 4).
- `spring-boot-starter-test` → `spring-boot-starter-webmvc-test` (provides MockMvc + `@AutoConfigureMockMvc`, brings `starter-test` transitively).

### Namespace migration (`javax` → `jakarta`)
- `model/Dashboard.java`, `model/Metric.java`: `jakarta.persistence.*`.
- `model/Metric.java`: `jakarta.validation.constraints.NotNull`.

### API documentation (Springfox → springdoc-openapi)
- `config/SwaggerConfig.java`: replaced the two `springfox.documentation...Docket` beans with two `org.springdoc.core.models.GroupedOpenApi` beans (`public-metrics` → `/api/v1/metrics/**`, `internal-dashboards` → `/api/v1/dashboards/**`), preserving the public-vs-internal docs split. Added an `io.swagger.v3.oas.models.OpenAPI` bean carrying the title/version/contact/license info.
- `controller/DashboardController.java`, `controller/MetricsController.java`: Springfox v2 annotations (`io.swagger.annotations.*`) → OpenAPI v3 (`io.swagger.v3.oas.annotations.*`): `@Api`→`@Tag`, `@ApiOperation`→`@Operation`, `@ApiParam`→`@Parameter`, `@ApiImplicitParams`/`@ApiImplicitParam`→`@Parameter` on the method params, `@ApiResponse(code=,message=)`→`@ApiResponse(responseCode=,description=)`.

### Configuration (`application.properties`)
- Removed `springfox.documentation.swagger-ui.enabled=true`; springdoc swagger-ui is enabled by default at `/swagger-ui.html`.

### Schema fix (`model/Metric.java`)
- `VALUE` is a reserved keyword in H2 2.x (managed by Spring Boot 4). Hibernate's `ddl-auto=update` failed to create the `metric` table with a column named `value`. Mapped the field to a non-reserved column via `@Column(name = "metric_value")`. The Java API (`getValue()`/`setValue()`) and JSON contract are unchanged.

### Tests (new — `src/test/java/com/metricflow/api/`)
- `MetricflowApiApplicationTests` — `@SpringBootTest` smoke test verifying the full context (JPA/Hibernate 7 + H2 2.x + springdoc + WebMVC) boots.
- `DashboardApiTests` — `@SpringBootTest` + `@AutoConfigureMockMvc` MockMvc tests: create, list with `owner`/`sharedOnly` filters, delete.
- `MetricApiTests` — MockMvc tests: create, fetch by id, list, and missing-id behavior.
- Tests use the real in-memory services (no mocking), sidestepping the Spring Boot 4 removal of `@MockBean` and exercising the full stack.

## Migration notes
- **`@MockBean`/`@SpyBean` removed in Boot 4.** This codebase had no tests, so nothing to migrate; new tests deliberately avoid mocking.
- **`@AutoConfigureMockMvc` moved** to package `org.springframework.boot.webmvc.test.autoconfigure` under Boot 4 modularization.
- **Jackson 3**: Boot 4 auto-configures `tools.jackson.databind.ObjectMapper` (Jackson 3), not the legacy `com.fasterxml.jackson.databind.ObjectMapper`. Tests use the Jackson 3 type.
- **`spring.jpa.open-in-view`** logs a warning by default (unchanged from Boot 2); left as-is.

## Verification

Run locally:
```
mvn clean test
mvn package
```

Results:
- `mvn clean test` → **BUILD SUCCESS**, `Tests run: 5, Failures: 0, Errors: 0, Skipped: 0`.
- `mvn package` → **BUILD SUCCESS**, repackaged executable jar `target/metricflow-api-0.1.0.jar` (~57 MB).
- No DDL/schema-generation errors (H2 reserved-keyword issue resolved).

## Out of scope
- No Spring Security, Spring Cloud, Actuator, or native-image changes (not present/used).
- No REST API behavior changes; endpoint paths, request/response shapes, and the two OpenAPI doc groups are preserved.
