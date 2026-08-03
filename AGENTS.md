# Repository guide
 
## Commands
 
- Install dependencies: `mvn install`
- Start spring boot: `mvn spring-boot:run`
- Run unit tests: `mvn clean test`
 
## Coding conventions
 
- Prefer small, focused modules with explicit types.
- Keep business logic in pure functions where possible.
- Match existing component and file naming patterns.
- Do not add a new dependency unless the existing stack cannot solve the problem.
 
## Verification
 
Before calling work finished, run:
 
1. `mvn clean test`
 
If a command fails, fix the issue and rerun it.