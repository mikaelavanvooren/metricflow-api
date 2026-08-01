# MetricFlow API — Boot 2 → Boot 3 migration demo fixture

Toy Spring Boot app for a B2B analytics company ("MetricFlow"). Represents a
metrics + dashboard API currently on **Spring Boot 2.7**, using **springfox**
for API docs and **javax.persistence** for JPA entities.

## The story (for the demo intro)

MetricFlow needs to move to Spring Boot 3. That forces two migrations at once:

1. `javax.*` → `jakarta.*` namespace (mechanical — good for a quick "yeah, it
   handles the boring stuff" beat, not the main event)
2. **springfox is archived and has no Jakarta-compatible release.** It has to
   be replaced entirely with **springdoc-openapi**, a different library with
   a structurally different API. This is the real differentiator moment.

## Where the "judgment, not find-replace" moments live

| File | What's tricky |
|---|---|
| `config/SwaggerConfig.java` | Two `Docket` beans with `groupName` + package/path selectors. springdoc's equivalent is `GroupedOpenApi` beans built differently — this isn't a rename, it's a restructure. |
| `controller/DashboardController.java` | `@ApiImplicitParams` with `dataType`/`paramType` strings has no 1:1 springdoc annotation — needs `@Parameter` + schema type. `@ApiResponse(code = 200, ...)` uses an **int** code; springdoc's `@ApiResponse` wants a **String** `responseCode`. Naive find-replace breaks the build here. |
| `controller/MetricsController.java` | Mostly `@Api` / `@ApiOperation` / `@ApiParam` — these map close to 1:1 (`@Tag`, `@Operation`, `@Parameter`). Good "mechanical" contrast case — show this one fast, don't dwell. |
| `model/*.java` | `javax.persistence.*` → `jakarta.persistence.*`, plus `javax.validation` → `jakarta.validation`. Pure namespace swap. |

## Suggested demo flow

1. **Cold open (15 sec):** "We actually hit this — needed to move to Boot 3,
   and one of our libraries had no path forward. Had to swap it entirely."
2. Point the tool at this repo, ask it to plan/execute the Boot 3 migration.
3. Skim past the javax→jakarta and `MetricsController` changes quickly —
   "yep, mechanical, it gets those right."
4. **Slow down on `DashboardController.java` and `SwaggerConfig.java`.**
   Show the tool recognizing springfox has no forward path, choosing
   springdoc, and correctly handling the `int` vs `String` response code
   mismatch and the Docket → GroupedOpenApi restructure. This is the beat
   that proves judgment, not pattern-matching.
5. Close: run the app / show docs endpoint working post-migration if the
   tool supports execution, or show the diff summary if not.

## Not included on purpose

No tests, no CI config, no auth — kept minimal so setup and rehearsal stay
fast. Add only if the specific product you're demoing needs to show test
validation as part of its story.
