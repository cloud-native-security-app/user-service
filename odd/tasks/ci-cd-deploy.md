# CI/CD deploy for user-service

Feature id: `ci-cd-deploy` | Engram topic: `odd/ci-cd-deploy/tasks` (project: user-service) | Branch: `feature/ci_cd`

Master plan: repo `infra`, path `odd/tasks/cloud-native-deploy.md`, Engram `odd/cloud-native-deploy/tasks` (project: infra).

## Objective

Build, test and deploy `user-service` to ECS Fargate from GitHub Actions: `ci.yml` validates every
pull request and `deploy.yml` ships a new task-definition revision on every push to `main`.

## Why

Images are built and pushed by hand today, and the task definition is rendered with `sed`
placeholders in the `infra` legacy scripts. Per-commit images and a reviewable task definition
make rollouts repeatable.

## Scope

In:

- Image-only rollout (D1): the task definition is read from the running service, not stored here.
- `ci.yml` (pull requests) and `deploy.yml` (push to `main` + `workflow_dispatch`).
- README section documenting the pipeline.

Out:

- Terraform resources (ECR, cluster, service, log group): owned by `infra`.
- GitHub OIDC or new IAM roles (not possible in Learner Lab).
- Creating remotes, pushing, opening PRs (user decisions).

## Constraints

- AWS Academy Learner Lab: no OIDC. Temporary credentials are stored as GitHub secrets
  `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, refreshed with
  `refresh-gh-secrets.sh` from the `infra` repo before each deploy.
- Execution role is the existing `LabRole`.
- Terraform owns the ECS service and its task definition content (`ignore_changes = [task_definition]`);
  CI only registers revisions that differ in the image (D1).
- Cluster `security-app-cluster-v2`, service `user-service`.

## Tooling

- TDD: Strict, source user global config. Runner: `make verify` (`cargo fmt --check`,
  `cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo test -- --ignored`, `cargo doc --no-deps`).
- Workflows are checked with `actionlint`.

## Checklist

- [x] CI-01 Repo-owned `.aws/task-definition.json`: superseded by D1 (done-by-design). The task definition lives in Terraform.
- [x] CI-02 `ci.yml` on pull request and push to `develop`: `make verify` (fmt, clippy `-D warnings`, tests, ignored testcontainers/PostgreSQL tests on the runner's Docker, doc) and `docker build` without push. `actionlint` clean.
- [x] CI-03 `deploy.yml` on push to `main` + `workflow_dispatch`: configure-aws-credentials -> ECR login -> build and push `:${{ github.sha }}` (+ `:latest`) -> download current task definition -> render (image swap of container `user-service`) -> deploy with `wait-for-service-stability`; cluster `security-app-cluster-v2`, service `user-service`.
- [x] CI-04 Secrets/env: superseded by D1 (done-by-design). `DATABASE_URL`, `GATEWAY_SHARED_SECRET` and `CREDENTIALS_ENCRYPTION_KEY` come from the Terraform task definition via SSM parameters `/security-app/user-service/database-url`, `/security-app/gateway-shared-secret`, `/security-app/user-service/credentials-encryption-key`. Nothing is committed here.
- [x] CI-05 Docs: README CI/CD section in Spanish (secrets, refresh flow, manual redeploy, rollback, Service Connect note).

## Decisions

- D1 (2026-10-19, user, same as gateway and nmap-service): Terraform (`infra`) owns the task definition (env incl. `DATABASE_URL` from SSM, shared secret, encryption key, roles, logging). CI owns only the image: `deploy.yml` fetches the service's current task definition, strips read-only fields with jq, swaps the image of container `user-service` to `${{ github.sha }}` (also pushes `:latest`) and deploys with wait-for-service-stability. Supersedes CI-01 and CI-04.

## Acceptance criteria

- `ci.yml` is green on a pull request.
- `deploy.yml` registers a new task-definition revision tagged with the commit SHA and the rollout reaches a stable service.
- No plaintext secret or task definition is committed to the repository.
- Both workflows pass `actionlint`.

## Checks

- `make verify`
- `actionlint .github/workflows/*.yml`
- `docker build -t user-service:ci-check .`

## Dependencies

- infra TF-07 (ECR repository).
- infra TF-12 (ECS service shell).

## Progress

CI-01/04 superseded by D1. CI-02, CI-03, CI-05 implemented locally (workflows, README CI/CD section); local checks passed. Not committed yet. Live checks pending: green PR run and real deploy (need the user to open a PR / merge to `main` with repo secrets and variable set).

## CI/CD evidence

Route: delegated writer (single bounded writer). Strict TDD = observable checks first.

- Baseline (before): `mise exec actionlint@1.7.12 shellcheck@latest -- actionlint .github/workflows/*.yml` -> `could not read ".github/workflows/*.yml": no such file or directory` (exit 3; workflow dir absent).
- After: same command -> clean, exit 0.
- `make verify` -> exit 0 on the final run (44 unit + 23 api + 24 repository + 2 wiring integration tests via Docker/PostgreSQL). First run failed once on `api::tests::repo_error_is_logged_server_side_before_mapping_to_internal` (empty captured log); it passed in 3 isolated reruns, the full lib suite and the final `make verify`. Pre-existing flaky test (tracing log capture), unrelated to this change; worth a follow-up.
- `docker build -t user-service:ci-check .` -> exit 0; image removed afterwards.
- `git status --short` -> ` M README.md`, `?? .github/` (this feature doc also modified).
- Pinned actions (full SHA, same as gateway/nmap-service): configure-aws-credentials v6.3.0, amazon-ecr-login v2.1.7, amazon-ecs-render-task-definition v1.9.1, amazon-ecs-deploy-task-definition v2.6.4, Swatinem/rust-cache v2.9.2; `actions/checkout@v4`.
- Pending (needs user): green PR run of `ci.yml`; real `deploy.yml` rollout.

## Next step

Commit (user), push and open a PR to verify CI live; run infra `refresh-gh-secrets.sh` before the first deploy.
