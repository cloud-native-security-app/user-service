# CI/CD deploy for user-service

Feature id: `ci-cd-deploy` | Engram topic: `odd/ci-cd-deploy/tasks` (project: user-service) | Branch: `v1`

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

- Task definition stored in this repo (`.aws/task-definition.json`).
- `ci.yml` (pull requests) and `deploy.yml` (push to `main` + `workflow_dispatch`).
- Moving hardcoded secrets out of the task definition.
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
- Terraform owns the ECS service (bootstrap task definition, `ignore_changes = [task_definition]`).
  This repo's CI owns task-definition revisions afterwards.
- Cluster `security-app-cluster-v2`, service `user-service`.

## Tooling

- TDD: Strict, source user global config. Runner: `make verify` (`cargo fmt --check`,
  `cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo test -- --ignored`, `cargo doc --no-deps`).
- Workflows are checked with `actionlint`.

## Checklist

- [ ] CI-01 Move the task definition to `.aws/task-definition.json`; replace `__EXEC_ROLE_ARN__`, `__IMG_USER_SERVICE__`, `__AWS_REGION__` with values filled by the render action / workflow env.
- [ ] CI-02 `ci.yml` on pull request: fmt, clippy, tests (including the `#[ignore]` testcontainers tests, which need Docker on the runner), `docker build` without push.
- [ ] CI-03 `deploy.yml` on push to `main` + `workflow_dispatch`: `configure-aws-credentials` -> `amazon-ecr-login` -> build and push `:${{ github.sha }}` -> `amazon-ecs-render-task-definition` -> `amazon-ecs-deploy-task-definition` with `wait-for-service-stability`.
- [ ] CI-04 Secrets/env: remove `DATABASE_URL` credentials, `GATEWAY_SHARED_SECRET` and `CREDENTIALS_ENCRYPTION_KEY` from the committed task definition; use ECS `secrets` from SSM / Secrets Manager if infra spike 6 passes, otherwise GitHub secrets injected at render time.
- [ ] CI-05 Docs: README section on the pipeline, required secrets and the credential refresh step.

## Acceptance criteria

- `ci.yml` is green on a pull request.
- `deploy.yml` registers a new task-definition revision tagged with the commit SHA and the rollout reaches a stable service.
- No plaintext secret remains in the repository.
- Both workflows pass `actionlint`.

## Checks

- `make verify`
- `actionlint .github/workflows/*.yml`
- `docker build -t user-service:ci .`

## Dependencies

- infra TF-07 (ECR repository).
- infra TF-12 (ECS service shell).
- infra spike 6 (`LabRole` reads SSM / Secrets Manager) for CI-04.

## Progress

Planned. Nothing implemented yet.

## Next step

CI-01: move and parameterize the task definition (source today:
`infra/deploy/aws/task-defs/user-service.json`).
