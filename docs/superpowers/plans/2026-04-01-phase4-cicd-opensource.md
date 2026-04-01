# Phase 4: CI/CD + Open Source Infrastructure

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add production-grade CI/CD, GitHub templates, documentation, and community files so the project is ready for public release.

**Depends on:** Phase 3 complete (65 tests, Docker images, working CLI)

---

## Task 1: GitHub Actions CI Workflow

Create `.github/workflows/ci.yml` — layered pipeline: lint → unit test → Docker build.

## Task 2: GitHub Actions Release Workflow

Create `.github/workflows/release.yml` — triggered by tag, publishes to PyPI + Docker.

## Task 3: pip-audit Workflow + Dependabot

Create `.github/workflows/pip-audit.yml` and `.github/dependabot.yml`.

## Task 4: Issue Templates + PR Template

Create `.github/ISSUE_TEMPLATE/` (3 YAML templates + config.yml) and `.github/PULL_REQUEST_TEMPLATE.md`.

## Task 5: CONTRIBUTING.md + CODE_OF_CONDUCT.md + SECURITY.md + CODEOWNERS

Community and governance files.

## Task 6: CHANGELOG.md

Initial changelog with all Phase 1-3 work.

## Task 7: Complete README.md

Full README with badges, quick start, architecture, examples, all CLI usage.

## Task 8: justfile

Task runner for development workflows.

## Task 9: Final Lint + Verification
