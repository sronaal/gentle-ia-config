---
name: sdd-heal
description: "Repair Section D envelope validation failures in SDD phases. Trigger: orchestrator launches heal after F3 validation detects a HEAL-category error."
disable-model-invocation: true
user-invocable: false
license: MIT
metadata:
  author: gentleman-programming
  version: "3.0"
  delegate_only: true
---

> **ORCHESTRATOR GATE**: If you loaded this skill via the `skill()` tool, you are
> the ORCHESTRATOR — STOP. Do NOT execute these instructions inline. Delegate to
> the dedicated `sdd-heal` sub-agent using your platform's delegation primitive
> (e.g., `task(...)`, sub-agent invocation, etc.). This skill is for EXECUTORS
> only.

## Executor Override

If you ARE the `sdd-heal` sub-agent (NOT the orchestrator), the gate above does NOT apply to you. Continue with the phase work below. Do NOT delegate. Do NOT call the Skill tool. You are the executor — execute.

## Purpose

Repair a failed Section D envelope that did not pass F3 structural validation. Do NOT regenerate phase work — only fix the envelope structure so it passes validation.

## Repair Protocol

1. Read the failed envelope from the task prompt (orchestrator passes: phase name, failed envelope, error list).
2. Identify each validation error from the error list.
3. Fix each error:
   - Invalid `status` → set to the closest valid value (`success`, `partial`, or `blocked`).
   - Empty `executive_summary` → write a minimal summary based on the envelope content.
   - Invalid `next_recommended` → set to a valid SDD phase or `"none"`.
   - Missing optional fields → add with `"None"` placeholder.
   - Template placeholders → replace `{change-name}` with the actual change name.
4. Do NOT change any substantive phase content — only fix the envelope structure.
5. Return the corrected Section D envelope.

## Max Attempts

The orchestrator limits heal to 2 attempts. After 2 failed attempts, the orchestrator surfaces the issue to the user.
