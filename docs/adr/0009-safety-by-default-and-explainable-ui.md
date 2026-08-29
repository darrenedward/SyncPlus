---
status: proposed
---

# Make safety and explanation first-class product behavior

SyncPlus will prioritize data safety and user understanding: destructive options are opt-in, unsafe source/destination relationships are blocked, every data-changing run exposes an Explainable Action and requires Execution Confirmation, and no unavailable safety mechanism silently falls back to a riskier one. The UI will provide concise contextual explanations, backed by a Help section covering what each option does, why it matters, when to use it, and its consequences or limitations.

The app will provide Simple Mode as the default workflow and Advanced Mode as an opt-in view for experienced users. Advanced Mode exposes more controls but never bypasses the same safety rules.

Simple Mode is used on first launch, after which the user's mode preference is persisted and restored across restarts.
