#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

run_id=${SYNCPLUS_RELEASE_GATE_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}
case "$run_id" in
    ''|*[!A-Za-z0-9._-]*)
        echo "SYNCPLUS_RELEASE_GATE_ID contains unsupported characters" >&2
        exit 1
        ;;
esac

if [ -n "${SYNCPLUS_RELEASE_EVIDENCE_DIR:-}" ]; then
    evidence_root=$SYNCPLUS_RELEASE_EVIDENCE_DIR
else
    evidence_root="$ROOT/target/release-evidence/$run_id"
fi
case "$evidence_root" in
    /*)
        ;;
    *)
        echo "SYNCPLUS_RELEASE_EVIDENCE_DIR must be an absolute path" >&2
        exit 1
        ;;
esac
if [ -e "$evidence_root" ]; then
    echo "refusing to overwrite existing release evidence: $evidence_root" >&2
    exit 1
fi
mkdir -p "$evidence_root"

records="$evidence_root/cases.tsv"
: >"$records"

toolchain_ok=1
tool_versions="$evidence_root/tool-versions.txt"
{
    for tool in cargo rustc git dpkg-deb dpkg fakeroot sqlite3 rsync ssh ssh-keygen sshd sha256sum strings findmnt xvfb-run timeout desktop-file-install desktop-file-validate update-desktop-database systemd-analyze; do
        tool_path=$(command -v "$tool" 2>/dev/null || true)
        if [ -z "$tool_path" ]; then
            printf '%s\tMISSING\n' "$tool"
            toolchain_ok=0
        else
            tool_version=$("$tool" --version 2>&1 | sed -n '1p' || true)
            printf '%s\t%s\t%s\n' "$tool" "$tool_path" "$tool_version"
        fi
    done
} >"$tool_versions"

commit_at_start=unavailable
source_diff_sha256=unavailable
untracked_count=unknown
if command -v git >/dev/null 2>&1; then
    commit_at_start=$(git rev-parse HEAD 2>/dev/null || printf '%s' unavailable)
    untracked_count=$(git ls-files --others --exclude-standard 2>/dev/null \
        | awk 'END {print NR + 0}' || printf '%s' unknown)
    if command -v sha256sum >/dev/null 2>&1; then
        source_diff_sha256=$(git diff --binary HEAD 2>/dev/null \
            | sha256sum | awk '{print $1}' || printf '%s' unavailable)
    fi
fi
printf '%s\n' \
    "base_commit=$commit_at_start" \
    "source_diff_sha256=$source_diff_sha256" \
    "untracked_files=$untracked_count" \
    >"$evidence_root/source-state.txt"

required_cases=0
passed_cases=0
failed_cases=0
not_run_cases=0

record_case() {
    case_id=$1
    case_status=$2
    criterion=$3
    log_name=$4
    printf '%s\t%s\t%s\t%s\n' "$case_id" "$case_status" "$criterion" "$log_name" >>"$records"
    required_cases=$((required_cases + 1))
    case "$case_status" in
        PASS) passed_cases=$((passed_cases + 1)) ;;
        NOT_RUN) not_run_cases=$((not_run_cases + 1)) ;;
        *) failed_cases=$((failed_cases + 1)) ;;
    esac
}

run_case() {
    case_id=$1
    criterion=$2
    shift 2
    log_name="$case_id.log"
    log_path="$evidence_root/$log_name"

    if [ "$toolchain_ok" -ne 1 ]; then
        printf '%s\n' 'NOT RUN: a required release-gate tool is unavailable.' >"$log_path"
        record_case "$case_id" NOT_RUN "$criterion" "$log_name"
        return
    fi

    if "$@" >/dev/null 2>&1; then
        case_status=PASS
    else
        case_status=FAIL
    fi
    printf 'case=%s\nstatus=%s\n' "$case_id" "$case_status" >"$log_path"
    record_case "$case_id" "$case_status" "$criterion" "$log_name"
}

run_external_case() {
    case_id=$1
    criterion=$2
    shift 2
    external_root=$(findmnt -rn -t vfat,exfat,ntfs,ntfs3 -o TARGET 2>/dev/null | sed -n '1p' || true)
    if [ -z "$external_root" ]; then
        log_name="$case_id.log"
        printf '%s\n' 'NOT RUN: no mounted case-insensitive or restricted filesystem was available.' \
            >"$evidence_root/$log_name"
        record_case "$case_id" NOT_RUN "$criterion" "$log_name"
        return
    fi
    probe_root=$(mktemp -d "$external_root/.syncplus-release-gate-probe.XXXXXX" 2>/dev/null || true)
    if [ -z "$probe_root" ]; then
        log_name="$case_id.log"
        printf '%s\n' 'NOT RUN: the available restricted filesystem was not writable.' \
            >"$evidence_root/$log_name"
        record_case "$case_id" NOT_RUN "$criterion" "$log_name"
        return
    fi
    rmdir "$probe_root"
    run_case "$case_id" "$criterion" env SYNCPLUS_EXTERNAL_FILESYSTEM_ROOT="$external_root" "$@"
}

if [ "$toolchain_ok" -eq 1 ]; then
    record_case toolchain-availability PASS criterion-6 tool-versions.txt
else
    record_case toolchain-availability FAIL criterion-6 tool-versions.txt
fi
if [ "$untracked_count" = 0 ]; then
    record_case source-content-identity PASS criterion-6 source-state.txt
else
    record_case source-content-identity FAIL criterion-6 source-state.txt
fi

run_case scheduled-authorized-recoverable-delete criterion-1 \
    cargo test --locked -p syncplus-core --lib \
    release_gate_tests::scheduled_recoverable_safe_delete_requires_authorization_and_persists_recovery -- --exact
run_case scheduled-destination-cleanup criterion-1 \
    cargo test --locked -p syncplus-core --lib \
    release_gate_tests::scheduled_destination_cleanup_keeps_unverified_orphan_for_review -- --exact
run_case scheduled-permanent-removal-authorization criterion-1 \
    cargo test --locked -p syncplus-core --lib \
    release_gate_tests::scheduled_permanent_removal_requires_separate_authorization -- --exact
run_case scheduled-destructive-authorization criterion-1 \
    cargo test --locked -p syncplus-core --lib \
    scheduler::tests::unattended_destructive_schedule_requires_explicit_authorization -- --exact
run_case authorization-revocation criterion-1 \
    cargo test --locked -p syncplus-core --lib \
    storage_tests::safety_and_endpoint_edits_revoke_unattended_authorization -- --exact
run_case permanent-removal-authorization-boundary criterion-1 \
    cargo test --locked -p syncplus-core --lib \
    workflow::tests::remote_permanent_removal_requires_separate_authorization -- --exact
run_case unavailable-local-recovery-preserves-source criterion-1 \
    cargo test --locked -p syncplus-core --lib \
    removal_tests::unavailable_recovery_preserves_source_and_records_unresolved -- --exact
run_case unavailable-remote-recovery-preserves-source criterion-1 \
    cargo test --locked -p syncplus-core --lib \
    workflow::tests::unavailable_remote_trash_blocks_before_any_ssh_mutation -- --exact

run_case ordinary-scheduled-run criterion-2 \
    cargo test --locked -p syncplus-core --lib \
    scheduler::tests::poll_due_claims_once_and_launches_a_durable_unattended_run -- --exact
run_case overlapping-scopes-are-blocked criterion-2 \
    cargo test --locked -p syncplus-core --lib \
    scheduler::tests::overlapping_scheduled_run_is_recorded_as_skipped_without_mutation -- --exact
run_case missed-schedules-coalesce criterion-2 \
    cargo test --locked -p syncplus-core --lib \
    scheduler::tests::unavailable_scheduled_runs_create_one_coalesced_missed_notice -- --exact
run_case run-now-is-interactive criterion-2 \
    cargo test --locked -p syncplus-core --lib \
    scheduler::tests::run_now_uses_a_new_interactive_run_and_current_profile -- --exact
run_case notifications-are-safe-and-best-effort criterion-2 \
    cargo test --locked -p syncplus-core --lib \
    scheduler::tests::scheduler_notification_uses_only_a_safe_report_intent -- --exact
run_case bounded-retry-exhaustion criterion-2 \
    cargo test --locked -p syncplus-core --lib \
    workflow::tests::bounded_retry_does_not_restart_a_transient_action_forever -- --exact
run_case scheduled-transport-retry criterion-2 \
    cargo test --locked -p syncplus-core --lib \
    workflow::tests::ssh_push_retries_transport_and_persists_verified_remote_content -- --exact

run_case missing-volume-resume-blocks criterion-3 \
    cargo test --locked -p syncplus-core --lib \
    volume_tests::resume_reports_a_missing_recorded_volume_before_running_other_probes -- --exact
run_case changed-volume-resume-blocks criterion-3 \
    cargo test --locked -p syncplus-core --lib \
    volume_tests::precheck_blocks_when_a_resumed_peer_has_a_different_volume_identity -- --exact
run_case source-mutation-preserves-source criterion-3 \
    cargo test --locked -p syncplus-core --lib \
    removal_tests::source_change_after_transfer_proof_preserves_source_and_marks_unresolved -- --exact
run_case destination-hash-mismatch-preserves-source criterion-3 \
    cargo test --locked -p syncplus-core --lib \
    workflow::tests::ssh_destination_digest_mismatch_keeps_the_action_unresolved_and_source_present -- --exact
run_case permission-failure-blocks-before-mutation criterion-3 \
    cargo test --locked -p syncplus-core --lib \
    precheck_tests::real_permission_precheck_reports_effective_access_without_changing_modes -- --exact
run_case ssh-capability-failure-blocks-before-mutation criterion-3 \
    cargo test --locked -p syncplus-core --lib \
    ssh_safety_matrix_tests::remote_precheck_failures_stop_before_any_backend_mutation -- --exact
run_case sqlite-corruption-restore-and-quarantine criterion-3 \
    cargo test --locked -p syncplus-core --lib \
    sqlite_recovery_gate_tests::sqlite_recovery_gate_quarantines_corruption_and_restores_a_reviewable_database -- --exact
run_case orphan-process-cleanup criterion-3 \
    cargo test --locked -p syncplus-core --lib \
    runner::tests::cancellation_terminates_the_process_group_without_orphans -- --exact
run_case missed-critical-file-preserves-and-resumes criterion-3 \
    cargo test --locked -p syncplus-core --lib \
    workflow::tests::critical_file_reconciliation_preserves_source_and_allows_safe_resume -- --exact
run_case unreadable-source-blocks-before-mutation criterion-3 \
    cargo test --locked -p syncplus-core --lib \
    precheck_tests::unreadable_local_source_is_reported_without_turning_precheck_into_a_probe_error -- --exact
run_case interrupted-run-resumes-safely criterion-3 \
    cargo test --locked -p syncplus-core --lib \
    workflow::tests::an_open_verified_local_transfer_boundary_requires_recovery_review -- --exact
run_case scheduled-offline-peer criterion-3 \
    cargo test --locked -p syncplus-core --lib \
    release_gate_tests::scheduled_offline_peer_is_blocked_without_mutation -- --exact
run_case scheduled-destination-disconnect criterion-3 \
    cargo test --locked -p syncplus-core --lib \
    release_gate_tests::scheduled_destination_disconnect_preserves_source -- --exact
run_external_case restricted-filesystem-collision-before-mutation criterion-3 \
    cargo test --locked -p syncplus-core --lib \
    release_gate_tests::disposable_external_filesystem_detects_collisions_before_mutation -- --exact --ignored
run_case disposable-ssh-peer criterion-3 \
    cargo test --locked -p syncplus-core --lib \
    ssh_safety_matrix_tests::disposable_ssh_peer_exercises_push_pull_strict_identity_and_hostile_paths -- --exact --ignored

run_case installed-deb-lifecycle criterion-4 \
    env SYNCPLUS_DEB_TEST_ROOT="$evidence_root/package" ./packaging/test-deb.sh

run_case confirmation-is-required criterion-5 \
    cargo test --locked -p syncplus-core --lib \
    workflow::tests::workflow_requires_explicit_confirmation_before_journaling_or_mutation -- --exact
run_case unattended-ssh-rejects-hidden-prompt criterion-5 \
    cargo test --locked -p syncplus-core --lib \
    ssh::tests::unattended_interactive_password_stops_without_invoking_a_prompt -- --exact
run_case command-preview-redacts-secrets criterion-5 \
    cargo test --locked -p syncplus-core --lib \
    process_tests::preview_and_invocation_come_from_the_same_validated_specification -- --exact
run_case evidence-contains-no-secrets-or-file-content criterion-5 \
    cargo test --locked -p syncplus-core --lib \
    evidence_tests::snapshot_and_journal_types_cannot_capture_passwords_or_file_contents -- --exact
run_case recovery-review-cannot-be-bypassed criterion-5 \
    cargo test --locked -p syncplus-core --lib \
    workflow::tests::resume_does_not_bypass_an_existing_recovery_review -- --exact
run_case process-stderr-is-redacted criterion-5 \
    cargo test --locked -p syncplus-core --lib \
    runner::tests::stderr_presence_is_retained_without_persisting_raw_process_output -- --exact

expected_matrix_cases=39
expected_cases=40
if [ "$required_cases" -eq "$expected_matrix_cases" ] \
    && [ "$failed_cases" -eq 0 ] \
    && [ "$not_run_cases" -eq 0 ] \
    && [ "$passed_cases" -eq "$expected_matrix_cases" ]; then
    gate_status=PASS
else
    gate_status=FAIL
fi
record_case release-gate-manifest "$gate_status" criterion-6 release-gate-summary.txt
printf '%s\n' \
    "expected_cases=$expected_cases" \
    "recorded_cases=$required_cases" \
    "passed_cases=$passed_cases" \
    "failed_cases=$failed_cases" \
    "not_run_cases=$not_run_cases" \
    "status=$gate_status" \
    >"$evidence_root/release-gate-summary.txt"

commit=$(git rev-parse HEAD 2>/dev/null || printf '%s' unknown)
package_sha256=
if [ -f "$evidence_root/package/package-summary.txt" ]; then
    package_sha256=$(sed -n 's/^package_sha256=//p' "$evidence_root/package/package-summary.txt" | sed -n '1p')
fi

if [ "$gate_status" = PASS ] && [ "$failed_cases" -eq 0 ] && [ "$not_run_cases" -eq 0 ]; then
    release_ready=true
else
    release_ready=false
fi

manifest="$evidence_root/manifest.json"
manifest_tmp="$evidence_root/.manifest.json.tmp"
{
    printf '{\n'
    printf '  "schema_version": 1,\n'
    printf '  "run_id": "%s",\n' "$run_id"
    printf '  "commit": "%s",\n' "$commit"
    printf '  "source_diff_sha256": "%s",\n' "$source_diff_sha256"
    printf '  "source_state": "%s",\n' "$(basename "$evidence_root/source-state.txt")"
    printf '  "release_ready": %s,\n' "$release_ready"
    printf '  "expected_cases": %s,\n' "$expected_cases"
    printf '  "recorded_cases": %s,\n' "$required_cases"
    printf '  "passed_cases": %s,\n' "$passed_cases"
    printf '  "failed_cases": %s,\n' "$failed_cases"
    printf '  "not_run_cases": %s,\n' "$not_run_cases"
    printf '  "package_sha256": "%s",\n' "$package_sha256"
    printf '  "tool_versions": "%s",\n' "$(basename "$tool_versions")"
    printf '  "cases": [\n'
    first_case=true
    while IFS="$(printf '\t')" read -r case_id case_status criterion log_name; do
        if [ "$first_case" = false ]; then
            printf ',\n'
        fi
        printf '    {"id":"%s","status":"%s","criterion":"%s","log":"%s"}' \
            "$case_id" "$case_status" "$criterion" "$log_name"
        first_case=false
    done <"$records"
    printf '\n  ]\n}\n'
} >"$manifest_tmp"
test -s "$manifest_tmp"
mv "$manifest_tmp" "$manifest"

if [ "$release_ready" = true ]; then
    printf '%s\n' "$commit" >"$evidence_root/RELEASE_READY"
    test -s "$evidence_root/RELEASE_READY"
else
    rm -f "$evidence_root/RELEASE_READY"
fi

if [ "$release_ready" = true ]; then
    echo "SyncPlus release gate passed: $evidence_root"
    exit 0
fi
echo "SyncPlus release gate failed; evidence retained at: $evidence_root" >&2
exit 1
