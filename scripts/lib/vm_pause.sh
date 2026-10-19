# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Was the VM frozen while a suite ran? Sourced by lib/test_guard.sh, so every
# suite has it; a suite calls vm_pause_report beside its own summary.
#
# The test VM stops when the computer running it sleeps. Closing a laptop's lid
# on battery sleeps it whatever keep-awake is in force, and it then wakes for a
# few seconds at a time ("DarkWake") every few minutes, so the VM runs in
# bursts. Each time it resumes, its clock is set forward to the real time, and
# every wait in flight (a Playwright expectation of 30 seconds, a test's 60, a
# suite's `for _ in $(seq 30); do … sleep 1; done`) has expired at once.
#
# A run like that fails in batches of tests that each "timed out" after about
# their timeout, and the console, the engine and the tests are all blameless:
# on 18 Oct 2026, main failed 2 and then 8 Playwright tests this way, and
# chronyd logged "Forward time jump detected!" fifteen times in the afternoon.
# So the run says so, and a reader is not left to debug a product that worked.
#
# How it is seen: a watcher reads the clock every 2 seconds. A sleep inside a
# frozen VM does not advance either, so after a pause the clock has moved far
# further than the 2 seconds slept. Any gap past VM_PAUSE_GAP (15 s) is noted.
# A VM that is merely slow does not trip it; one that was stopped does.

VM_PAUSE_GAP="${VM_PAUSE_GAP:-15}"
VM_PAUSE_LOG="$(mktemp "${TMPDIR:-/tmp}/vm-pause.XXXXXX")"

# The watcher stops when the suite does, without a trap: three suites set their
# own EXIT trap, which would replace one set here.
(
	parent=$$ # in a subshell $$ is still the suite; PPID would be the suite's parent
	prev=$(date +%s)
	while kill -0 "$parent" 2>/dev/null; do
		sleep 2
		now=$(date +%s)
		gap=$((now - prev))
		if [ "$gap" -gt "$VM_PAUSE_GAP" ]; then
			echo "$(date '+%H:%M:%S') $gap" >>"$VM_PAUSE_LOG"
		fi
		prev=$now
	done
	rm -f "$VM_PAUSE_LOG"
) >/dev/null 2>&1 &
VM_PAUSE_WATCHER=$!
disown "$VM_PAUSE_WATCHER" 2>/dev/null || true

# vm_pause_report prints a warning when the VM was frozen during the run, and
# returns 1 then. It changes no result: a failure is still a failure, now with
# its likely cause named.
vm_pause_report() {
	[ -s "$VM_PAUSE_LOG" ] || return 0
	local n longest total
	n=$(wc -l <"$VM_PAUSE_LOG" | tr -d ' ')
	longest=$(awk 'BEGIN{m=0} {if ($2>m) m=$2} END{print m}' "$VM_PAUSE_LOG")
	total=$(awk '{s+=$2} END{print s}' "$VM_PAUSE_LOG")
	echo
	echo "WARNING: the test VM was frozen $n time(s) during this run, for ${total}s in all"
	echo "(longest ${longest}s; at $(awk '{print $1}' "$VM_PAUSE_LOG" | head -5 | paste -sd' ' -)$([ "$n" -gt 5 ] && echo ' …'))."
	echo "That is the computer sleeping, usually a laptop with its lid closed. Every wait"
	echo "that spanned a pause expired at once, so a timeout in this run says nothing"
	echo "about the code. Keep the computer awake (lid open, or on power) and run it again."
	return 1
}
