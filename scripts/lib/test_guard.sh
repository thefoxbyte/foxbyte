# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Sourced first by every integration suite. The suites wipe Blackbox history,
# restore main to an earlier point in time, fail HA over, remove containers
# and create accounts — run against a real install they destroy real data.
# So they run only where scripts/test_vm.sh has left its marker.
#
# FOX_TEST_ALLOW_REAL_INSTALL=yes-destroy-my-data overrides this, for a
# machine that is itself disposable (for example a CI runner).
if [ ! -f /etc/fox-test-instance ] && [ "${FOX_TEST_ALLOW_REAL_INSTALL:-}" != "yes-destroy-my-data" ]; then
	cat >&2 <<'MSG'
refusing to run: this is not a FoxByte test instance.

These suites delete Blackbox history, restore main to an earlier point in time
and fail HA over, so on a real install they destroy real data. Run them in the
throwaway test VM instead:

    make integration        # creates the VM on first use (make test-vm)

To run on a machine that is itself disposable, set
FOX_TEST_ALLOW_REAL_INSTALL=yes-destroy-my-data.
MSG
	exit 2
fi
