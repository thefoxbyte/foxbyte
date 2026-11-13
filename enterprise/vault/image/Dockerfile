# SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0
#
# The vault service's image (point 13, docs/FOX_P13_Vault_Design.md, section
# 5). Gate 0, the prototype: the binary is built beforehand, with cgo and the
# enterprise tag, in a Go image of the same Debian release, and copied in
# here; Gate 1 builds it in a stage of this file and publishes the image beside
# the engine's.
#
# SoftHSM2 is FoxByte's own software token, for trials and tests, labelled as
# not compliant wherever a kind's rules require an HSM. A customer's HSM
# client library is mounted read-only instead, and named with --pkcs11-lib.
FROM debian:bookworm-slim

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends softhsm2; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --system --gid 10001 vault; \
    useradd --system --uid 10001 --gid 10001 --home-dir /var/lib/fox-vault --no-create-home vault; \
    mkdir -p /var/lib/fox-vault/tokens /run/fox-vault /etc/fox-vault; \
    chown -R vault:vault /var/lib/fox-vault /run/fox-vault; \
    chmod 700 /var/lib/fox-vault/tokens /run/fox-vault

COPY softhsm2.conf /etc/fox-vault/softhsm2.conf
COPY fox-vault /usr/local/bin/fox-vault
ENV SOFTHSM2_CONF=/etc/fox-vault/softhsm2.conf
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/fox-vault"]
CMD ["serve"]
