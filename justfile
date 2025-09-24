# SPDX-FileCopyrightText: Timothée Ravier <tim@siosm.fr>
# SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

image := "quay.io/fedora/fedora-coreos:42.20250705.3.0"
container_image_name := "compute-pcrs"

run container *args:
    #!/bin/bash
    set -euo pipefail
    cargo build --release
    set -x
    podman run --rm -ti \
        --security-opt label=disable \
        --mount=type=image,source={{container}},destination=/var/srv/image,rw=false \
        -v $PWD/target/release/compute-pcrs:/usr/bin/compute-pcrs \
        -v $PWD/test-data/:/var/srv/test-data \
        -v $PWD/systemd-bootx64.efi:/var/srv/image/usr/lib/bootupd/updates/EFI/fedora/grubx64.efi \
        fedora:latest \
        compute-pcrs pcr4 \
            --shim /var/srv/image/usr/lib/bootupd/updates/EFI/fedora/shimx64.efi \
            --bootloader /var/srv/image/usr/lib/bootupd/updates/EFI/fedora/grubx64.efi \
            --uki /var/srv/image/boot/EFI/Linux/6.15.10-200.fc42.x86_64.efi \
            --uki-addon /var/srv/image/boot/EFI/Linux/6.15.10-200.fc42.x86_64.efi.extra.d/ignition.addon.efi

build-container:
    #!/bin/bash
    set -euo pipefail
    # set -x
    podman build . \
        --security-opt label=disable \
        -t {{container_image_name}}

test-container: prepare-test-env get-reference-values build-container
    #!/bin/bash
    set -euo pipefail
    # set -x
    podman pull {{image}}
    podman run --rm \
        --security-opt label=disable \
        -v $PWD/test-data/:/var/srv/test-data \
        --mount=type=image,source={{image}},destination=/var/srv/image,rw=false \
        {{container_image_name}} \
        compute-pcrs all \
            --kernels /var/srv/image/usr/lib/modules \
            --esp /var/srv/image/usr/lib/bootupd/updates \
            --efivars /var/srv/test-data/efivars/qemu-ovmf/fedora-42 \
            --mok-variables /var/srv/test-data/mok-variables/fedora-42 \
            > test/result.json 2>/dev/null
    diff test-fixtures/quay.io_fedora_fedora-coreos_42.20250705.3.0/all-pcrs.json test/result.json || (echo "FAILED" && exit 1)
    echo "OK"

get-reference-values:
    #!/bin/bash
    # set -x
    set -euo pipefail
    if [ ! -d test-data ]; then
        git clone git@github.com:confidential-clusters/reference-values.git test-data
    else
        cd test-data
        git pull --ff-only
    fi

get-test-data:
    #!/bin/bash
    set -euo pipefail
    # set -x
    mkdir -p test-data/6.15.4-200.fc42.x86_64
    podman run --rm -ti \
        --security-opt label=disable \
        -v $PWD/test-data:/var/srv:rw \
        {{image}} \
        cp -a \
            /usr/lib/bootupd/updates/EFI \
            /var/srv
    podman run --rm -ti \
        --security-opt label=disable \
        -v $PWD/test-data:/var/srv:rw \
        {{image}} \
        cp \
            /usr/lib/modules/6.15.4-200.fc42.x86_64/vmlinuz \
            /var/srv/6.15.4-200.fc42.x86_64

prepare-test-env:
    #!/bin/bash
    set -euo pipefail
    # set -x
    mkdir -p test

prepare-test-env-local: get-reference-values prepare-test-env get-test-data

clean-tests:
    #!/bin/bash
    set -euo pipefail
    # set -x
    rm -rf test-data test

test-vmlinuz: prepare-test-env-local
    #!/bin/bash
    set -euo pipefail
    # set -x
    cargo run -- pcr4 -k test-data -e test-data

test-uki: prepare-test-env-local
    #!/bin/bash
    set -euo pipefail
    # set -x
    cargo run -- pcr11 uki

test-secureboot-enabled: prepare-test-env-local
    #!/bin/bash
    set -euo pipefail
    # set -x
    cargo run -- pcr7 \
        -e test-data \
        --efivars test-data/efivars/qemu-ovmf/fedora-42 \
        > test/result.json 2>/dev/null
    diff test-fixtures/quay.io_fedora_fedora-coreos_42.20250705.3.0/pcr7-sb-enabled.json test/result.json || (echo "FAILED" && exit 1)
    echo "OK"

test-secureboot-disabled: prepare-test-env-local
    #!/bin/bash
    set -euo pipefail
    # set -x
    mkdir -p test-data/efivars/qemu-ovmf/fedora-42-sb-disabled
    cargo run -- pcr7 \
        -e test-data \
        --efivars test-data/efivars/qemu-ovmf/fedora-42-sb-disabled \
        --secureboot-disabled \
        > test/result.json 2>/dev/null
    diff test-fixtures/quay.io_fedora_fedora-coreos_42.20250705.3.0/pcr7-sb-disabled.json test/result.json || (echo "FAILED" && exit 1)
    echo "OK"

test-default-mok-keys-fcos42: prepare-test-env-local
    #!/bin/bash
    set -euo pipefail
    # set -x
    cargo run -- pcr14 \
        --mok-variables test-data/mok-variables/fedora-42 \
        > test/result.json 2>/dev/null
    diff test-fixtures/quay.io_fedora_fedora-coreos_42.20250705.3.0/pcr14.json test/result.json || (echo "FAILED" && exit 1)
    echo "OK"
