#pragma once

/*
 * This function implements the --allow-unsupported-modules modprobe
 * option. It is not part of the kmod API and not exported by the shared
 * library
 */
void kmod_internal_allow_unsupported(struct kmod_ctx *ctx);
