#include "libkmod-internal.h"
#include "libkmod-unsupported.h"

void kmod_internal_allow_unsupported(struct kmod_ctx *ctx)
{
	struct kmod_config *config = (struct kmod_config *)kmod_get_config(ctx);

	config->block_unsupported = 0;
}
