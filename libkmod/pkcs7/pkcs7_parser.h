/*
 * Copyright (C) 2018 Red Hat, Inc., Yauheni Kaliuta
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef KMOD_PKCS7_PARSER_H_
#define KMOD_PKCS7_PARSER_H_

#define EMIT_ASN_DEBUG 0

#include <PKCS7ContentInfo.h>
#include <Name.h>

struct pkcs7_cert {
	PKCS7ContentInfo_t *ci;
	/* issuer RAW data are needed as well, so parsed separately */
	Name_t *issuer;

	const char *hash_algo;
	uint8_t *key_id;
	size_t key_id_size;
	char *signer; /* copy cn there, name like in module_signature */
	uint8_t *signature;
	size_t signature_size;
};

struct pkcs7_cert *pkcs7_parse_cert(const void *raw, size_t len);
void pkcs7_free_cert(struct pkcs7_cert *cert);

#endif
