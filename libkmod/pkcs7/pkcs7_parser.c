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

#include "pkcs7_parser.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

enum pkey_hash_algo {
	PKEY_HASH_MD4,
	PKEY_HASH_MD5,
	PKEY_HASH_SHA1,
	PKEY_HASH_SHA256,
	PKEY_HASH_SHA384,
	PKEY_HASH_SHA512,
	PKEY_HASH_SHA224,
	PKEY_HASH__LAST
};

static const char *const pkey_hash_algo[PKEY_HASH__LAST] = {
	[PKEY_HASH_MD4]		= "md4",
	[PKEY_HASH_MD5]		= "md5",
	[PKEY_HASH_SHA1]	= "sha1",
	[PKEY_HASH_SHA256]	= "sha256",
	[PKEY_HASH_SHA384]	= "sha384",
	[PKEY_HASH_SHA512]	= "sha512",
	[PKEY_HASH_SHA224]	= "sha224",
};

/* 2.5.4.3 */
static uint8_t OID_cn[] = { '\x55', '\x04', '\x03' };
/* 1.3.14.3.2.26 */
static uint8_t OID_SHA1[] = { '\x2b', '\x0e', '\x03', '\x02', '\x1a' };
/* 2.16.840.1.101.3.4.2.1 */
static uint8_t OID_SHA256[] = { '\x60', '\x86', '\x48', '\x01',
				'\x65', '\x03', '\x04', '\x02', '\x01' };
/* 2.16.840.1.101.3.4.2.2 */
static uint8_t OID_SHA384[] = { '\x60', '\x86', '\x48', '\x01',
				'\x65', '\x03', '\x04', '\x02', '\x02' };
/* 2.16.840.1.101.3.4.2.3 */
static uint8_t OID_SHA512[] = { '\x60', '\x86', '\x48', '\x01',
				'\x65', '\x03', '\x04', '\x02', '\x03' };
/* 2.16.840.1.101.3.4.2.4 */
static uint8_t OID_SHA224[] = { '\x60', '\x86', '\x48', '\x01',
				'\x65', '\x03', '\x04', '\x02', '\x04' };

static uint8_t OID_MD4[] = { '\x2a', '\x86', '\x48', '\x86', '\xf7',
			     '\x0d', '\x02', '\x04' };
static uint8_t OID_MD5[] = { '\x2a', '\x86', '\x48', '\x86', '\xf7',
			     '\x0d', '\x02', '\x05' };


#define OID_TO_ID(oid) { OID_ ## oid, sizeof(OID_ ## oid), PKEY_HASH_ ## oid }
static struct oid_to_id {
	uint8_t *oid;
	int oid_size;
	int id;
} oid_to_id[] = {
	OID_TO_ID(SHA256),
	OID_TO_ID(MD5),
	OID_TO_ID(SHA1),
	OID_TO_ID(SHA384),
	OID_TO_ID(SHA512),
	OID_TO_ID(SHA224),
	OID_TO_ID(MD4),
};


static const char *pkey_hash_algo_to_str(unsigned id)
{
	if (id >= PKEY_HASH__LAST)
		return "unknown";

	return pkey_hash_algo[id];
}

void pkcs7_free_cert(struct pkcs7_cert *cert)
{

	asn_DEF_Name.free_struct(&asn_DEF_Name, cert->issuer, 0);

	asn_DEF_PKCS7ContentInfo.free_struct
		(&asn_DEF_PKCS7ContentInfo, cert->ci, 0);

	free(cert->key_id);
	free(cert->signer);
	free(cert->signature);
	free(cert);
}

static char *pkcs7_parse_utf8(uint8_t *buf, int size)
{
	char *p;
	int len;
	int llen = 1; /* length of length field */

	if (buf[0] != 0x0C) /* utf8 string tag */
		return NULL;

	if (buf[1] & 0x80)
		llen = (buf[1] & ~0x80) + 1;
	len = size - 1 - llen; /* 1 is tag */

	p = malloc(len + 1);
	if (p == NULL)
		return NULL;

	memcpy(p, buf + 1 + llen, len);
	p[len] = '\0';

	return p;
}

static int pkcs7_parse_issuer(struct pkcs7_cert *cert, ANY_t *data)
{
	asn_dec_rval_t rval;
	struct RelativeDistinguishedName **dnames;
	int count;
	int i;

	rval = ber_decode(0, &asn_DEF_Name, (void **)&cert->issuer,
			  data->buf, data->size);

	if(rval.code != RC_OK)
		return -1;

	dnames = cert->issuer->list.array;
	count = cert->issuer->list.count;

	for (i = 0; i < count; i++) {
		int j;
		int n = dnames[i]->list.count;
		struct AttributeValueAssertion **ava = dnames[i]->list.array;

		for (j = 0; j < n; j++) {
			OBJECT_IDENTIFIER_t *oid = &ava[j]->attributeType;
			ANY_t *d = &ava[j]->attributeValue;

			if (oid->size != sizeof(OID_cn))
				continue;

			if (memcmp(oid->buf, OID_cn, sizeof(OID_cn)) == 0) {
				cert->signer = pkcs7_parse_utf8(d->buf, d->size);
				break;
			}
		}
		if (cert->signer != NULL)
			break;
	}

	return 0;
}

static int pkcs7_gen_keyid_from_skid(OCTET_STRING_t *skid,
				     uint8_t **buf, size_t *size)
{
	uint8_t *p;

	p = malloc(skid->size);
	if (p == NULL)
		return -1;

	memcpy(p, skid->buf, skid->size);

	*buf = p;
	*size = skid->size;

	return 0;
}

static int pkcs7_gen_keyid_from_issuer(IssuerAndSerialNumber_t *issuer,
				       uint8_t **buf, size_t *size)
{
	size_t s;
	uint8_t *p;

	/*
	 * see asymmetric_key_generate_id(),
	 * crypto/asymmetric_keys/assymmetric_type.c in the linux kernel
	 */

	s = issuer->issuer.size + issuer->serialNumber.size;

	p = malloc(s);
	if (p == NULL)
		return -1;

	memcpy(p, issuer->issuer.buf, issuer->issuer.size);
	memcpy(p + issuer->issuer.size,
	       issuer->serialNumber.buf,
	       issuer->serialNumber.size);

	*buf = p;
	*size = s;

	return 0;
}

static uint8_t pkcs7_hashalgo_oid_to_id(OBJECT_IDENTIFIER_t *oid)
{
	unsigned i;
	struct oid_to_id *item;

	for (i = 0; i < ARRAY_SIZE(oid_to_id); i++) {
		item = &oid_to_id[i];
		if (oid->size != item->oid_size)
			continue;
		if (memcmp(oid->buf, item->oid, oid->size) != 0)
			continue;
		return item->id;
	}
	return ~0;
}

static int pkcs7_parse_si(struct pkcs7_cert *cert)
{
	struct SignerInfo **infos;
	struct SignerInfo *si;
	int count;
	OBJECT_IDENTIFIER_t *oid;
	uint8_t *buf;

	infos = cert->ci->content->signerInfos.choice.siSequence.list.array;
	count = cert->ci->content->signerInfos.choice.siSequence.list.count;

	if (count < 1)
		return -1;

	si = infos[0];

	if (si->sid.present == SignerIdentifier_PR_subjectKeyIdentifier) {
		if (pkcs7_gen_keyid_from_skid(&si->sid.choice.subjectKeyIdentifier, &cert->key_id, &cert->key_id_size) < 0)
			return -1;
		return 1;
	}

	if (pkcs7_parse_issuer(cert,
			       &si->sid.choice.issuerAndSerialNumber.issuer) < 0)
		return -1;
	if (pkcs7_gen_keyid_from_issuer(&si->sid.choice.issuerAndSerialNumber,
					&cert->key_id, &cert->key_id_size) < 0)
		return -1;

	buf = malloc(si->encryptedDigest.size);
	if (buf == NULL)
		return -1;
	memcpy(buf, si->encryptedDigest.buf, si->encryptedDigest.size);

	cert->signature = buf;
	cert->signature_size = si->encryptedDigest.size;

	oid = &si->digestAlgorithm.algorithm;
	cert->hash_algo = pkey_hash_algo_to_str(pkcs7_hashalgo_oid_to_id(oid));

	return 0;
}

struct pkcs7_cert *pkcs7_parse_cert(const void *raw, size_t len)
{
	struct pkcs7_cert *cert;
	asn_dec_rval_t rval;

	cert = malloc(sizeof(*cert));
	if (cert == NULL)
		return NULL;
	memset(cert, 0, sizeof(*cert));

	rval = ber_decode(0, &asn_DEF_PKCS7ContentInfo, (void **)&cert->ci,
			  raw, len);

	if(rval.code != RC_OK)
		goto err;

	if (cert->ci->content->signerInfos.present == SignerInfos_PR_NOTHING)
		goto err;

	if (pkcs7_parse_si(cert) < 0)
		goto err;

	return cert;
err:
	pkcs7_free_cert(cert);
	return NULL;
}
