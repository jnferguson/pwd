#include "stdafx.h"
#include "sgx_replace.hpp"


sgx_replace_t::sgx_replace_t(void)
{
	return;
}


sgx_replace_t::~sgx_replace_t(void)
{
	return;
}

IppStatus 
sgx_replace_t::_ipp_newBN(const Ipp32u* p_data, int size_in_bytes, IppsBigNumState ** p_new_BN)
{
	IppsBigNumState *pBN = 0;
	int bn_size = 0;

	if (p_new_BN == NULL || (size_in_bytes <= 0) || ((size_in_bytes % sizeof(Ipp32u)) != 0))
		return ippStsBadArgErr;

	// Get the size of the IppsBigNumState context in bytes
	IppStatus error_code = ippsBigNumGetSize(size_in_bytes / (int)sizeof(Ipp32u), &bn_size);
	if (error_code != ippStsNoErr)
	{
		*p_new_BN = 0;
		return error_code;
	}
	pBN = (IppsBigNumState *)malloc(bn_size);
	if (!pBN)
	{
		error_code = ippStsMemAllocErr;
		*p_new_BN = 0;
		return error_code;
	}
	// Initialize context and partition allocated buffer
	error_code = ippsBigNumInit(size_in_bytes / (int)sizeof(Ipp32u), pBN);
	if (error_code != ippStsNoErr)
	{
		free(pBN);
		*p_new_BN = 0;
		return error_code;
	}
	if (p_data)
	{
		error_code = ippsSet_BN(IppsBigNumPOS, size_in_bytes / (int)sizeof(Ipp32u), p_data, pBN);
		if (error_code != ippStsNoErr)
		{
			*p_new_BN = 0;
			free(pBN);
			return error_code;
		}
	}


	*p_new_BN = pBN;
	return error_code;
}

void 
sgx_replace_t::_ipp_secure_free_BN(IppsBigNumState *pBN, int size_in_bytes)
{
	if (pBN == NULL || size_in_bytes <= 0 || ((size_in_bytes % sizeof(Ipp32u)) != 0))
	{
		if (pBN)
		{
			free(pBN);
		}
		return;
	}
	int bn_size = 0;

	// Get the size of the IppsBigNumState context in bytes
	// Since we have checked the size_in_bytes before and the &bn_size is not NULL, ippsBigNumGetSize never returns failure
	IppStatus error_code = ippsBigNumGetSize(size_in_bytes / (int)sizeof(Ipp32u), &bn_size);
	if (error_code != ippStsNoErr)
	{
		free(pBN);
		return;
	}
	// Clear the buffer before free.
	//memset_s(pBN, bn_size, 0, bn_size);
	memset(pBN, 0, bn_size);
	free(pBN);
	return;
}

IppStatus __STDCALL 
sgx_replace_t::_ipp_DRNGen(Ipp32u* pRandBNU, int nBits, void* pCtx)
{
	sgx_status_t sgx_ret;
	UNUSED(pCtx);

	if (0 != nBits % 8)
	{
		// Must be byte aligned
		return ippStsSizeErr;
	}

	if (!pRandBNU)
	{
		return ippStsNullPtrErr;
	}
	sgx_ret = sgx_replace_t::read_rand((uint8_t*)pRandBNU, (uint32_t)nBits / 8);
	if (SGX_SUCCESS != sgx_ret)
	{
		return ippStsErr;
	}
	return ippStsNoErr;
}

extern "C" sgx_status_t SGXAPI 
sgx_replace_t::read_rand(uint8_t *buf, size_t size)
{
	if (buf == NULL || size == 0 || size> UINT32_MAX) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	uint32_t i;
	for (i = 0; i<(uint32_t)size; ++i) {
		buf[i] = (uint8_t)rand();
	}

	return SGX_SUCCESS;
}


inline IppStatus 
sgx_replace_t::check_copy_size(size_t target_size, size_t source_size)
{
	if (target_size < source_size)
		return ippStsSizeErr;
	return ippStsNoErr;
}

sgx_status_t 
sgx_replace_t::ecc256_open_context(ecc_state_handle_t* p_ecc_handle)
{
	IppStatus ipp_ret = ippStsNoErr;
	IppsECCPState* p_ecc_state = NULL;
	// default use 256r1 parameter
	int ctx_size = 0;

	if (p_ecc_handle == NULL)
		return SGX_ERROR_INVALID_PARAMETER;
	ipp_ret = ippsECCPGetSize(256, &ctx_size);
	if (ipp_ret != ippStsNoErr)
		return SGX_ERROR_UNEXPECTED;
	p_ecc_state = (IppsECCPState*)(malloc(ctx_size));
	if (p_ecc_state == NULL)
		return SGX_ERROR_OUT_OF_MEMORY;
	ipp_ret = ippsECCPInit(256, p_ecc_state);
	if (ipp_ret != ippStsNoErr)
	{
		SAFE_FREE(p_ecc_state);
		*p_ecc_handle = NULL;
		return SGX_ERROR_UNEXPECTED;
	}
	ipp_ret = ippsECCPSetStd(IppECCPStd256r1, p_ecc_state);
	if (ipp_ret != ippStsNoErr)
	{
		SAFE_FREE(p_ecc_state);
		*p_ecc_handle = NULL;
		return SGX_ERROR_UNEXPECTED;
	}
	*p_ecc_handle = p_ecc_state;
	return SGX_SUCCESS;
}

sgx_status_t 
sgx_replace_t::ecc256_create_key_pair(sgx_ec256_private_t* p_private, sgx_ec256_public_t* p_public, sgx_ecc_state_handle_t ecc_handle)
{
	if ((ecc_handle == NULL) || (p_private == NULL) || (p_public == NULL))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	IppsBigNumState*    dh_priv_BN = NULL;
	IppsECCPPointState* point_pub = NULL;
	IppsBigNumState*    pub_gx = NULL;
	IppsBigNumState*    pub_gy = NULL;
	IppStatus           ipp_ret = ippStsNoErr;
	int                 ecPointSize = 0;
	IppsECCPState* p_ecc_state = (IppsECCPState*)ecc_handle;

	do
	{
		//init eccp point
		ipp_ret = ippsECCPPointGetSize(256, &ecPointSize);
		ERROR_BREAK(ipp_ret);
		point_pub = (IppsECCPPointState*)(malloc(ecPointSize));
		if (!point_pub)
		{
			ipp_ret = ippStsNoMemErr;
			break;
		}
		ipp_ret = ippsECCPPointInit(256, point_pub);
		ERROR_BREAK(ipp_ret);

		ipp_ret = sgx_replace_t::_ipp_newBN(NULL, SGX_ECP256_KEY_SIZE, &dh_priv_BN);
		ERROR_BREAK(ipp_ret);
		// Use the true random number (DRNG)
		// Notice that IPP ensures the private key generated is non-zero
		ipp_ret = ippsECCPGenKeyPair(dh_priv_BN, point_pub, p_ecc_state, (IppBitSupplier)sgx_replace_t::_ipp_DRNGen, NULL);
		ERROR_BREAK(ipp_ret);

		//convert point_result to oct string
		ipp_ret = sgx_replace_t::_ipp_newBN(NULL, SGX_ECP256_KEY_SIZE, &pub_gx);
		ERROR_BREAK(ipp_ret);
		ipp_ret = sgx_replace_t::_ipp_newBN(NULL, SGX_ECP256_KEY_SIZE, &pub_gy);
		ERROR_BREAK(ipp_ret);
		ipp_ret = ippsECCPGetPoint(pub_gx, pub_gy, point_pub, p_ecc_state);
		ERROR_BREAK(ipp_ret);

		IppsBigNumSGN sgn = IppsBigNumPOS;
		Ipp32u *pdata = NULL;
		// ippsRef_BN is in bits not bytes (versus old ippsGet_BN)
		int length = 0;
		ipp_ret = ippsRef_BN(&sgn, &length, &pdata, pub_gx);
		ERROR_BREAK(ipp_ret);
		memset(p_public->gx, 0, sizeof(p_public->gx));
		ipp_ret = check_copy_size(sizeof(p_public->gx), ROUND_TO(length, 8) / 8);
		ERROR_BREAK(ipp_ret);
		memcpy(p_public->gx, pdata, ROUND_TO(length, 8) / 8);
		ipp_ret = ippsRef_BN(&sgn, &length, &pdata, pub_gy);
		ERROR_BREAK(ipp_ret);
		memset(p_public->gy, 0, sizeof(p_public->gy));
		ipp_ret = check_copy_size(sizeof(p_public->gy), ROUND_TO(length, 8) / 8);
		ERROR_BREAK(ipp_ret);
		memcpy(p_public->gy, pdata, ROUND_TO(length, 8) / 8);
		ipp_ret = ippsRef_BN(&sgn, &length, &pdata, dh_priv_BN);
		ERROR_BREAK(ipp_ret);
		memset(p_private->r, 0, sizeof(p_private->r));
		ipp_ret = check_copy_size(sizeof(p_private->r), ROUND_TO(length, 8) / 8);
		ERROR_BREAK(ipp_ret);
		memcpy(p_private->r, pdata, ROUND_TO(length, 8) / 8);
	} while (0);

	//Clear temp buffer before free.
	//if (point_pub) memset_s(point_pub, ecPointSize, 0, ecPointSize);
	if (point_pub) memset(point_pub, 0, ecPointSize);

	SAFE_FREE(point_pub);
	sgx_replace_t::_ipp_secure_free_BN(pub_gx, SGX_ECP256_KEY_SIZE);
	sgx_replace_t::_ipp_secure_free_BN(pub_gy, SGX_ECP256_KEY_SIZE);
	sgx_replace_t::_ipp_secure_free_BN(dh_priv_BN, SGX_ECP256_KEY_SIZE);

	switch (ipp_ret)
	{
	case ippStsNoErr: return SGX_SUCCESS;
	case ippStsNoMemErr:
	case ippStsMemAllocErr: return SGX_ERROR_OUT_OF_MEMORY;
	case ippStsNullPtrErr:
	case ippStsLengthErr:
	case ippStsOutOfRangeErr:
	case ippStsSizeErr:
	case ippStsBadArgErr: return SGX_ERROR_INVALID_PARAMETER;
	default: return SGX_ERROR_UNEXPECTED;
	}
}

sgx_status_t 
sgx_replace_t::ecc256_close_context(ecc_state_handle_t ecc_handle)
{
	if (ecc_handle == NULL)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	IppsECCPState* p_ecc_state = (IppsECCPState*)ecc_handle;
	int ctx_size = 0;
	IppStatus ipp_ret = ippsECCPGetSize(256, &ctx_size);
	if (ipp_ret != ippStsNoErr)
	{
		free(p_ecc_state);
		return SGX_SUCCESS;
	}
	//memset_s(p_ecc_state, ctx_size, 0, ctx_size);
	memset(p_ecc_state, 0, ctx_size);
	free(p_ecc_state);
	return SGX_SUCCESS;
}

sgx_status_t 
sgx_replace_t::ecc256_check_point(const sgx_ec256_public_t *p_point, const ecc_state_handle_t ecc_handle, int *p_valid)
{
	if ((ecc_handle == NULL) || (p_point == NULL) || (p_valid == NULL))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	IppsECCPPointState* point2check = NULL;
	IppStatus           ipp_ret = ippStsNoErr;
	IppsECCPState* p_ecc_state = (IppsECCPState*)ecc_handle;
	IppECResult ipp_result = ippECValid;
	int                 ecPointSize = 0;
	IppsBigNumState*    BN_gx = NULL;
	IppsBigNumState*    BN_gy = NULL;

	// Intialize return to false
	*p_valid = 0;

	do
	{
		ipp_ret = ippsECCPPointGetSize(256, &ecPointSize);
		ERROR_BREAK(ipp_ret);
		point2check = (IppsECCPPointState*)malloc(ecPointSize);
		if (!point2check)
		{
			ipp_ret = ippStsNoMemErr;
			break;
		}
		ipp_ret = ippsECCPPointInit(256, point2check);
		ERROR_BREAK(ipp_ret);

		ipp_ret = sgx_replace_t::_ipp_newBN((const Ipp32u *)p_point->gx, sizeof(p_point->gx), &BN_gx);
		ERROR_BREAK(ipp_ret);
		ipp_ret = sgx_replace_t::_ipp_newBN((const Ipp32u *)p_point->gy, sizeof(p_point->gy), &BN_gy);
		ERROR_BREAK(ipp_ret);

		ipp_ret = ippsECCPSetPoint(BN_gx, BN_gy, point2check, p_ecc_state);
		ERROR_BREAK(ipp_ret);

		// Check to see if the point is a valid point on the Elliptic curve and is not infinity
		ipp_ret = ippsECCPCheckPoint(point2check, &ipp_result, p_ecc_state);
		ERROR_BREAK(ipp_ret);
		if (ipp_result == ippECValid)
		{
			*p_valid = 1;
		}
	} while (0);

	// Clear temp buffer before free.
	if (point2check)
		memset(point2check, 0, ecPointSize);
	//	memset_s(point2check, ecPointSize, 0, ecPointSize);
	SAFE_FREE(point2check);

	sgx_replace_t::_ipp_secure_free_BN(BN_gx, sizeof(p_point->gx));
	sgx_replace_t::_ipp_secure_free_BN(BN_gy, sizeof(p_point->gy));

	switch (ipp_ret)
	{
	case ippStsNoErr: return SGX_SUCCESS;
	case ippStsNoMemErr:
	case ippStsMemAllocErr: return SGX_ERROR_OUT_OF_MEMORY;
	case ippStsNullPtrErr:
	case ippStsLengthErr:
	case ippStsOutOfRangeErr:
	case ippStsSizeErr:
	case ippStsBadArgErr: return SGX_ERROR_INVALID_PARAMETER;
	default: return SGX_ERROR_UNEXPECTED;
	}
}

sgx_status_t 
sgx_replace_t::ecc256_compute_shared_dhkey(sgx_ec256_private_t *p_private_b, sgx_ec256_public_t *p_public_ga, sgx_ec256_dh_shared_t *p_shared_key, ecc_state_handle_t ecc_handle)
{
	if ((ecc_handle == NULL) || (p_private_b == NULL) || (p_public_ga == NULL) || (p_shared_key == NULL))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	IppsBigNumState*    BN_dh_privB = NULL;
	IppsBigNumState*    BN_dh_share = NULL;
	IppsBigNumState*    pubA_gx = NULL;
	IppsBigNumState*    pubA_gy = NULL;
	IppsECCPPointState* point_pubA = NULL;
	IppStatus           ipp_ret = ippStsNoErr;
	int                 ecPointSize = 0;
	IppsECCPState* p_ecc_state = (IppsECCPState*)ecc_handle;
	IppECResult ipp_result = ippECValid;

	do
	{
		ipp_ret = sgx_replace_t::_ipp_newBN((Ipp32u*)p_private_b->r, sizeof(sgx_ec256_private_t), &BN_dh_privB);
		ERROR_BREAK(ipp_ret);
		ipp_ret = sgx_replace_t::_ipp_newBN((uint32_t*)p_public_ga->gx, sizeof(p_public_ga->gx), &pubA_gx);
		ERROR_BREAK(ipp_ret);
		ipp_ret = sgx_replace_t::_ipp_newBN((uint32_t*)p_public_ga->gy, sizeof(p_public_ga->gy), &pubA_gy);
		ERROR_BREAK(ipp_ret);
		ipp_ret = ippsECCPPointGetSize(256, &ecPointSize);
		ERROR_BREAK(ipp_ret);
		point_pubA = (IppsECCPPointState*)(malloc(ecPointSize));
		if (!point_pubA)
		{
			ipp_ret = ippStsNoMemErr;
			break;
		}
		ipp_ret = ippsECCPPointInit(256, point_pubA);
		ERROR_BREAK(ipp_ret);
		ipp_ret = ippsECCPSetPoint(pubA_gx, pubA_gy, point_pubA, p_ecc_state);
		ERROR_BREAK(ipp_ret);

		// Check to see if the point is a valid point on the Elliptic curve and is not infinity
		ipp_ret = ippsECCPCheckPoint(point_pubA, &ipp_result, p_ecc_state);
		if (ipp_result != ippECValid)
		{
			break;
		}
		ERROR_BREAK(ipp_ret);

		ipp_ret = sgx_replace_t::_ipp_newBN(NULL, sizeof(sgx_ec256_dh_shared_t), &BN_dh_share);
		ERROR_BREAK(ipp_ret);
		/* This API generates shareA = x-coordinate of (privKeyB*pubKeyA) */
		ipp_ret = ippsECCPSharedSecretDH(BN_dh_privB, point_pubA, BN_dh_share, p_ecc_state);
		ERROR_BREAK(ipp_ret);
		IppsBigNumSGN sgn = IppsBigNumPOS;
		int length = 0;
		Ipp32u * pdata = NULL;
		ipp_ret = ippsRef_BN(&sgn, &length, &pdata, BN_dh_share);
		ERROR_BREAK(ipp_ret);
		memset(p_shared_key->s, 0, sizeof(p_shared_key->s));
		ipp_ret = check_copy_size(sizeof(p_shared_key->s), ROUND_TO(length, 8) / 8);
		ERROR_BREAK(ipp_ret);
		memcpy(p_shared_key->s, pdata, ROUND_TO(length, 8) / 8);
	} while (0);

	// Clear temp buffer before free.
	//if (point_pubA) memset_s(point_pubA, ecPointSize, 0, ecPointSize);
	if (point_pubA) memset(point_pubA, 0, ecPointSize);
	SAFE_FREE(point_pubA);
	sgx_replace_t::_ipp_secure_free_BN(pubA_gx, sizeof(p_public_ga->gx));
	sgx_replace_t::_ipp_secure_free_BN(pubA_gy, sizeof(p_public_ga->gy));
	sgx_replace_t::_ipp_secure_free_BN(BN_dh_privB, sizeof(sgx_ec256_private_t));
	sgx_replace_t::_ipp_secure_free_BN(BN_dh_share, sizeof(sgx_ec256_dh_shared_t));


	if (ipp_result != ippECValid)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	switch (ipp_ret)
	{
	case ippStsNoErr: return SGX_SUCCESS;
	case ippStsNoMemErr:
	case ippStsMemAllocErr: return SGX_ERROR_OUT_OF_MEMORY;
	case ippStsNullPtrErr:
	case ippStsLengthErr:
	case ippStsOutOfRangeErr:
	case ippStsSizeErr:
	case ippStsBadArgErr: return SGX_ERROR_INVALID_PARAMETER;
	default: return SGX_ERROR_UNEXPECTED;
	}
}

sgx_status_t 
sgx_replace_t::cmac128_init(const sgx_cmac_128bit_key_t *p_key, sgx_cmac_state_handle_t* p_cmac_handle)
{
	if ((p_key == NULL) || (p_cmac_handle == NULL))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	IppsAES_CMACState* pState = NULL;
	int ippStateSize = 0;
	IppStatus error_code = ippStsNoErr;
	error_code = ippsAES_CMACGetSize(&ippStateSize);
	if (error_code != ippStsNoErr)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	pState = (IppsAES_CMACState*)malloc(ippStateSize);
	if (pState == NULL)
	{
		return SGX_ERROR_OUT_OF_MEMORY;
	}
	error_code = ippsAES_CMACInit((const Ipp8u *)p_key, SGX_CMAC_KEY_SIZE, pState, ippStateSize);
	if (error_code != ippStsNoErr)
	{
		// Clear state before free.
		//memset_s(pState, ippStateSize, 0, ippStateSize);
		memset(pState, 0, ippStateSize);
		free(pState);
		*p_cmac_handle = NULL;
		switch (error_code)
		{
		case ippStsMemAllocErr: return SGX_ERROR_OUT_OF_MEMORY;
		case ippStsNullPtrErr:
		case ippStsLengthErr: return SGX_ERROR_INVALID_PARAMETER;
		default: return SGX_ERROR_UNEXPECTED;
		}
	}
	*p_cmac_handle = pState;
	return SGX_SUCCESS;
}

sgx_status_t 
sgx_replace_t::cmac128_update(const uint8_t *p_src, uint32_t src_len, sgx_cmac_state_handle_t cmac_handle)
{
	if ((p_src == NULL) || (cmac_handle == NULL))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	IppStatus error_code = ippStsNoErr;
	error_code = ippsAES_CMACUpdate(p_src, src_len, (IppsAES_CMACState*)cmac_handle);
	switch (error_code)
	{
	case ippStsNoErr: return SGX_SUCCESS;
	case ippStsNullPtrErr:
	case ippStsLengthErr: return SGX_ERROR_INVALID_PARAMETER;
	default: return SGX_ERROR_UNEXPECTED;
	}
}

sgx_status_t 
sgx_replace_t::cmac128_final(sgx_cmac_state_handle_t cmac_handle, sgx_cmac_128bit_tag_t *p_hash)
{
	if ((cmac_handle == NULL) || (p_hash == NULL))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	IppStatus error_code = ippStsNoErr;
	error_code = ippsAES_CMACFinal((Ipp8u *)p_hash, SGX_CMAC_MAC_SIZE, (IppsAES_CMACState*)cmac_handle);
	switch (error_code)
	{
	case ippStsNoErr: return SGX_SUCCESS;
	case ippStsNullPtrErr:
	case ippStsLengthErr: return SGX_ERROR_INVALID_PARAMETER;
	default: return SGX_ERROR_UNEXPECTED;
	}
}

sgx_status_t 
sgx_replace_t::cmac128_close(sgx_cmac_state_handle_t cmac_handle)
{
	if (cmac_handle == NULL)
		return SGX_ERROR_INVALID_PARAMETER;
	sgx_replace_t::_secure_free_cmac128_state((IppsAES_CMACState*)cmac_handle);
	return SGX_SUCCESS;
}

void 
sgx_replace_t::_secure_free_cmac128_state(IppsAES_CMACState *pState)
{
	if (pState == NULL)
		return;
	int ippStateSize = 0;
	IppStatus error_code = ippStsNoErr;
	error_code = ippsAES_CMACGetSize(&ippStateSize);
	if (error_code != ippStsNoErr)
	{
		free(pState);
		return;
	}
	//memset_s(pState, ippStateSize, 0, ippStateSize);
	memset(pState, 0, ippStateSize);
	free(pState);
	return;
}


sgx_status_t 
sgx_replace_t::ecdsa_verify(const uint8_t *p_data, uint32_t data_size, const sgx_ec256_public_t *p_public, sgx_ec256_signature_t *p_signature, uint8_t *p_result, ecc_state_handle_t ecc_handle)
{
	if ((ecc_handle == NULL) || (p_public == NULL) || (p_signature == NULL) || (p_data == NULL) || (data_size < 1) || (p_result == NULL))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	IppStatus ipp_ret = ippStsNoErr;
	IppsECCPState* p_ecc_state = (IppsECCPState*)ecc_handle;
	IppECResult result = ippECInvalidSignature;
	*p_result = SGX_EC_INVALID_SIGNATURE;

	IppsBigNumState* p_ecp_order = NULL;
	IppsBigNumState* p_hash_bn = NULL;
	IppsBigNumState* p_msg_bn = NULL;
	IppsECCPPointState* p_reg_pub = NULL;
	IppsBigNumState* p_reg_pubx_bn = NULL;
	IppsBigNumState* p_reg_puby_bn = NULL;
	IppsBigNumState* p_signx_bn = NULL;
	IppsBigNumState* p_signy_bn = NULL;
	const int order_size = sizeof(_nistp256_r);
	uint32_t hash[8] = { 0 };
	int ecp_size = 0;

	do
	{
		ipp_ret = sgx_replace_t::_ipp_newBN(_nistp256_r, order_size, &p_ecp_order);
		ERROR_BREAK(ipp_ret);

		// Prepare the message used to sign.
		ipp_ret = ippsHashMessage(p_data, data_size, (Ipp8u*)hash, IPP_ALG_HASH_SHA256);
		ERROR_BREAK(ipp_ret);
		/* Byte swap in creation of Big Number from SHA256 hash output */
		ipp_ret = sgx_replace_t::_ipp_newBN(NULL, sizeof(hash), &p_hash_bn);
		ERROR_BREAK(ipp_ret);
		ipp_ret = ippsSetOctString_BN((Ipp8u*)hash, sizeof(hash), p_hash_bn);
		ERROR_BREAK(ipp_ret);

		ipp_ret = sgx_replace_t::_ipp_newBN(NULL, order_size, &p_msg_bn);
		ERROR_BREAK(ipp_ret);
		ipp_ret = ippsMod_BN(p_hash_bn, p_ecp_order, p_msg_bn);
		ERROR_BREAK(ipp_ret);

		//Init eccp point
		ipp_ret = ippsECCPPointGetSize(256, &ecp_size);
		ERROR_BREAK(ipp_ret);
		p_reg_pub = (IppsECCPPointState*)(malloc(ecp_size));
		if (!p_reg_pub)
		{
			ipp_ret = ippStsNoMemErr;
			break;
		}
		ipp_ret = ippsECCPPointInit(256, p_reg_pub);
		ERROR_BREAK(ipp_ret);
		ipp_ret = sgx_replace_t::_ipp_newBN((const uint32_t *)p_public->gx, sizeof(p_public->gx), &p_reg_pubx_bn);
		ERROR_BREAK(ipp_ret);
		ipp_ret = sgx_replace_t::_ipp_newBN((const uint32_t *)p_public->gy, sizeof(p_public->gy), &p_reg_puby_bn);
		ERROR_BREAK(ipp_ret);
		ipp_ret = ippsECCPSetPoint(p_reg_pubx_bn, p_reg_puby_bn, p_reg_pub, p_ecc_state);
		ERROR_BREAK(ipp_ret);
		ipp_ret = ippsECCPSetKeyPair(NULL, p_reg_pub, ippTrue, p_ecc_state);
		ERROR_BREAK(ipp_ret);

		ipp_ret = sgx_replace_t::_ipp_newBN(p_signature->x, order_size, &p_signx_bn);
		ERROR_BREAK(ipp_ret);
		ipp_ret = sgx_replace_t::_ipp_newBN(p_signature->y, order_size, &p_signy_bn);
		ERROR_BREAK(ipp_ret);

		// Verify the message.
		ipp_ret = ippsECCPVerifyDSA(p_msg_bn, p_signx_bn, p_signy_bn, &result,p_ecc_state);
		ERROR_BREAK(ipp_ret);
	} while (0);

	// Clear buffer before free.
	if (p_reg_pub)
		memset(p_reg_pub, 0, ecp_size);
		//memset_s(p_reg_pub, ecp_size, 0, ecp_size);
	SAFE_FREE(p_reg_pub);
	sgx_replace_t::_ipp_secure_free_BN(p_ecp_order, order_size);
	sgx_replace_t::_ipp_secure_free_BN(p_hash_bn, sizeof(hash));
	sgx_replace_t::_ipp_secure_free_BN(p_msg_bn, order_size);
	sgx_replace_t::_ipp_secure_free_BN(p_reg_pubx_bn, sizeof(p_public->gx));
	sgx_replace_t::_ipp_secure_free_BN(p_reg_puby_bn, sizeof(p_public->gy));
	sgx_replace_t::_ipp_secure_free_BN(p_signx_bn, order_size);
	sgx_replace_t::_ipp_secure_free_BN(p_signy_bn, order_size);

	switch (result) {
		case ippECValid: *p_result = SGX_EC_VALID; break;                           /* validation pass successfully */
	case ippECInvalidSignature: *p_result = SGX_EC_INVALID_SIGNATURE; break;    /* invalid signature */
	default: *p_result = SGX_EC_INVALID_SIGNATURE; break;
	}

	switch (ipp_ret)
	{
	case ippStsNoErr: return SGX_SUCCESS;
	case ippStsNoMemErr:
	case ippStsMemAllocErr: return SGX_ERROR_OUT_OF_MEMORY;
	case ippStsNullPtrErr:
	case ippStsLengthErr:
	case ippStsOutOfRangeErr:
	case ippStsSizeErr:
	case ippStsBadArgErr: return SGX_ERROR_INVALID_PARAMETER;
	default: return SGX_ERROR_UNEXPECTED;
	}
}


sgx_status_t 
sgx_replace_t::ecdsa_sign(const uint8_t *p_data, uint32_t data_size, sgx_ec256_private_t *p_private, sgx_ec256_signature_t *p_signature, ecc_state_handle_t ecc_handle) 
{
	if ((ecc_handle == NULL) || (p_private == NULL) || (p_signature == NULL) || (p_data == NULL) || (data_size < 1))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	IppStatus ipp_ret = ippStsNoErr;
	IppsECCPState* p_ecc_state = (IppsECCPState*)ecc_handle;
	IppsBigNumState* p_ecp_order = NULL;
	IppsBigNumState* p_hash_bn = NULL;
	IppsBigNumState* p_msg_bn = NULL;
	IppsBigNumState* p_eph_priv_bn = NULL;
	IppsECCPPointState* p_eph_pub = NULL;
	IppsBigNumState* p_reg_priv_bn = NULL;
	IppsBigNumState* p_signx_bn = NULL;
	IppsBigNumState* p_signy_bn = NULL;
	Ipp32u *p_sigx = NULL;
	Ipp32u *p_sigy = NULL;
	int ecp_size = 0;
	const int order_size = sizeof(_nistp256_r);
	uint32_t hash[8] = { 0 };

	do
	{

		ipp_ret = sgx_replace_t::_ipp_newBN(_nistp256_r, order_size, &p_ecp_order);
		ERROR_BREAK(ipp_ret);

		// Prepare the message used to sign.
		ipp_ret = ippsHashMessage(p_data, data_size, (Ipp8u*)hash, IPP_ALG_HASH_SHA256);
		ERROR_BREAK(ipp_ret);
		/* Byte swap in creation of Big Number from SHA256 hash output */
		ipp_ret = sgx_replace_t::_ipp_newBN(NULL, sizeof(hash), &p_hash_bn);
		ERROR_BREAK(ipp_ret);
		ipp_ret = ippsSetOctString_BN((Ipp8u*)hash, sizeof(hash), p_hash_bn);
		ERROR_BREAK(ipp_ret);

		ipp_ret = sgx_replace_t::_ipp_newBN(NULL, order_size, &p_msg_bn);
		ERROR_BREAK(ipp_ret);
		ipp_ret = ippsMod_BN(p_hash_bn, p_ecp_order, p_msg_bn);
		ERROR_BREAK(ipp_ret);

		// Get ephemeral key pair.
		ipp_ret = sgx_replace_t::_ipp_newBN(NULL, order_size, &p_eph_priv_bn);
		ERROR_BREAK(ipp_ret);
		//init eccp point
		ipp_ret = ippsECCPPointGetSize(256, &ecp_size);
		ERROR_BREAK(ipp_ret);
		p_eph_pub = (IppsECCPPointState*)(malloc(ecp_size));
		if (!p_eph_pub)
		{
			ipp_ret = ippStsNoMemErr;
			break;
		}
		ipp_ret = ippsECCPPointInit(256, p_eph_pub);
		ERROR_BREAK(ipp_ret);
		// Generate ephemeral key pair for signing operation
		// Notice that IPP ensures the private key generated is non-zero
		ipp_ret = ippsECCPGenKeyPair(p_eph_priv_bn, p_eph_pub, p_ecc_state,
			(IppBitSupplier)sgx_replace_t::_ipp_DRNGen, NULL);
		ERROR_BREAK(ipp_ret);
		ipp_ret = ippsECCPSetKeyPair(p_eph_priv_bn, p_eph_pub, ippFalse, p_ecc_state);
		ERROR_BREAK(ipp_ret);

		// Set the regular private key.
		ipp_ret = sgx_replace_t::_ipp_newBN((uint32_t *)p_private->r, sizeof(p_private->r),
			&p_reg_priv_bn);
		ERROR_BREAK(ipp_ret);
		ipp_ret = sgx_replace_t::_ipp_newBN(NULL, order_size, &p_signx_bn);
		ERROR_BREAK(ipp_ret);
		ipp_ret = sgx_replace_t::_ipp_newBN(NULL, order_size, &p_signy_bn);
		ERROR_BREAK(ipp_ret);

		// Sign the message.
		ipp_ret = ippsECCPSignDSA(p_msg_bn, p_reg_priv_bn, p_signx_bn, p_signy_bn,
			p_ecc_state);
		ERROR_BREAK(ipp_ret);

		IppsBigNumSGN sign;
		int length;
		ipp_ret = ippsRef_BN(&sign, &length, (Ipp32u**)&p_sigx, p_signx_bn);
		ERROR_BREAK(ipp_ret);
		memset(p_signature->x, 0, sizeof(p_signature->x));
		ipp_ret = check_copy_size(sizeof(p_signature->x), ROUND_TO(length, 8) / 8);
		ERROR_BREAK(ipp_ret);
		memcpy(p_signature->x, p_sigx, ROUND_TO(length, 8) / 8);
		//memset_s(p_sigx, sizeof(p_signature->x), 0, ROUND_TO(length, 8) / 8);
		memset(p_sigx, 0, ROUND_TO(length, 8) / 8);
		ipp_ret = ippsRef_BN(&sign, &length, (Ipp32u**)&p_sigy, p_signy_bn);
		ERROR_BREAK(ipp_ret);
		memset(p_signature->y, 0, sizeof(p_signature->y));
		ipp_ret = check_copy_size(sizeof(p_signature->y), ROUND_TO(length, 8) / 8);
		ERROR_BREAK(ipp_ret);
		memcpy(p_signature->y, p_sigy, ROUND_TO(length, 8) / 8);
		//memset_s(p_sigy, sizeof(p_signature->y), 0, ROUND_TO(length, 8) / 8);
		memset(p_sigy, 0, ROUND_TO(length, 8) / 8);
	} while (0);

	// Clear buffer before free.
	if (p_eph_pub)
		memset(p_eph_pub, 0, ecp_size);
		//memset_s(p_eph_pub, ecp_size, 0, ecp_size);
	SAFE_FREE(p_eph_pub);
	sgx_replace_t::_ipp_secure_free_BN(p_ecp_order, order_size);
	sgx_replace_t::_ipp_secure_free_BN(p_hash_bn, sizeof(hash));
	sgx_replace_t::_ipp_secure_free_BN(p_msg_bn, order_size);
	sgx_replace_t::_ipp_secure_free_BN(p_eph_priv_bn, order_size);
	sgx_replace_t::_ipp_secure_free_BN(p_reg_priv_bn, sizeof(p_private->r));
	sgx_replace_t::_ipp_secure_free_BN(p_signx_bn, order_size);
	sgx_replace_t::_ipp_secure_free_BN(p_signy_bn, order_size);

	switch (ipp_ret)
	{
	case ippStsNoErr: return SGX_SUCCESS;
	case ippStsNoMemErr:
	case ippStsMemAllocErr: return SGX_ERROR_OUT_OF_MEMORY;
	case ippStsNullPtrErr:
	case ippStsLengthErr:
	case ippStsOutOfRangeErr:
	case ippStsSizeErr:
	case ippStsBadArgErr: return SGX_ERROR_INVALID_PARAMETER;
	default: return SGX_ERROR_UNEXPECTED;
	}
}

sgx_status_t 
sgx_replace_t::aes_ctr_encrypt(const sgx_aes_ctr_128bit_key_t *p_key, const uint8_t *p_src, const uint32_t src_len, uint8_t *p_ctr, const uint32_t ctr_inc_bits, uint8_t *p_dst)
{
	IppStatus error_code = ippStsNoErr;
	IppsAESSpec* ptr_ctx = NULL;
	int ctx_size = 0;

	if ((p_key == NULL) || (p_src == NULL) || (p_ctr == NULL) || (p_dst == NULL))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	// AES-CTR-128 encryption
	error_code = ippsAESGetSize(&ctx_size);
	if (error_code != ippStsNoErr)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	ptr_ctx = (IppsAESSpec*)malloc(ctx_size);
	if (ptr_ctx == NULL)
	{
		return SGX_ERROR_OUT_OF_MEMORY;
	}

	// Init
	error_code = ippsAESInit((const Ipp8u*)p_key, SGX_AESCTR_KEY_SIZE, ptr_ctx, ctx_size);
	if (error_code != ippStsNoErr)
	{
		// Clear temp State before free.
		memset(ptr_ctx, 0, ctx_size);
		//memset_s(ptr_ctx, ctx_size, 0, ctx_size);
		free(ptr_ctx);
		switch (error_code)
		{
		case ippStsMemAllocErr: return SGX_ERROR_OUT_OF_MEMORY;
		case ippStsNullPtrErr:
		case ippStsLengthErr: return SGX_ERROR_INVALID_PARAMETER;
		default: return SGX_ERROR_UNEXPECTED;
		}
	}
	error_code = ippsAESEncryptCTR(p_src, p_dst, src_len, ptr_ctx, p_ctr, ctr_inc_bits);
	if (error_code != ippStsNoErr)
	{
		// Clear temp State before free.
		//memset_s(ptr_ctx, ctx_size, 0, ctx_size);
		memset(ptr_ctx, 0, ctx_size);
		free(ptr_ctx);
		switch (error_code)
		{
		case ippStsCTRSizeErr:
		case ippStsNullPtrErr:
		case ippStsLengthErr: return SGX_ERROR_INVALID_PARAMETER;
		default: return SGX_ERROR_UNEXPECTED;
		}
	}
	// Clear temp State before free.
	//memset_s(ptr_ctx, ctx_size, 0, ctx_size);
	memset(ptr_ctx, 0, ctx_size);
	free(ptr_ctx);
	return SGX_SUCCESS;
}

sgx_status_t 
sgx_replace_t::aes_ctr_decrypt(const sgx_aes_ctr_128bit_key_t *p_key, const uint8_t *p_src, const uint32_t src_len, uint8_t *p_ctr, const uint32_t ctr_inc_bits, uint8_t *p_dst)
{
	IppStatus error_code = ippStsNoErr;
	IppsAESSpec* ptr_ctx = NULL;
	int ctx_size = 0;

	if ((p_key == NULL) || (p_src == NULL) || (p_ctr == NULL) || (p_dst == NULL))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	// AES-CTR-128 encryption
	error_code = ippsAESGetSize(&ctx_size);
	if (error_code != ippStsNoErr)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	ptr_ctx = (IppsAESSpec*)malloc(ctx_size);
	if (ptr_ctx == NULL)
	{
		return SGX_ERROR_OUT_OF_MEMORY;
	}

	// Init
	error_code = ippsAESInit((const Ipp8u*)p_key, SGX_AESCTR_KEY_SIZE, ptr_ctx, ctx_size);
	if (error_code != ippStsNoErr)
	{
		// Clear temp State before free.
		//memset_s(ptr_ctx, ctx_size, 0, ctx_size);
		memset(ptr_ctx, 0, ctx_size);
		free(ptr_ctx);
		switch (error_code)
		{
		case ippStsMemAllocErr: return SGX_ERROR_OUT_OF_MEMORY;
		case ippStsNullPtrErr:
		case ippStsLengthErr: return SGX_ERROR_INVALID_PARAMETER;
		default: return SGX_ERROR_UNEXPECTED;
		}
	}
	error_code = ippsAESDecryptCTR(p_src, p_dst, src_len, ptr_ctx, p_ctr, ctr_inc_bits);
	if (error_code != ippStsNoErr)
	{
		// Clear temp State before free.
		//memset_s(ptr_ctx, ctx_size, 0, ctx_size);
		memset(ptr_ctx, 0, ctx_size);
		free(ptr_ctx);
		switch (error_code)
		{
		case ippStsCTRSizeErr:
		case ippStsNullPtrErr:
		case ippStsLengthErr: return SGX_ERROR_INVALID_PARAMETER;
		default: return SGX_ERROR_UNEXPECTED;
		}
	}
	// Clear temp State before free.
	//memset_s(ptr_ctx, ctx_size, 0, ctx_size);
	memset(ptr_ctx, 0, ctx_size);
	free(ptr_ctx);
	return SGX_SUCCESS;
}

sgx_status_t 
sgx_replace_t::sha256_init(sgx_sha_state_handle_t* p_sha_handle)
{
	IppStatus ipp_ret = ippStsNoErr;
	IppsHashState* p_temp_state = NULL;

	if (p_sha_handle == NULL)
		return SGX_ERROR_INVALID_PARAMETER;

	int ctx_size = 0;
	ipp_ret = ippsHashGetSize(&ctx_size);
	if (ipp_ret != ippStsNoErr)
		return SGX_ERROR_UNEXPECTED;
	p_temp_state = (IppsHashState*)(malloc(ctx_size));
	if (p_temp_state == NULL)
		return SGX_ERROR_OUT_OF_MEMORY;
	ipp_ret = ippsHashInit(p_temp_state, IPP_ALG_HASH_SHA256);
	if (ipp_ret != ippStsNoErr)
	{
		SAFE_FREE(p_temp_state);
		*p_sha_handle = NULL;
		switch (ipp_ret)
		{
		case ippStsNullPtrErr:
		case ippStsLengthErr: return SGX_ERROR_INVALID_PARAMETER;
		default: return SGX_ERROR_UNEXPECTED;
		}
	}

	*p_sha_handle = p_temp_state;
	return SGX_SUCCESS;
}

sgx_status_t 
sgx_replace_t::sha256_update(const uint8_t *p_src, uint32_t src_len, sgx_sha_state_handle_t sha_handle)
{
	if ((p_src == NULL) || (sha_handle == NULL))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	IppStatus ipp_ret = ippStsNoErr;
	ipp_ret = ippsHashUpdate(p_src, src_len, (IppsHashState*)sha_handle);
	switch (ipp_ret)
	{
	case ippStsNoErr: return SGX_SUCCESS;
	case ippStsNullPtrErr:
	case ippStsLengthErr: return SGX_ERROR_INVALID_PARAMETER;
	default: return SGX_ERROR_UNEXPECTED;
	}
}

sgx_status_t 
sgx_replace_t::sha256_close(sgx_sha_state_handle_t sha_handle)
{
	if (sha_handle == NULL)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	SAFE_FREE(sha_handle);
	return SGX_SUCCESS;
}

sgx_status_t 
sgx_replace_t::sha256_get_hash(sgx_sha_state_handle_t sha_handle, sgx_sha256_hash_t *p_hash)
{
	if ((sha_handle == NULL) || (p_hash == NULL))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	IppStatus ipp_ret = ippStsNoErr;
	ipp_ret = ippsHashGetTag((Ipp8u*)p_hash, SGX_SHA256_HASH_SIZE, (IppsHashState*)sha_handle);
	switch (ipp_ret)
	{
	case ippStsNoErr: return SGX_SUCCESS;
	case ippStsNullPtrErr:
	case ippStsLengthErr: return SGX_ERROR_INVALID_PARAMETER;
	default: return SGX_ERROR_UNEXPECTED;
	}
}
