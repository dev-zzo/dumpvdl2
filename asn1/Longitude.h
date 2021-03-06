/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "PMCPDLCMessageSetVersion1"
 * 	found in "atn-cpdlc.asn1"
 * 	`asn1c -fcompound-names -gen-PER`
 */

#ifndef	_Longitude_H_
#define	_Longitude_H_


#include <asn_application.h>

/* Including external dependencies */
#include "LongitudeType.h"
#include "LongitudeDirection.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Longitude */
typedef struct Longitude {
	LongitudeType_t	 longitudeType;
	LongitudeDirection_t	 longitudeDirection;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Longitude_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Longitude;

#ifdef __cplusplus
}
#endif

#endif	/* _Longitude_H_ */
#include <asn_internal.h>
