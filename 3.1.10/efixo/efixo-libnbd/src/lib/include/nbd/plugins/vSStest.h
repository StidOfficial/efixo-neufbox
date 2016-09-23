#ifndef _NBD_PLUGIN_VSSTEST_H_
#define _NBD_PLUGIN_VSSTEST_H_

#include <stdlib.h>
#include <string.h>

#define RESULT_MAX_CHAR	256

typedef enum VSS_TEST_STATUS {
	VSS_TEST_NOT_RUN,
	VSS_TEST_IN_PROGRESS,
	VSS_TEST_SUCCEEDED,
	VSS_TEST_FAILED_CHECK,
	VSS_TEST_FAILED,
	VSS_TEST_MAX
} VSS_TEST_STATUS;

typedef enum VSS_TEST_GR909_ERROR {
	VSS_TEST_GR909_ERROR_VOLTAGE = 1,
	VSS_TEST_GR909_ERROR_RESIST,
	VSS_TEST_GR909_ERROR_UNHOOK,
	VSS_TEST_GR909_ERROR_LINELOAD,
} VSS_TEST_GR909_ERROR;

typedef enum VSS_TEST_HOOKNTONE_ERROR {
	VSS_TEST_HOOKNTONE_ERROR_PICKUP = 1,
	VSS_TEST_HOOKNTONE_ERROR_HANGUP,
	VSS_TEST_HOOKNTONE_ERROR_FT,
} VSS_TEST_HOOKNTONE_ERROR;

typedef enum VSS_TEST_DTMF_ERROR {
	VSS_TEST_DTMF_ERROR_PRESS_0 = 1,
	VSS_TEST_DTMF_ERROR_RELEASE_0,
	VSS_TEST_DTMF_ERROR_PRESS_1,
	VSS_TEST_DTMF_ERROR_RELEASE_1,
	VSS_TEST_DTMF_ERROR_PRESS_2,
	VSS_TEST_DTMF_ERROR_RELEASE_2,
	VSS_TEST_DTMF_ERROR_PRESS_3,
	VSS_TEST_DTMF_ERROR_RELEASE_3,
	VSS_TEST_DTMF_ERROR_PRESS_4,
	VSS_TEST_DTMF_ERROR_RELEASE_4,
	VSS_TEST_DTMF_ERROR_PRESS_5,
	VSS_TEST_DTMF_ERROR_RELEASE_5,
	VSS_TEST_DTMF_ERROR_PRESS_6,
	VSS_TEST_DTMF_ERROR_RELEASE_6,
	VSS_TEST_DTMF_ERROR_PRESS_7,
	VSS_TEST_DTMF_ERROR_RELEASE_7,
	VSS_TEST_DTMF_ERROR_PRESS_8,
	VSS_TEST_DTMF_ERROR_RELEASE_8,
	VSS_TEST_DTMF_ERROR_PRESS_9,
	VSS_TEST_DTMF_ERROR_RELEASE_9,
} VSS_TEST_DTMF_ERROR;

typedef struct {
	VSS_TEST_STATUS init_status;
	int init_errcode;
	float init_LVopen, init_LCopen;
	float init_LVfwa, init_LCfwa;
	char init_result[RESULT_MAX_CHAR];

	VSS_TEST_STATUS ring_status;
	char ring_result[RESULT_MAX_CHAR];

	VSS_TEST_STATUS hookntone_status;
	unsigned short hookntone_state;
	float hookntone_LVfwa_offhook, hookntone_LCfwa_offhook;
	char hookntone_result[RESULT_MAX_CHAR];

	VSS_TEST_STATUS dtmf_status;
	unsigned short dtmf_state;
	char dtmf_result[RESULT_MAX_CHAR];

	VSS_TEST_STATUS gr909_status;
	unsigned short gr909_state;
	unsigned short gr909_voltage_state;
	unsigned short gr909_resistive_state;
	float gr909_ac_vtip, gr909_dc_vtip;
	float gr909_ac_vring, gr909_dc_vring;
	float gr909_ac_vloop, gr909_dc_vloop;
	double gr909_rtg, gr909_rrg, gr909_rtr;
	double gr909_rv1, gr909_rv2;
	double gr909_ren;
	char gr909_result[RESULT_MAX_CHAR];
} vSS_testResults;

#endif
