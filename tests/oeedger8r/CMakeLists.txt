# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
	add_subdirectory(enc)
endif()

add_enclave_test(tests/oeedger8r edl_host edl_enc)
add_enclave_test(tests/oeedger8r_other edl_host edl_other_enc)

add_subdirectory(behavior)
