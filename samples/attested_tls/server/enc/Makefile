# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Detect C and C++ compiler options
# if not gcc and g++, default to clang-7
C_COMPILER=$(notdir $(CC))
ifeq ($(C_COMPILER), gcc)
        CXX_COMPILER=$(notdir $(CXX))
        USE_GCC = true
endif

ifeq ($(USE_GCC),)
        CC = clang-7
        CXX = clang++-7
        C_COMPILER=clang
        CXX_COMPILER=clang++
endif

CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)

.PHONY: all build clean run

all:
	$(MAKE) genkey
	$(MAKE) -C ../../client/enc genkey
	$(MAKE) build
	$(MAKE) sign

private.pem:
	openssl genrsa -out $@ -3 3072

public.pem: private.pem
	openssl rsa -in $< -out $@ -pubout

# The enclaves in the sample will check if the other enclave is signed
# with the expected key. Since this sample builds both enclaves, we can
# inject the expected public keys at build time.
#
# If the other public key isn't known, then we would have to load the
# public key from the host. We can't simply load the raw public key since
# a malicious host might change it. So, we would need to load a certicate
# that contains the expected public key that is signed by a trusted CA.
genkey: public.pem
	chmod u+x ../../scripts/gen_pubkey_header.sh
	../../scripts/gen_pubkey_header.sh tls_server_enc_pubkey.h $<
	cp tls_server_enc_pubkey.h ../../client/enc
	cp tls_server_enc_pubkey.h ../../non_enc_client

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../tls_server.edl --trusted --trusted-dir .
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -std=c++11 ecalls.cpp server.cpp identity_verifier.cpp cert_verifier.cpp crypto.cpp ../../common/utility.cpp
	$(CC) -c $(CFLAGS) $(CINCLUDES) tls_server_t.c
	$(CXX) -o tls_server_enc ecalls.o server.o cert_verifier.o identity_verifier.o crypto.o utility.o tls_server_t.o $(LDFLAGS) -lmbedtls -lmbedcrypto -loehostsock -loehostresolver -loecore -loelibc -loesyscall

sign:
	oesign sign -e tls_server_enc -c enc.conf -k private.pem

clean:
	rm -f *.o tls_server_enc tls_server_enc.signed tls_server_enc.signed.so tls_server_t.* tls_server_args.h *.pem tls_server_enc_pubkey.h tls_client_enc_pubkey.h
