#!/bin/bash

# set default values
export PKCS11MODULE=${PKCS11MODULE:-libopencryptoki.so};
export PKCS11SLOTID=${PKCS11SLOTID:-1};
export PKCS11USERPIN=${PKCS11USERPIN:-87654321};
