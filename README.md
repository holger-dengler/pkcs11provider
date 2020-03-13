# pkcs11provider

work in progress

### build

```
./bootstrap
./configure
make
```

### test
```
make check
```

### usage

Configuring the provider in the config file:
```
openssl_conf = openssl_init

[openssl_init]
providers = providers_sect

[providers_sect]
pkcs11 = pkcs11_sect

[pkcs11_sect]
module = pkcs11.so
pkcs11module = <mymodule.so>
pkcs11slotid = <myslotid>
```

Querying the provider via the CLI:
```
openssl provider -vvv pkcs11
```

Loading the provider from the application:
```
OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, "pkcs11");
if (prov == NULL)
    /* handle error */;
/* [...] */
if (OSSL_PROVIDER_unload(prov) != 1)
    /* handle error */;
```

The pkcs11 module shared object resp. the pkcs11 slot id can also be specified by setting the PKCS11MODULE resp. PKCS11SLOTID environment variable. If the environment variable is set, it will take precedence over the config file setting.
