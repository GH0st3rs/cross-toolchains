# cross-toolchains
Script for build cross-toolchain for ARMEL, ARMBE, MIPSEL, MIPS, PowerPC, i686


## Docker enviroment variables

For use that variables, set them with `--build-arg`

* TARGET - Set custom target for toolchain

* CFLAGS_FOR_TARGET - Set CFLAGS for build taret binaries

* GCC_PARAMS - Set custom flags for build target GCC

* GLIBC_EX_FLAGS - Set custom flags for build target glibc

* SSL_MARCH - Set custom -march for build target openssl

### Execute post scripts

If you need to perform some additional actions after the assembly of the toolchain is complete, add the following file:

```bash
docker build -t mipsel-linux-gnu \
    -v /path/to/your_script:/etc/post_toolchain_script.sh \
    --build-arg ARCH=mipsel .
```


## Howto build the docker images

### MIPS Little Endian x32
```docker build --build-arg ARCH=mipsel -t mipsel-linux-gnu .```

### MIPS Big Endian x32
```docker build --build-arg ARCH=mips -t mips-linux-gnu .```

### ARM Little Endian x32
```docker build --build-arg ARCH=armel -t armel-linux-gnu .```

### ARM Big Endian x32
```docker build --build-arg ARCH=armbe -t armbe-linux-gnu .```

### i686 Little Endian
```docker build --build-arg ARCH=i686 -t i686-linux-gnu .```

### PowerPC Big Endian x32
```docker build --build-arg ARCH=powerpc -t powerpc-linux-gnu .```