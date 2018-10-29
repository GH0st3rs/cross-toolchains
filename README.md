# cross-toolchains
Script for build cross-toolchain for ARMEL, ARMBE, MIPSEL, MIPS, PowerPC, TileGX, i686

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

### TileGX Little Endian x32
```docker build --build-arg ARCH=tilegx -t tilegx-linux-gnu .```