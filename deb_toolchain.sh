#!/bin/bash

# Set colors
if [ -f /.dockerenv ]; then
    # Regular
    black=""  # Black
    red=""  # Red
    green=""  # Green
    yellow=""  # Yellow
    blue=""  # Blue
    purple=""  # Purple
    cyan=""  # Cyan
    white=""  # White
    # Bold
    BLACK=""  # Black
    RED=""  # Red
    GREEN=""  # Green
    YELLOW=""  # Yellow
    BLUE=""  # Blue
    PURPLE=""  # Purple
    CYAN=""  # Cyan
    WHITE="" # White
    # Reset
    NC="" # Text Reset
else
    # Regular
    black="$(tput setaf 0 2>/dev/null || echo '\e[0;30m')"  # Black
    red="$(tput setaf 1 2>/dev/null || echo '\e[0;31m')"  # Red
    green="$(tput setaf 2 2>/dev/null || echo '\e[0;32m')"  # Green
    yellow="$(tput setaf 3 2>/dev/null || echo '\e[0;33m')"  # Yellow
    blue="$(tput setaf 4 2>/dev/null || echo '\e[0;34m')"  # Blue
    purple="$(tput setaf 5 2>/dev/null || echo '\e[0;35m')"  # Purple
    cyan="$(tput setaf 6 2>/dev/null || echo '\e[0;36m')"  # Cyan
    white="$(tput setaf 7 2>/dev/null || echo '\e[0;37m')"  # White
    # Bold
    BLACK="$(tput setaf 0 2>/dev/null)$(tput bold 2>/dev/null || echo '\e[1;30m')"  # Black
    RED="$(tput setaf 1 2>/dev/null)$(tput bold 2>/dev/null || echo '\e[1;31m')"  # Red
    GREEN="$(tput setaf 2 2>/dev/null)$(tput bold 2>/dev/null || echo '\e[1;32m')"  # Green
    YELLOW="$(tput setaf 3 2>/dev/null)$(tput bold 2>/dev/null || echo '\e[1;33m')"  # Yellow
    BLUE="$(tput setaf 4 2>/dev/null)$(tput bold 2>/dev/null || echo '\e[1;34m')"  # Blue
    PURPLE="$(tput setaf 5 2>/dev/null)$(tput bold 2>/dev/null || echo '\e[1;35m')"  # Purple
    CYAN="$(tput setaf 6 2>/dev/null)$(tput bold 2>/dev/null || echo '\e[1;36m')"  # Cyan
    WHITE="$(tput setaf 7 2>/dev/null)$(tput bold 2>/dev/null || echo '\e[1;37m')" # White
    # Reset
    NC="$(tput sgr 0 2>/dev/null || echo '\e[0m')" # Text Reset
fi

if [ -f /.dockerenv ]; then
    LOG_FILE=""
    ERROR_FILE=""
else
    LOG_FILE=$(pwd)/$1-output.log
    ERROR_FILE=$(pwd)/$1-error.log
fi
RESULT_FILE=$(pwd)/$1-result.log
# Clear logs
rm -rf $LOG_FILE $ERROR_FILE

# Set script params
trap 'previous_command=$this_command; this_command=$BASH_COMMAND' DEBUG

redirect_output() {
    if [ -f /.dockerenv ]; then
        return
    else
        # Save stdout and stderr
        exec 3>&1 4>&2
        # Set output log files
        exec 2>>$ERROR_FILE
        exec 1>>$LOG_FILE
    fi
}

restore_output() {
    if [ -f /.dockerenv ]; then
        return
    else
        # Restore original stdout/stderr
        exec 1>&3 2>&4
        # Close the unused descriptors
        exec 3>&- 4>&-
    fi
}

download() {
    SRC_ARC=$(echo $1|grep -o '[a-zA-Z0-9\.\-]\+\.tar\.[a-z2]\+'|head -n1)
    print_info "Start download $SRC_ARC"
    if [[ ! -f $SRC_ARC ]]; then
        wget -q $1
    fi
    if [[ ! -f $SRC_ARC ]]; then
        print_error "File $SRC_ARC not found! There may be installation problems"
    else
        restore_output
        echo -n "${GREEN}[+] Extracting: $SRC_ARC"; tar -xf $SRC_ARC; echo " => done${NC}"
        redirect_output
    fi
}

strip_debug() {
    strip --strip-unneeded --strip-debug -x -R .comment -R .note.ABI-tag -R .note.gnu.build-id $1
}

print_info() {
    restore_output
    echo "${YELLOW}[*] INFO: $1${NC}"
    redirect_output
}

print_error() {
    restore_output
    echo "${RED}[!] ERROR: $1${NC}"
    redirect_output
}

print_success() {
    restore_output
    echo "${GREEN}[+] SUCCESS: $1${NC}"
    redirect_output
}

# Set error handler
err_report() {
    print_error "line $1 => '$previous_command'"
    print_info "See $ERROR_FILE for more info"
    exit 1
}


USAGE="Usage: $0 [mipsel|mips|armel|armv4l|armbe|i686|powerpc|tilegx]"
if [[ $1 == mipsel ]]; then
    export TARGET=mipsel-linux-gnu
    export KERNEL_ARCH=mips
elif [[ $1 == mips ]]; then
    export TARGET=mips-linux-gnu
    export KERNEL_ARCH=mips
elif [[ $1 == armel ]]; then
    export TARGET=arm-linux-gnueabi
    export KERNEL_ARCH=arm
elif [[ $1 == armv4l ]]; then
    export TARGET=armv4l-unknown-linux
    export KERNEL_ARCH=armv4
elif [[ $1 == armbe ]]; then
    export TARGET=armbe-linux-gnueabi
    export CPPFLAGS_FOR_TARGET="-mbig-endian"
    export CFLAGS_FOR_TARGET="-mbig-endian"
    export GCC_PARAMS="--with-endian=big"
    export KERNEL_ARCH=arm
elif [[ $1 == i686 ]]; then
    export TARGET=i686-pc-linux-gnu
    export KERNEL_ARCH=x86
elif [[ $1 == powerpc ]]; then
    export TARGET=powerpc-linux-gnu
    export KERNEL_ARCH=powerpc
elif [[ $1 == r3000 ]]; then
    export TARGET=mips-linux-gnu
    export KERNEL_ARCH=mips
    export CPPFLAGS_FOR_TARGET="-march=r3000"
    export CFLAGS_FOR_TARGET="-march=r3000"
    export GCC_PARAMS="--with-arch=r3000"
elif [[ $1 == tilegx ]]; then
    export TARGET=tilegx-linux-gnu
    export KERNEL_ARCH=tilegx
    export GCC_PARAMS="--disable-libssp"
    export CFLAGS_FOR_TARGET="-m32"
    export CPPFLAGS_FOR_TARGET=$CFLAGS_FOR_TARGET
else
    echo $USAGE
    exit 1
fi


trap 'err_report $LINENO' ERR
trap 'restore_output' EXIT


TOOLCHAIN_DIR=/usr
export TARGET_CC="$TARGET-gcc $CFLAGS_FOR_TARGET"
# Global version vars
export GCCv=7.1.0
export GLIBCv=2.20
export BINUTILSv=2.28
export MPFRv=3.1.5
export GMPv=6.1.2
export MPCv=1.0.3
export ISLv=0.16.1
export CLOOGv=0.18.1
export KERNELv=3.1 #2.6.38.8
# Global param vars
export USR=$TOOLCHAIN_DIR
export PREFIX=$USR/$TARGET
export PATH=$PATH:$PREFIX/bin:$USR/bin
export PARALLEL_MAKE=-j3
if [[ $(uname -m) == x86_64 ]]; then
    export DEB_ARCH=amd64
else
    export DEB_ARCH=i386
fi
export DEBv=1.0
export DEB_TARGET=$1 #$(echo $TARGET|tr '-' ' '|awk '{print $1}')
export DEB_PACK=$(pwd)/${DEB_TARGET}_toolchain_v${DEBv}_${DEB_ARCH}
export TMP_BUILD_DIR=$(pwd)/$DEB_TARGET-cross


# Check kernel generation
if [[ $KERNELv > 3 ]] && [[ $KERNELv < 4 ]]; then export KERNEL_GEN=v3.x; fi
if [[ $KERNELv > 4 ]] && [[ $KERNELv < 5 ]]; then export KERNEL_GEN=v4.x; fi
if [[ $KERNELv > 2.6 ]] && [[ $KERNELv < 3 ]]; then export KERNEL_GEN=v2.6; fi
if [[ $KERNELv > 2.5 ]] && [[ $KERNELv < 2.6 ]]; then export KERNEL_GEN=v2.5; fi
if [[ $KERNELv > 2.4 ]] && [[ $KERNELv < 2.5 ]]; then export KERNEL_GEN=v2.4; fi
if [[ $KERNELv > 2.3 ]] && [[ $KERNELv < 2.4 ]]; then export KERNEL_GEN=v2.3; fi


redirect_output
print_info "Update apt-get"
apt-get update && apt-get -y upgrade
apt-get install -y g++ make gawk autoconf libtool bison wget texinfo
apt-get -y autoremove


if [[ ! -d $TMP_BUILD_DIR ]]; then
    mkdir $TMP_BUILD_DIR
    cd $TMP_BUILD_DIR
else
    cd $TMP_BUILD_DIR
    print_info "Remove previous sources"
    ls|grep -v "\.tar\."| xargs rm -rf
fi
if [[ -d $DEB_PACK ]]; then
    rm -rf $DEB_PACK
fi
mkdir -p $DEB_PACK


print_info "Download sources"
SOURCE_LINKS=(
    https://ftp.gnu.org/gnu/binutils/binutils-$BINUTILSv.tar.gz
    https://ftp.gnu.org/gnu/gcc/gcc-$GCCv/gcc-$GCCv.tar.gz
    https://www.kernel.org/pub/linux/kernel/$KERNEL_GEN/linux-$KERNELv.tar.gz
    https://ftp.gnu.org/gnu/glibc/glibc-$GLIBCv.tar.bz2
    https://ftp.gnu.org/gnu/glibc/glibc-ports-$GLIBCv.tar.bz2
    https://ftp.gnu.org/gnu/mpfr/mpfr-$MPFRv.tar.bz2
    https://ftp.gnu.org/gnu/gmp/gmp-$GMPv.tar.bz2
    https://ftp.gnu.org/gnu/mpc/mpc-$MPCv.tar.gz
    ftp://gcc.gnu.org/pub/gcc/infrastructure/isl-$ISLv.tar.bz2
    ftp://gcc.gnu.org/pub/gcc/infrastructure/cloog-$CLOOGv.tar.gz
)
for i in ${SOURCE_LINKS[@]}; do download $i; done


print_info "Create links"
cd binutils-$BINUTILSv
ln -s ../mpfr-$MPFRv mpfr
ln -s ../gmp-$GMPv gmp
ln -s ../mpc-$MPCv mpc
ln -s ../isl-$ISLv isl
ln -s ../cloog-$CLOOGv cloog
cd ..
cd gcc-$GCCv
ln -s ../mpfr-$MPFRv mpfr
ln -s ../gmp-$GMPv gmp
ln -s ../mpc-$MPCv mpc
ln -s ../isl-$ISLv isl
ln -s ../cloog-$CLOOGv cloog
cd ..


if ! grep -Fxq "binutils" $RESULT_FILE; then
    print_info "Compile binutils"
    mkdir binutils-$BINUTILSv-build && cd binutils-$BINUTILSv-build
    CFLAGS="-s -static -O2" ../binutils-$BINUTILSv/configure --prefix=$USR --target=$TARGET --disable-multilib --disable-werror --program-prefix=$TARGET- --disable-doc
    make $PARALLEL_MAKE configure-host
    make LDFLAGS="-all-static" $PARALLEL_MAKE
    make DESTDIR=$DEB_PACK install-strip
    make install-strip
    cd ..
    echo "binutils" > $RESULT_FILE
else
    print_success "Binutils installed"
fi


if ! grep -Fxq "headers" $RESULT_FILE; then
    print_info "Install headers for $KERNEL_ARCH"
    cd linux-$KERNELv
    make ARCH=$KERNEL_ARCH INSTALL_HDR_PATH=$PREFIX headers_install
    make ARCH=$KERNEL_ARCH INSTALL_HDR_PATH=$DEB_PACK/$PREFIX headers_install
    if [[ $KERNELv > 3 ]] && [[ $KERNELv < 3.2 ]] && [[ $KERNEL_ARCH == tilegx ]]; then
        wget -q -c http://www.mellanox.com/repository/solutions/tile-scm/opcode.tar.bz2 -O /tmp/opcode.tar.bz2
        tar -C /tmp -xf /tmp/opcode.tar.bz2
        if [[ ! -d $PREFIX/include/arch ]]; then
            mkdir $PREFIX/include/arch
        fi
        cp -r /tmp/usr/* $PREFIX/
        cp ./arch/tile/include/arch/*.h $PREFIX/include/arch/
        if ! grep -Fq __uint_reg_t $PREFIX/include/arch/abi.h; then
            sed -i 's|\(f __ASSEMBLER__\)|\1\ntypedef unsigned long long __uint_reg_t;\ntypedef long long __int_reg_t;|g' $PREFIX/include/arch/abi.h
        fi
        cp -r $PREFIX/include/arch $DEB_PACK/$PREFIX/include/
    fi
    cd ..
    echo "headers" >> $RESULT_FILE
else
    print_success "Linux headers installed"
fi


if ! grep -Fxq "gcc_simple" $RESULT_FILE; then
    print_info "Compile GCC without libc"
    mkdir gcc-$GCCv-build && cd gcc-$GCCv-build
    CFLAGS="-static" ../gcc-$GCCv/configure --disable-shared --prefix=$USR --target=$TARGET --enable-languages=c,c++ --disable-multilib --disable-threads --libdir=$USR/lib --libexecdir=$USR/lib --includedir=$PREFIX/include --enable-version-specific-runtime-libs --with-gxx-include-dir=$PREFIX/c++/include --disable-doc $GCC_PARAMS
    make $PARALLEL_MAKE all-gcc
    make DESTDIR=$DEB_PACK install-gcc
    make install-gcc
    cd ..
    echo "gcc_simple" >> $RESULT_FILE
else
    print_success "GCC without libc installed"
fi


if ! grep -Fxq "libc_basic" $RESULT_FILE; then
    print_info "Compile basic libc"
    mkdir glibc-$GLIBCv-build && cd glibc-$GLIBCv-build
    CC="$TARGET_CC" ../glibc-$GLIBCv/configure --prefix=$PREFIX --build=$MACHTYPE --host=$TARGET --target=$TARGET --with-headers=$PREFIX/include --disable-multilib libc_cv_forced_unwind=yes libc_cv_ssp=no
    make install-bootstrap-headers=yes install-headers DESTDIR=$DEB_PACK
    make install-bootstrap-headers=yes install-headers
    make $PARALLEL_MAKE csu/subdir_lib CC="$TARGET_CC"
    install csu/crt1.o csu/crti.o csu/crtn.o $PREFIX/lib/
    install csu/crt1.o csu/crti.o csu/crtn.o $DEB_PACK/$PREFIX/lib/
    $TARGET_CC -nostdlib -nostartfiles -shared -x c /dev/null -o $PREFIX/lib/libc.so
    $TARGET_CC -nostdlib -nostartfiles -shared -x c /dev/null -o $DEB_PACK/$PREFIX/lib/libc.so
    touch $PREFIX/include/stubs.h
    touch $DEB_PACK/$PREFIX/include/stubs.h
    cd ..
    echo "libc_basic" >> $RESULT_FILE
else
    print_success "Basic libc installed"
fi


if ! grep -Fxq "libgcc" $RESULT_FILE; then
    print_info "Compile GCC all-target"
    cd gcc-$GCCv-build
    make $PARALLEL_MAKE all-target-libgcc
    make DESTDIR=$DEB_PACK install-target-libgcc
    make install-target-libgcc
    cd ..
    echo "libgcc" >> $RESULT_FILE
else
    print_success "GCC all-target installed"
fi


if ! grep -Fxq "libc_full" $RESULT_FILE; then
    print_info "Compile libc"
    cd glibc-$GLIBCv-build
    make $PARALLEL_MAKE
    make DESTDIR=$DEB_PACK install
    make install
    cd ..
    echo "libc_full" >> $RESULT_FILE
else
    print_success "Full libc installed"
fi


if ! grep -Fxq "libstdc++" $RESULT_FILE; then
    print_info "Compile libstdc++"
    cd gcc-$GCCv-build
    make $PARALLEL_MAKE all
    make DESTDIR=$DEB_PACK install
    make install
    cd ..
    echo "libstdc++" >> $RESULT_FILE
else
    print_success "libstdc++ installed"
fi


if ! grep -Fxq "test" $RESULT_FILE; then
    print_info "Test GCC"
    echo "void main(){}" > test.c
    $TARGET_CC test.c -static
    print_success "$(file a.out)"
    cd ..
    echo "test" >> $RESULT_FILE
fi


for item in $(file $USR/bin/$TARGET*|grep ELF|tr : ' '|awk '{print $1}'); do
    strip_debug "$item"
done


print_success "Toolchain for $TARGET is ready"
print_success "Use $TARGET_CC for compile your projects"


if [ -z ${MAKE_DEB} ]; then
    exit 0
fi


if ! grep -Fxq "deb" $RESULT_FILE; then
    print_info "Start create deb package"
    sudo apt-get -y install md5deep fakeroot
    # Strip binary for deb
    for item in $(file $DEB_PACK/$USR/bin/$TARGET*|grep ELF|tr : ' '|awk '{print $1}'); do
        strip_debug "$item"
    done
    rm -rf $DEB_PACK/DEBIAN
    rm -rf $DEB_PACK/usr/share
    mkdir -p $DEB_PACK/DEBIAN
    TOOL_DIR=$(echo $DEB_PACK|sed -e "s|$(pwd)/||")
    NAME=$(echo $TOOL_DIR|sed 's/_/-/g')
    echo "Package: $NAME" >> $DEB_PACK/DEBIAN/control
    echo "Version: ${DEBv}" >> $DEB_PACK/DEBIAN/control
    echo "Architecture: ${DEB_ARCH}" >> $DEB_PACK/DEBIAN/control
    echo "Maintainer: Admin" >> $DEB_PACK/DEBIAN/control
    echo "Priority: optional" >> $DEB_PACK/DEBIAN/control
    echo "Installed-Size: $(du -s $DEB_PACK/usr|awk '{print $1}')" >> $DEB_PACK/DEBIAN/control
	echo "Section: devel" >> $DEB_PACK/DEBIAN/control
    echo "Depends: make, autoconf, libtool" >> $DEB_PACK/DEBIAN/control
    DEB_DESC="Description: ${DEB_TARGET} C/C++ toolchain with composition"
    DEB_DESC+="\n .\n gcc $GCCv"
    DEB_DESC+="\n .\n glibc $GLIBCv"
    DEB_DESC+="\n .\n binutils $BINUTILSv"
    DEB_DESC+="\n .\n mpfr $MPFRv"
    DEB_DESC+="\n .\n gmp $GMPv"
    DEB_DESC+="\n .\n mpc $MPCv"
    DEB_DESC+="\n .\n isl $ISLv"
    DEB_DESC+="\n .\n cloog $CLOOGv"
    DEB_DESC+="\n .\n linux-kernel $KERNELv"
    echo -e $DEB_DESC >> $DEB_PACK/DEBIAN/control

    md5deep -l -o f -r $DEB_PACK/usr > $DEB_PACK/DEBIAN/md5sums
    fakeroot dpkg-deb --build $TOOL_DIR
    print_success "Toolchain was packed into the deb package $TOOL_DIR.deb"
    echo "deb" >> $RESULT_FILE
    apt-get remove --purge -y md5deep fakeroot
fi


apt-get remove --purge -y g++ autoconf libtool bison wget texinfo
apt-get autoremove -y
apt-get autoclean -y
apt-get clean -y
rm -rf /tmp/* && rm -rf /var/cache/*