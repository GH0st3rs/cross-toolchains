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
    SRC_ARC=$(echo $1|grep -o '[a-zA-Z0-9\.\-]\+\.tar\.[a-z0-9]\+'|head -n1)
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


export TARGET=arm-linux-uclibcgnueabi
export KERNEL_ARCH=arm
export GCC_PARAMS="--disable-nls --disable-libmudflap --disable-libssp --disable-libsanitizer"


trap 'err_report $LINENO' ERR
trap 'restore_output' EXIT


TOOLCHAIN_DIR=/opt/arm-linux
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
export TMP_BUILD_DIR=/tmp/arm


# Check kernel generation
if [[ $KERNELv > 3 ]] && [[ $KERNELv < 4 ]]; then export KERNEL_GEN=v3.x; fi
if [[ $KERNELv > 4 ]] && [[ $KERNELv < 5 ]]; then export KERNEL_GEN=v4.x; fi
if [[ $KERNELv > 2.6 ]] && [[ $KERNELv < 3 ]]; then export KERNEL_GEN=v2.6; fi
if [[ $KERNELv > 2.5 ]] && [[ $KERNELv < 2.6 ]]; then export KERNEL_GEN=v2.5; fi
if [[ $KERNELv > 2.4 ]] && [[ $KERNELv < 2.5 ]]; then export KERNEL_GEN=v2.4; fi
if [[ $KERNELv > 2.3 ]] && [[ $KERNELv < 2.4 ]]; then export KERNEL_GEN=v2.3; fi


print_info "Update apt-get"
apt-get update && apt-get -y upgrade && \
apt-get install -y g++ make gawk autoconf libtool bison wget texinfo git && \
apt-get -y autoremove


if [[ ! -d $TMP_BUILD_DIR ]]; then
    mkdir -p $TMP_BUILD_DIR
    cd $TMP_BUILD_DIR
else
    cd $TMP_BUILD_DIR
    print_info "Remove previous sources"
    ls|grep -v "\.tar\."| xargs rm -rf
fi


print_info "Download sources"
SOURCE_LINKS=(
    https://ftp.gnu.org/gnu/binutils/binutils-$BINUTILSv.tar.gz
    https://ftp.gnu.org/gnu/gcc/gcc-$GCCv/gcc-$GCCv.tar.gz
    https://www.kernel.org/pub/linux/kernel/$KERNEL_GEN/linux-$KERNELv.tar.gz
    https://ftp.gnu.org/gnu/mpfr/mpfr-$MPFRv.tar.bz2
    https://ftp.gnu.org/gnu/gmp/gmp-$GMPv.tar.bz2
    https://ftp.gnu.org/gnu/mpc/mpc-$MPCv.tar.gz
    ftp://gcc.gnu.org/pub/gcc/infrastructure/isl-$ISLv.tar.bz2
    ftp://gcc.gnu.org/pub/gcc/infrastructure/cloog-$CLOOGv.tar.gz
)
for i in ${SOURCE_LINKS[@]}; do download $i; done
git clone -b 0.9.32 git://git.busybox.net/uClibc


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
    CFLAGS="-s -static -O2" ../binutils-$BINUTILSv/configure \
        --prefix=$USR \
        --target=$TARGET \
        --disable-multilib \
        --disable-werror \
        --program-prefix=$TARGET- \
        --disable-doc
    make $PARALLEL_MAKE configure-host
    make LDFLAGS="-all-static" $PARALLEL_MAKE
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
    fi
    cd ..
    echo "headers" >> $RESULT_FILE
else
    print_success "Linux headers installed"
fi


if ! grep -Fxq "gcc_stage1" $RESULT_FILE; then
    print_info "Compile GCC without libc"
    mkdir gcc-$GCCv-build1 && cd gcc-$GCCv-build1
    CFLAGS="-s -static -O2" CXXFLAGS=$CFLAGS ../gcc-$GCCv/configure \
        --disable-shared \
        --prefix=$USR \
        --target=$TARGET \
        --enable-languages=c,c++ \
        --disable-multilib \
        --disable-threads \
        --libdir=$USR/lib \
        --libexecdir=$USR/lib \
        --includedir=$PREFIX/include \
        --enable-version-specific-runtime-libs \
        --with-gxx-include-dir=$PREFIX/c++/include \
        --disable-doc \
        $GCC_PARAMS
    sed -i 's|-g -O|-s -O|' Makefile
    make $PARALLEL_MAKE all-gcc
    make install-gcc
    cd ..
    echo "gcc_simple" >> $RESULT_FILE
else
    print_success "GCC without libc installed"
fi


if ! grep -Fxq "libgcc" $RESULT_FILE; then
    print_info "Compile GCC all-target-libgcc"
    cd gcc-$GCCv-build1
    make $PARALLEL_MAKE all-target-libgcc
    make install-target-libgcc
    cd ..
    echo "libgcc" >> $RESULT_FILE
else
    print_success "GCC all-target-libgcc installed"
fi


if ! grep -Fxq "uClibc" $RESULT_FILE; then
    print_info "Compile uClibc"
    cd uClibc
    cp /mnt/uClibc/.config ./
    ln -s $USR/lib/gcc/$TARGET/$GCCv/libgcc.a $USR/lib/gcc/$TARGET/$GCCv/libgcc_eh.a
    make CROSS_COMPILER_PREFIX=${USR}/bin/${TARGET}- \
        KERNEL_HEADERS=${PREFIX}/include \
        RUNTIME_PREFIX=${PREFIX}/ \
        DEVEL_PREFIX=${PREFIX}/ \
        PREFIX="" \
        install
    cd ..
    echo "uClibc" >> $RESULT_FILE
else
    print_success "GCC uClibc installed"
fi

exit

if ! grep -Fxq "libstdc++" $RESULT_FILE; then
    print_info "Compile libstdc++"
    mkdir gcc-$GCCv-build2 && cd gcc-$GCCv-build2
    CFLAGS="-s -static -O2 -L$USR/lib" CXXFLAGS=$CFLAGS ../gcc-$GCCv/configure \
        --disable-shared \
        --prefix=$USR \
        --target=$TARGET \
        --enable-languages=c,c++ \
        --disable-multilib \
        --disable-threads \
        --libdir=$USR/lib \
        --libexecdir=$USR/lib \
        --includedir=$PREFIX/include \
        --enable-version-specific-runtime-libs \
        --with-gxx-include-dir=$PREFIX/c++/include \
        --disable-doc \
        $GCC_PARAMS
    sed -i 's|-g -O|-s -O|' Makefile
    make $PARALLEL_MAKE all
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


print_info "Remove unneeded files"
apt-get autoremove -y --purge g++ autoconf libtool bison texinfo
apt-get autoclean -y
apt-get clean -y
rm -rf /tmp/* && rm -rf /var/cache/*
