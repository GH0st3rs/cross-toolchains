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


# Local Variables
MAKE_INSTALL=0
VERBOSE=0
CREATE_PACKAGE=0


# Set script params
trap 'err_report $LINENO $BASH_LINENO "$BASH_COMMAND" $(printf "::%s" ${FUNCNAME[@]:-})' ERR
trap 'restore_output' EXIT
trap 'previous_command=$this_command; this_command=$BASH_COMMAND' DEBUG

redirect_output() {
    if (( ! VERBOSE )); then
        # Save stdout and stderr
        exec 3>&1
        exec 4>&2
        # Set output log files
        exec 1>>$LOG_FILE
        exec 2>>$ERROR_FILE
    fi
}

restore_output() {
    if (( ! VERBOSE )); then
        # Restore original stdout
        exec 1>&3 3>&- # Восстановить stdout и закрыть дескр. #3
        exec 2>&4 4>&- # Восстановить stderr и закрыть дескр. #4
    fi
}

download() {
    SRC_ARC=$(echo $1|grep -oP '[a-zA-Z0-9\.\-\_]+\.tar\.[a-z0-9]+'|head -n1)
    print_info "Start download $SRC_ARC"
    if [ ! -f $SRC_ARC ]; then
        wget -q "$1" --no-check-certificate
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
    $TARGET-strip --strip-unneeded --strip-debug -x -R .comment -R .note.ABI-tag -R .note.gnu.build-id $1
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
    local line=$1 # LINENO
    local linecallfunc=$2
    local command="$3"
    local funcstack="$4"
    print_error "line $1 => '$previous_command'"
    if [ "$funcstack" != "::" ]; then
        echo -n "$(date) $(hostname) $0: DEBUG Error in ${funcstack} "
        if [ "$linecallfunc" != "" ]; then
            echo "called at line $linecallfunc"
        else
            echo
        fi
    fi
    print_info "See $ERROR_FILE for more info"
    exit 1
}

init_logs() {
    export LOGS_DIR=$(mktemp -d)
    if ((! VERBOSE)); then
        ERROR_FILE=${LOGS_DIR}/error.log
        LOG_FILE=${LOGS_DIR}/output.log
        # Clear logs
        rm -f $LOG_FILE $ERROR_FILE 2>/dev/null
    else
        ERROR_FILE=""
        LOG_FILE=""
    fi
    RESULT_FILE=${LOGS_DIR}/result.log
    redirect_output
}

upgrade_system() {
    print_info "Update apt-get"
    apt-get update && apt-get -y upgrade
    apt-get install -y make gawk wget pkg-config ccache
    apt-get -y autoremove
}

init() {
    init_logs
    upgrade_system
    TOOLCHAIN_DIR=/usr
    export TARGET_CC="ccache $TARGET-gcc $CFLAGS_FOR_TARGET"
    export TARGET_CXX="ccache $TARGET-g++ $CFLAGS_FOR_TARGET"
    export AR=$TARGET-ar
    export AS=$TARGET-as
    export RANLIB=$TARGET-ranlib
    export CFLAGS="${CFLAGS} -s -static -O2 "
    export LDFLAGS="${LDFLAGS} -s -static "

    export USR=$TOOLCHAIN_DIR
    export PREFIX=${PREFIX:=$USR/$TARGET}
    export PKG_CONFIG_LIBDIR=${PREFIX}/lib/pkgconfig
    export PKG_CONFIG_PATH=${PKG_CONFIG_LIBDIR}
    export PATH=$PATH:$PREFIX/bin:$USR/bin
    export PARALLEL_MAKE=-j3
    # if [[ $(uname -m) == x86_64 ]]; then
    #     export DEB_ARCH=amd64
    # else
    #     export DEB_ARCH=i386
    # fi
    export WORK_DIRECTORY=$(mktemp -d)
    export DEB_ARCH=all
    export DEBv=1.0
    export DEB_TARGET=$1 #$(echo $TARGET|tr '-' ' '|awk '{print $1}')
    if [[ -z $DEB_PACK ]]; then
        export DEB_PACK=$(pwd)/${DEB_TARGET}_tools_v${DEBv}_${DEB_ARCH}
    fi
    export TMP_BUILD_DIR=${WORK_DIRECTORY}/${DEB_TARGET}-cross
    if [[ -z ${TOOLS_BIN_DIR} ]]; then
        export TOOLS_BIN_DIR=$(mktemp -d)/BIN
    fi
    if [[ $1 == i686 ]]; then
        export BUILDTARGET="--build=$TARGET"
    else
        export BUILDTARGET=""
    fi
    export DEB_DESC="Description: Tools for $DEB_TARGET toolchain"
    export TOOLS_NAME="$DEB_TARGET"
    
    if [[ ! -d $TMP_BUILD_DIR ]]; then
        mkdir -p $TMP_BUILD_DIR
        cd $TMP_BUILD_DIR
    else
        cd $TMP_BUILD_DIR
        print_info "Remove previous sources"
        ls|grep -v "\.tar\."| xargs rm -rf
    fi
    # Check BIN dir
    if [[ ! -d ${TOOLS_BIN_DIR} ]]; then
        mkdir -p ${TOOLS_BIN_DIR}
    fi
    # if [[ -d $DEB_PACK ]]; then
    #     rm -rf $DEB_PACK
    # fi
    # if ((CREATE_PACKAGE)); then
    #     mkdir -p $DEB_PACK
    # fi
}

usage() {
    init_logs
    restore_output
cat << EOF
usage: args.py [-h] [-i] [-o DIR] [-d] [-v] -a ARCH [-l LIBS] [-t TOOLS]

optional arguments:
  -h, --help      Show this help message and exit
  -a ARCH         Target Architecture: ($(echo ${ARCHS[*]}|sed 's/ /, /g'))
  -t TOOLS        Compile selected tools:
                  $(echo ${TOOLS[*]}|sed 's/ /\n                  /g')
  -l LIBS         Compile selected libs:
                  $(echo ${LIBS[*]}|sed 's/ /\n                  /g')
  -i              Run "make install" for selected tools
  -o DIR          Binary output directory
  -d              Create DEB package
  -v              Verbose
EOF
    redirect_output
    exit 1
}

# Versions

export LIBPCAPv=1.8.1
export FLEXv=2.6.4
export E2FSv=1.43.4
export LMAGICv=5.31
export BEECRYPTv=4.1.2
export LDBv=6.2.23.NC
export TORv=0.3.4.9
export SSHv=7.4p1
export DROPBEARv=2017.75
export PYTHON2v=2.7.13
export RPMv=4.12.0
export E2TOOLSv=0.0.16
export EMPTYv=0.6.20b
# Links

export PCAP_LINK=http://www.tcpdump.org/release/libpcap-$LIBPCAPv.tar.gz
export FLEX_LINK=https://github.com/westes/flex/files/981163/flex-$FLEXv.tar.gz
export E2FSPROGS_LINK=https://www.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v$E2FSv/e2fsprogs-$E2FSv.tar.xz
export LMAGIC_LINK=ftp://ftp.astron.com/pub/file/file-$LMAGICv.tar.gz
export BEECRYPT_LINK=http://prdownloads.sourceforge.net/beecrypt/beecrypt-$BEECRYPTv.tar.gz
export LDB_LINK=http://download.oracle.com/berkeley-db/db-$LDBv.tar.gz
export TOR_LINK=https://www.torproject.org/dist/tor-$TORv.tar.gz
export SSH_LINK=http://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-$SSHv.tar.gz
export DROPBEAR_LINK=https://matt.ucc.asn.au/dropbear/releases/dropbear-$DROPBEARv.tar.bz2
export PYTHON2_LINK=https://www.python.org/ftp/python/$PYTHON2v/Python-$PYTHON2v.tar.xz
export RPM_LINK=http://ftp.rpm.org/releases/rpm-4.12.x/rpm-$RPMv.tar.bz2
export E2TOOLS_LINK=http://home.earthlink.net/~k_sheff/sw/e2tools/e2tools-$E2TOOLSv.tar.gz
export EMPTY_LINK=https://downloads.sourceforge.net/project/empty/empty/empty-$EMPTYv/empty-$EMPTYv.tgz


ARCHS=(armel armbe mipsel mips i686 powerpc)
TOOLS=(wget tor ssh dropbear python2 python3 rpm e2tools empty joe gdb)
LIBS=(zlib openssl libtasn1 libevent libpcap flex libmagic e2fsprogs libdb curl libunistring libassuan libgpg-error libgnutls)
# redirect_output


#####################################################################################################
#                                               LIBS
#####################################################################################################


is_lib_installed() {
    echo "void main(){}" > test.c
    $TARGET_CC test.c $1 -static 2>/dev/null
    if [[ $? == 0 ]]; then
        return 1
    else
        return 0
    fi
}


check_lib() {
    is_lib_installed "$2"
    if [[ $? == 1 ]]
    then
        print_success "$1 Installed"
        rm a.out test.c >/dev/null
    else
        print_error "compile $1"
        exit 1
    fi
}


resolve_deps() {
    local depends="$@"
    print_info "(${depends[@]})"
    for dep in ${depends[@]}; do
        case "$dep" in 
            bzip2             ) lib_name="-lbz2" ;;
            libgpg-error|curl ) lib_name="-l$(echo ${dep}|sed 's|lib||')" ;;
            gnupg             ) if [[ -e $PREFIX/bin/gpg ]]; then continue; fi ;;
            ca-certificates   ) ;;
            *                 ) lib_name="$(pkg-config --libs --static ${dep} 2>/dev/null)"; if [[ $? == 1 ]]; then lib_name="-l$(echo ${dep}|sed 's|lib||')"; fi ;;
        esac
        is_lib_installed "${lib_name}"
        if [[ $? == 0 ]]; then
            ${dep}_build
        fi
    done
}


zlib_build() {
    local pkgname=zlib
    local pkgver=1.2.11
    local pkgdesc="Compression library implementing the deflate compression method found in gzip and PKZIP"
    local source=https://zlib.net/${pkgname}-${pkgver}.tar.gz
    download ${source}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    cd ${pkgname}-${pkgver}
    CC="$TARGET_CC" ./configure \
        --prefix=${PREFIX} \
        --static
    make $PARALLEL_MAKE
    if ((CREATE_PACKAGE)); then
        make DESTDIR=${DEB_PACK} install
    fi
    if ((MAKE_INSTALL)); then
        make install
    fi
    cd ..

    # Test zlib
    check_lib "zLib" "$(pkg-config --libs --static zlib)"
    DEB_DESC+="\n .\n zlib-$ZLIBv"
    TOOLS_NAME+="-zlib"
}


openssl_build() {
    apt-get install -y libfile-dircompare-perl
    local pkgname=openssl
    local pkgver=1.1.1
    local pkgdesc="The Open Source toolkit for Secure Sockets Layer and Transport Layer Security"
    local source=https://www.openssl.org/source/${pkgname}-${pkgver}.tar.gz
    download ${source}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    # prepare
    cd ${pkgname}-${pkgver}
    # Patch ssl dir to /etc/ssl
    sed -i "s|./demoCA|$(realpath ${PREFIX}/../etc/ssl)|g" ./apps/*.{cnf,in}
    # build
    if [[ ${PREFIX_TARCH} == i686 ]]; then
        local EXTRA_FLAGS="-m32"
    elif [[ ${PREFIX_TARCH} == powerpc ]]; then
        local EXTRA_FLAGS=""
    else
        local EXTRA_FLAGS="-march=${SSL_MARCH} -lpthread"
    fi
    CC="$TARGET_CC" CXX="$TARGET_CXX" ./Configure \
        $SSL_ARCH \
        --prefix=${PREFIX} \
        --openssldir="$(realpath ${PREFIX}/../etc/ssl)" \
        no-shared \
        no-fuzz-afl \
        no-fuzz-libfuzzer \
        -fPIC -I${PREFIX}/include -L${PREFIX}/lib \
        ${LDFLAGS} ${CFLAGS} \
        ${EXTRA_FLAGS}
    make $PARALLEL_MAKE
    strip_debug apps/openssl
    # package
    if ((MAKE_INSTALL)); then
        make install
    fi
    if ((CREATE_PACKAGE)); then
        # Create DEB
        CC="$TARGET_CC" CXX="$TARGET_CXX" ./Configure \
            $SSL_ARCH \
            --prefix=${DEB_PACK}/${PREFIX} \
            --openssldir="$(realpath ${DEB_PACK}/${PREFIX}/../etc/ssl)" \
            no-shared \
            no-fuzz-afl \
            no-fuzz-libfuzzer \
            -fPIC -I${PREFIX}/include -L${PREFIX}/lib \
            ${LDFLAGS} ${CFLAGS} \
            ${EXTRA_FLAGS}
        make $PARALLEL_MAKE
        make install
    fi
    cd ..

    # Test openssl
    check_lib "OpenSSL" "-lssl -lcrypto"
    DEB_DESC+="\n .\n openssl-$OPENSSLv"
    TOOLS_NAME+="-openssl"
}


libevent_build() {
    local pkgname=libevent
    local pkgver=2.1.8-stable
    local pkgdesc="An event notification library"
    local source=https://github.com/${pkgname}/${pkgname}/releases/download/release-${pkgver}/${pkgname}-${pkgver}.tar.gz
    local depends=('openssl')
    download ${source}
    print_info "Resolve dependies for ${pkgname}"
    resolve_deps ${depends[@]}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    mkdir ${pkgname}-${pkgver}-build && cd ${pkgname}-${pkgver}-build
    CFLAGS="${CFLAGS} -ldl" CC="$TARGET_CC" ../${pkgname}-${pkgver}/configure \
        --host=$TARGET \
        --with-pic \
        --prefix=$PREFIX \
        --enable-static \
        $BUILDTARGET
    make $PARALLEL_MAKE
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install
    fi
    if ((MAKE_INSTALL)); then
        make install
    fi
    cd ..

    check_lib "LibEvent" "-levent"
    DEB_DESC+="\n .\n libevent-$LIBEVENTv"
    TOOLS_NAME+="-libevent"
}


libtasn1_build() {
    local pkgname=libtasn1
    local pkgver=4.12
    local pkgdesc="The ASN.1 library used in GNUTLS"
    local source=http://ftp.gnu.org/gnu/${pkgname}/${pkgname}-${pkgver}.tar.gz
    download ${source}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    # build
    mkdir ${pkgname}-${pkgver}-build && cd ${pkgname}-${pkgver}-build
    CC="$TARGET_CC" ../${pkgname}-${pkgver}/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --disable-doc \
        --enable-static \
        $BUILDTARGET
    make $PARALLEL_MAKE
    # package
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install-strip
    fi
    if ((MAKE_INSTALL)); then
        make install-strip
    fi
    cd ..

    check_lib "LibTasn1" "-ltasn1"
    DEB_DESC+="\n .\n libtasn1-$LIBTASN1v"
    TOOLS_NAME+="-libtasn1"
}


flex_build() {
    download $FLEX_LINK
    print_info "Compile ${pkgname} - ${pkgdesc}"
    mkdir flex-$FLEXv-build && cd flex-$FLEXv-build
    if [[ $(uname -m) == x86_64 ]]; then
        apt-get -y install gcc-multilib
        LDFLAGS="${LDFLAGS} -static -s" CFLAGS="${CFLAGS} -static -O2 -s" CXXFLAGS=$CFLAGS CC="$TARGET_CC" ../flex-$FLEXv/configure --prefix=$PREFIX --enable-static --host=$TARGET $BUILDTARGET CFLAGS_FOR_BUILD="-s -O2 -m32"
    else
        LDFLAGS="${LDFLAGS} -static -s" CFLAGS="${CFLAGS} -static -O2 -s" CXXFLAGS=$CFLAGS CC="$TARGET_CC" ../flex-$FLEXv/configure --prefix=$PREFIX --enable-static --host=$TARGET $BUILDTARGET
    fi
    make $PARALLEL_MAKE
    # make install-strip
    make DESTDIR=$DEB_PACK install-strip
    if [[ $1 != i686 ]] || [[ $1 != i686 ]]; then
        rm -rf $PREFIX/bin/flex*
        if [[ $(uname -m) == x86_64 ]]; then
            LDFLAGS="${LDFLAGS} -static -s" CFLAGS="${CFLAGS} -static -O2 -s" CXXFLAGS=$CFLAGS CC=gcc ../flex-$FLEXv/configure --prefix=$PREFIX --enable-static --disable-libfl CFLAGS_FOR_BUILD="-s -O2 -m32"
        else
            LDFLAGS="${LDFLAGS} -static -s" CFLAGS="${CFLAGS} -static -O2 -s" CXXFLAGS=$CFLAGS CC=gcc ../flex-$FLEXv/configure --prefix=$PREFIX --enable-static --disable-libfl
        fi
        make $PARALLEL_MAKE
        make install-strip
    fi
    cd ..

    # Test libfl
    # echo "void main(){}" > test.c
    # $TARGET_CC test.c -static -lfl
    check_lib "flex" "-lfl"
    DEB_DESC+="\n .\n flex-$FLEXv"
    TOOLS_NAME+="-flex"
}


libpcap_build() {
    if [[ ! -x flex ]]; then
        flex_build $(echo $TARGET|tr "-" " "|awk '{print $1}')
    fi
    download $PCAP_LINK
    print_info "Compile ${pkgname} - ${pkgdesc}"
    mkdir libpcap-$LIBPCAPv-build && cd libpcap-$LIBPCAPv-build
    LDFLAGS="${LDFLAGS} -static -s" CFLAGS="${CFLAGS} -static -O2 -s" CC="$TARGET_CC" ../libpcap-$LIBPCAPv/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --with-pcap=linux \
        --disable-shared \
        $BUILDTARGET
    make $PARALLEL_MAKE
    make install
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install
    fi
    cd ..

    # Test libpcap
    # echo "void main(){}" > test.c
    # $TARGET_CC test.c -lpcap -static
    check_lib "LibPCAP" "-lpcap"
    DEB_DESC+="\n .\n libpcap-$LIBPCAPv"
    TOOLS_NAME+="-libpcap"
}

# Not tested for deb
libarchive_build() {
    local pkgname=libarchive
    local pkgver=3.3.2
    local pkgdesc="Multi-format archive and compression library"
    local source=https://www.libarchive.org/downloads/${pkgname}-${pkgver}.tar.gz
    local depends=('zlib' 'attr')
    download ${source}
    print_info "Resolve dependies for ${pkgname}"
    resolve_deps ${depends[@]}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    # build
    mkdir ${pkgname}-${pkgver}-build && cd ${pkgname}-${pkgver}-build
    CC="$TARGET_CC" ../${pkgname}-${pkgver}/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --enable-static \
        --without-xml2 \
        --without-lzma \
        --without-openssl \
        --with-zlib \
        $BUILDTARGET
    make $PARALLEL_MAKE
    # package
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install-strip
    fi
    if ((MAKE_INSTALL)); then
        make install-strip
    fi
    cd ..

    check_lib "libArchive" "-larchive"
    DEB_DESC+="\n .\n libarchive-$LIBARCHIVEv"
    TOOLS_NAME+="-libarchive"
}


e2fsprogs_build() {
    download $E2FSPROGS_LINK
    print_info "Compile ${pkgname} - ${pkgdesc}"
    mkdir e2fsprogs-$E2FSv-build && cd e2fsprogs-$E2FSv-build
    LDFLAGS="${LDFLAGS} -static -s" CFLAGS="${CFLAGS} -s -static -O2" CC="$TARGET_CC" ../e2fsprogs-$E2FSv/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --disable-threads \
        --disable-tls \
        --disable-uuidd \
        --disable-nls \
        --disable-defrag \
        --disable-debugfs \
        --disable-testio-debug \
        --disable-fsck \
        $BUILDTARGET
    make $PARALLEL_MAKE
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install-libs
    fi
    if ((MAKE_INSTALL)); then
        make install-strip
    fi
    cd ..

    # Test e2fsprogs
    echo "void main(){}" > test.c
    $TARGET_CC test.c -static -lcom_err -lblkid -luuid -lss -lext2fs
    check_lib "e2fsprogs"
    DEB_DESC+="\n .\n e2fsprogs-$E2FSv"
    TOOLS_NAME+="-e2fsprogs"
}


magic_build() {
    download $LMAGIC_LINK
    print_info "Compile ${pkgname} - ${pkgdesc}"
    mkdir file-$LMAGICv-build && cd file-$LMAGICv-build
    LDFLAGS="${LDFLAGS} -static -s" CFLAGS="${CFLAGS} -s -w -static -O2" CC="$TARGET_CC" ../file-$LMAGICv/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --enable-static \
        --includedir=$PREFIX/include \
        --libdir=$PREFIX/lib \
        $BUILDTARGET
    make $PARALLEL_MAKE
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install-strip
    fi
    if ((MAKE_INSTALL)); then
        make install-strip
    fi
    cd ..

    # Test libmagic
    echo "void main(){}" > test.c
    $TARGET_CC test.c -static -lmagic -lz
    check_lib "libmagic"
    DEB_DESC+="\n .\n file-$LMAGICv"
    TOOLS_NAME+="-file"
}


popt_build() {
    local pkgname=popt
    local pkgver=1.16
    local pkgdesc="A commandline option parser"
    local source="https://deb.debian.org/debian/pool/main/p/${pkgname}/${pkgname}_${pkgver}.orig.tar.gz"
    download ${source}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    mkdir ${pkgname}-${pkgver}-build && cd ${pkgname}-${pkgver}-build
    CC="$TARGET_CC" ../${pkgname}-${pkgver}/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --enable-static \
        --disable-nls \
        $BUILDTARGET
    make $PARALLEL_MAKE
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install
    fi
    if ((MAKE_INSTALL)); then
        make install
    fi
    cd ..

    # Test libpopt
    # echo "void main(){}" > test.c
    # $TARGET_CC test.c -static -lpopt
    check_lib "libpopt" "-lpopt"
    DEB_DESC+="\n .\n popt-$POPTv"
    TOOLS_NAME+="-popt"
}


beecrypt_build() {
    download $BEECRYPT_LINK
    print_info "Compile ${pkgname} - ${pkgdesc}"
    mkdir beecrypt-$BEECRYPTv-build && cd beecrypt-$BEECRYPTv-build
    LDFLAGS="${LDFLAGS} -static -s" CFLAGS="${CFLAGS} -s -static -O2" CC="$TARGET_CC" ../beecrypt-$BEECRYPTv/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --enable-static \
        --enable-openmp \
        --disable-debug \
        --without-java \
        $BUILDTARGET
    make $PARALLEL_MAKE
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install-strip
    fi
    if ((MAKE_INSTALL)); then
        make install-strip
    fi
    cd ..

    # Test libbeecrypt
    echo "char mpfprintln (); int main (){ return mpfprintln (); return 0; }" > test.c
    $TARGET_CC test.c -lbeecrypt
    check_lib "beecrypt"
    DEB_DESC+="\n .\n beecrypt-$BEECRYPTv"
    TOOLS_NAME+="-beecrypt"
}


db_build() {
    download $LDB_LINK
    print_info "Compile ${pkgname} - ${pkgdesc}"
    mkdir db-$LDBv-build && cd db-$LDBv-build
    LDFLAGS="${LDFLAGS} -static -s" CFLAGS="${CFLAGS} -s -static -O2" CC="$TARGET_CC" ../db-$LDBv/dist/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --disable-java \
        --enable-static \
        $BUILDTARGET
    make $PARALLEL_MAKE
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install_lib install_include
    fi
    make install_lib install_include
    cd ..

    # Test libdb
    echo "void main(){}" > test.c
    $TARGET_CC test.c -static -ldb
    check_lib "libdb"
    DEB_DESC+="\n .\n db-$LDBv"
    TOOLS_NAME+="-db"
}


ca-certificates_build() {
    apt install -y p11-kit
    local pkgbase=ca-certificates
    local pkgname=ca-certificates-utils
    local pkgver=20181109
    local pkgdesc="Common CA certificates"
    local source=https://git.archlinux.org/svntogit/packages.git/plain/trunk/update-ca-trust?h=packages/ca-certificates
    print_info "Compile ${pkgname} - ${pkgdesc}"
    # build
    pushd $(mktemp -d)
    wget ${source} --no-check-certificate -O update-ca-trust
    sed -ir "s|/etc|$(realpath ${PREFIX}/../etc)|" update-ca-trust
    # package
    install -D update-ca-trust "${PREFIX}/bin/update-ca-trust"
    # Trust source directories
    install -d ${PREFIX}/../{etc,usr/share}/${pkgbase}/trust-source/{anchors,blacklist}
    # Directories used by update-ca-trust (aka "trust extract-compat")
    install -d ${PREFIX}/../etc/${pkgbase}/extracted
    # Compatibility link for OpenSSL using /etc/ssl as CAdir
    # Used in preference to the individual links in /etc/ssl/certs
    ln -sr "${PREFIX}/../etc/${pkgbase}/extracted/tls-ca-bundle.pem" "${PREFIX}/../etc/ssl/cert.pem"
    # Compatiblity link for legacy bundle
    ln -sr "${PREFIX}/../etc/${pkgbase}/extracted/tls-ca-bundle.pem" "${PREFIX}/../etc/ssl/certs/ca-certificates.crt"
    ${PREFIX}/bin/update-ca-trust
    popd
}


curl_build() {
    local pkgname=curl
    local pkgver=7.53.1
    local pkgdesc="An URL retrieval utility and library"
    local source=https://curl.haxx.se/download/${pkgname}-${pkgver}.tar.gz
    local depends=('zlib' 'openssl' 'ca-certificates')
    download ${source}
    print_info "Resolve dependies for ${pkgname}"
    resolve_deps ${depends[@]}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    # build
    mkdir ${pkgname}-${pkgver}-build && cd ${pkgname}-${pkgver}-build
    LIBS="-ldl -lpthread" CPPFLAGS="-DCURL_STATICLIB" CC=$TARGET_CC ../${pkgname}-${pkgver}/configure \
        --host=$TARGET \
        --target=$TARGET \
        --prefix=$PREFIX \
        --disable-ipv6 \
        --disable-ldap \
        --disable-ldaps \
        --disable-rtsp \
        --disable-dict \
        --disable-telnet \
        --disable-tftp \
        --disable-pop3 \
        --disable-imap \
        --disable-smb \
        --disable-smtp \
        --disable-gopher \
        --disable-crypto-auth \
        --disable-sspi \
        --disable-shared \
        --disable-debug \
        --disable-curldebug \
        --disable-manual \
        --enable-rt \
        --enable-ftp \
        --enable-http \
        --enable-cookies \
        --enable-optimize \
        --enable-static \
        --without-axtls \
        --with-proxy \
        --with-zlib \
        --with-ssl="$(realpath -s $PREFIX/../etc/ssl)" \
        --with-ca-bundle="$(realpath -s $PREFIX/../etc/ssl/certs/ca-certificates.crt)" \
        --with-random=/dev/urandom
    make $PARALLEL_MAKE
    # package
    strip_debug src/curl
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install-strip
    fi
    if ((MAKE_INSTALL)); then
        make install-strip
    fi
    cd ..

    check_lib "libCURL" "-lcurl"
    DEB_DESC+="\n .\n curl-$CURLv"
    TOOLS_NAME+="-curl"
}


libunistring_build() {
    apt install -y xz-utils lzma
    local pkgname=libunistring
    local pkgver=0.9.10
    local pkgdesc="Library for manipulating Unicode strings and C strings"
    local source=https://ftp.gnu.org/gnu/$pkgname/${pkgname}-${pkgver}.tar.xz
    download ${source}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    # prepare
    mkdir ${pkgname}-${pkgver}-build && cd ${pkgname}-${pkgver}-build
    # https://git.savannah.gnu.org/cgit/gnulib.git/commit/?id=cca32830b5
    sed -i '/pragma weak pthread_create/d' tests/glthread/thread.h
    # build
    CC="$TARGET_CC" ../${pkgname}-${pkgver}/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --enable-static
    make $PARALLEL_MAKE
    # package
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install
    fi
    if ((MAKE_INSTALL)); then
        make install
    fi
    cd ..

    check_lib "libunistring" "-lunistring"
}


libgpg-error_build() {
    apt install -y autoconf automake autopoint libtool
    local pkgname=libgpg-error
    local pkgver=1.37
    local pkgdesc="Support library for libgcrypt"
    local source=ftp://ftp.gnupg.org/gcrypt/libgpg-error/${pkgname}-${pkgver}.tar.bz2
    download ${source}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    # prepare
    cd ${pkgname}-${pkgver}
    autoreconf -vfi
    # build
    CC="$TARGET_CC" ./configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --disable-doc \
        --enable-static
    make $PARALLEL_MAKE
    # package
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install-strip
    fi
    if ((MAKE_INSTALL)); then
        make install-strip
    fi
    cd ..

    check_lib "libgpg-error" "$(${PREFIX}/bin/gpg-error-config --libs)"
}


libassuan_build() {
    local pkgname=libassuan
    local pkgver=2.5.3
    local pkgdesc="IPC library used by some GnuPG related software"
    local source="https://gnupg.org/ftp/gcrypt/${pkgname}/${pkgname}-${pkgver}.tar.bz2"
    local depends=('libgpg-error')
    download ${source}
    print_info "Resolve dependies for ${pkgname}"
    resolve_deps ${depends[@]}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    # build
    mkdir ${pkgname}-${pkgver}-build && cd ${pkgname}-${pkgver}-build
    CC="$TARGET_CC" ../${pkgname}-${pkgver}/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --disable-doc \
        --enable-static
    make $PARALLEL_MAKE
    # package
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install-strip
    fi
    if ((MAKE_INSTALL)); then
        make install-strip
    fi
    cd ..

    check_lib "libassuan" "$(${PREFIX}/bin/libassuan-config --libs)"
}


gmp_build() {
    apt install -y lzip m4 gcc
    local pkgname=gmp
    local pkgver=6.1.2
    local pkgdesc="A free library for arbitrary precision arithmetic"
    local source=https://gmplib.org/download/${pkgname}/${pkgname}-${pkgver}.tar.lz
    download ${source}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    # build
    mkdir ${pkgname}-${pkgver}-build && cd ${pkgname}-${pkgver}-build
    CC="$TARGET_CC" ../${pkgname}-${pkgver}/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --enable-cxx \
        --enable-fat \
        --build=${MACHTYPE} \
        --enable-static
    make $PARALLEL_MAKE
    # package
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install-strip
    fi
    if ((MAKE_INSTALL)); then
        make install-strip
    fi
    cd ..

    check_lib "GMP" "-lgmp"
}


nettle_build() {
    apt install -y gcc
    local pkgname=nettle
    local pkgver=3.5.1
    local pkgdesc="A low-level cryptographic library"
    local source=https://ftp.gnu.org/gnu/$pkgname/$pkgname-$pkgver.tar.gz
    local depends=('gmp')
    download ${source}
    print_info "Resolve dependies for ${pkgname}"
    resolve_deps ${depends[@]}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    # build
    mkdir ${pkgname}-${pkgver}-build && cd ${pkgname}-${pkgver}-build
    CC="$TARGET_CC" ../${pkgname}-${pkgver}/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --enable-mini-gmp \
        --enable-static \
        --disable-shared
    make $PARALLEL_MAKE
    # package
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install
    fi
    if ((MAKE_INSTALL)); then
        make install
    fi
    cd ..

    check_lib "libnettle" "$(pkg-config --libs --static hogweed)"
}


gnutls_build() {
    apt install -y pkg-config
    local pkgname=gnutls
    local pkgver=3.6.13
    local pkgdesc="A library which provides a secure layer over a reliable transport layer"
    local source=https://www.gnupg.org/ftp/gcrypt/gnutls/v3.6/${pkgname}-${pkgver}.tar.xz
    local depends=('libtasn1' 'zlib' 'nettle' 'libunistring' 'libassuan')
    download ${source}
    print_info "Resolve dependies for ${pkgname}"
    resolve_deps ${depends[@]}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    # build
    mkdir ${pkgname}-${pkgver}-build && cd ${pkgname}-${pkgver}-build
    CC="$TARGET_CC" CXX="$TARGET_CXX" ../${pkgname}-${pkgver}/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --without-p11-kit \
        --disable-doc \
        --enable-static \
        --disable-shared
    make
    # package
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install-strip
    fi
    if ((MAKE_INSTALL)); then
        make install-strip
    fi
    cd ..

    check_lib "GnuTLS" "-lgnutls -lgmp -lnettle -lunistring -ltasn1 -lhogweed"
}


npth_build() {
    local pkgname=npth
    local pkgver=1.6
    local pkgdesc="New portable threads library"
    local source=ftp://ftp.gnupg.org/gcrypt/${pkgname}/${pkgname}-${pkgver}.tar.bz2
    download ${source}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    # build
    mkdir ${pkgname}-${pkgver}-build && cd ${pkgname}-${pkgver}-build
    CC="$TARGET_CC" ../${pkgname}-${pkgver}/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --enable-maintainer-mode \
        --enable-static \
        --enable-shared
    make $PARALLEL_MAKE
    # package
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install-strip
    fi
    if ((MAKE_INSTALL)); then
        make install-strip
    fi
    cd ..

    check_lib "NPTH" "-lnpth"
}


libksba_build() {
    apt install -y gcc
    local pkgname=libksba
    local pkgver=1.3.5
    local pkgdesc="A CMS and X.509 access library"
    local source=https://www.gnupg.org/ftp/gcrypt/$pkgname/$pkgname-$pkgver.tar.bz2
    local depends=('libgpg-error')
    download ${source}
    print_info "Resolve dependies for ${pkgname}"
    resolve_deps ${depends[@]}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    # build
    mkdir ${pkgname}-${pkgver}-build && cd ${pkgname}-${pkgver}-build
    CC="$TARGET_CC" ../${pkgname}-${pkgver}/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --enable-static
    make $PARALLEL_MAKE
    # package
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install-strip
    fi
    if ((MAKE_INSTALL)); then
        make install-strip
    fi
    cd ..

    check_lib "libksba" "-lksba"
}


libgcrypt_build() {
    apt install -y git gcc
    local pkgname=libgcrypt
    local pkgver=1.8.5
    local pkgdesc="General purpose cryptographic library based on the code from GnuPG"
    local source=https://gnupg.org/ftp/gcrypt/${pkgname}/${pkgname}-${pkgver}.tar.bz2
    local depends=('libgpg-error')
    download ${source}
    print_info "Resolve dependies for ${pkgname}"
    resolve_deps ${depends[@]}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    # prepare
    cd ${pkgname}-${pkgver}
    # tests fail due to systemd+libseccomp preventing memory syscalls when building in chroots
    # https://git.archlinux.org/svntogit/packages.git/tree/trunk/PKGBUILD?h=packages/libgcrypt
    sed -i "s:t-secmem::" tests/Makefile.am
    sed -i "s:t-sexp::" tests/Makefile.am
    autoreconf -vfi
    # build
    LDFLAGS="${LDFLAGS} -Wl,-static" CC="$TARGET_CC" ../${pkgname}-${pkgver}/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --disable-doc \
        --disable-padlock-support \
        --enable-static \
        --with-libgpg-error-prefix=$PREFIX
    make $PARALLEL_MAKE
    # package
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install-strip
    fi
    if ((MAKE_INSTALL)); then
        make install-strip
    fi
    cd ..

    check_lib "libgcrypt" "$(${PREFIX}/bin/libgcrypt-config --libs)"
}


gnupg_build() {
    apt install -y gcc
    local pkgname=gnupg
    local pkgver=2.2.20
    local pkgdesc="Complete and free implementation of the OpenPGP standard"
    local source=https://gnupg.org/ftp/gcrypt/${pkgname}/${pkgname}-${pkgver}.tar.bz2
    local depends=('bzip2' 'npth' 'libgcrypt' 'libksba' 'libassuan' 'gnutls')
    download ${source}
    print_info "Resolve dependies for ${pkgname}"
    resolve_deps ${depends[@]}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    cd ${pkgname}-${pkgver}
    # prepare
    sed '/noinst_SCRIPTS = gpg-zip/c sbin_SCRIPTS += gpg-zip' -i tools/Makefile.in
    wget "https://git.archlinux.org/svntogit/packages.git/plain/trunk/self-sigs-only.patch?h=packages/gnupg&id=9e5bbc8579a58fb0bb28a3377b0d558835c0adb8" -O self-sigs-only.patch
    patch -R -p1 -i self-sigs-only.patch
    # build
    LIBGNUTLS_LIBS=$(pkg-config --libs --static gnutls) CC="$TARGET_CC" ./configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --disable-doc \
        --enable-symcryptrun \
        --enable-maintainer-mode \
        --sysconfdir="$(realpath $PREFIX/../etc)" \
        --sbindir=$PREFIX/bin \
        --libexecdir=$PREFIX/lib/gnupg \
        --disable-all-tests
    make
    # package
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install-strip
    fi
    if ((MAKE_INSTALL)); then
        make install-strip
    fi
    cd ..
}


gpgme_build() {
    apt install -y gcc
    local pkgbase=gpgme
    local pkgver=1.13.1
    local pkgdesc="A C wrapper library for GnuPG"
    local source=https://www.gnupg.org/ftp/gcrypt/${pkgbase}/${pkgbase}-${pkgver}.tar.bz2
    local depends=('gnupg' 'libgpg-error')
    download ${source}
    print_info "Resolve dependies for ${pkgbase}"
    resolve_deps ${depends[@]}
    print_info "Compile ${pkgbase} - ${pkgdesc}"
    # prepare
    mkdir ${pkgbase}-${pkgver}-build && cd ${pkgbase}-${pkgver}-build
    # Because need libassaun
    sed -ri 's|(gpgme_json_LDADD = -lm libgpgme.la \$\()GPG_ERROR_LIBS\)|\1LIBASSUAN_LIBS\)|' ../${pkgbase}-${pkgver}/src/Makefile.*
    sed -ri 's|(LIBS = @LIBS@)|\1 @LIBASSUAN_LIBS@|' ../${pkgbase}-${pkgver}/tests/Makefile.*
    sed -ri 's|^(LIBS = )$|\1\$\(LIBASSUAN_LIBS\)|' ../${pkgbase}-${pkgver}/lang/cpp/tests/Makefile*
    # build
    CC="$TARGET_CC" CXX="$TARGET_CXX" ../${pkgbase}-${pkgver}/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --enable-static \
        --disable-gpgsm-test \
        --disable-fd-passing \
        --with-libassuan-prefix=$PREFIX
    make $PARALLEL_MAKE
    # package
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install-strip
    fi
    if ((MAKE_INSTALL)); then
        make install-strip
    fi
    cd ..
}


attr_build() {
    local pkgname=attr
    local pkgver=2.4.48
    local pkgdesc="Extended attribute support library for ACL support"
    local source=https://download.savannah.gnu.org/releases/${pkgname}/${pkgname}-${pkgver}.tar.gz
    download ${source}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    # build
    mkdir ${pkgname}-${pkgver}-build && cd ${pkgname}-${pkgver}-build
    LDFLAGS="${LDFLAGS} -Wl,-static" CC="$TARGET_CC" ../${pkgname}-${pkgver}/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --libdir=$PREFIX/lib \
        --libexecdir=$PREFIX/lib \
        --enable-static \
        --sysconfdir="$(realpath $PREFIX/../etc)"
    make $PARALLEL_MAKE
    # package
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install-strip
    fi
    if ((MAKE_INSTALL)); then
        make install-strip
    fi
    cd ..

    check_lib "attr" "-lattr"
}


libsecret_build() {
    apt install -y gettext gtk-doc-tools
    local pkgname=libsecret
    local pkgver=0.20.3
    local _commit=fb456a3853a080996f044496b11f3001af4a2659
    local source=https://gitlab.gnome.org/GNOME/libsecret/-/archive/${_commit}/libsecret-${_commit}.tar.gz
    local depends=(libgcrypt)
    download ${source}
    print_info "Resolve dependies for ${pkgname}"
    resolve_deps ${depends[@]}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    # build
    cd ${pkgname}-${_commit}
    CC="$TARGET_CC" ../${pkgname}-${_commit}/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --libdir=$PREFIX/lib \
        --libexecdir=$PREFIX/lib \
        --enable-static \
        --sysconfdir="$(realpath $PREFIX/../etc)"
    make $PARALLEL_MAKE
    # package
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install-strip
    fi
    if ((MAKE_INSTALL)); then
        make install-strip
    fi
    cd ..

    check_lib "attr" "-lattr"
}

#####################################################################################################
#                                               SOFT
#####################################################################################################


pacman_build() {
    local pkgname=pacman
    local pkgver=5.2.1
    local pkgdesc="A library-based package manager with dependency support"
    local source=https://sources.archlinux.org/other/$pkgname/$pkgname-$pkgver.tar.gz
    local source_deps=(
        "https://git.archlinux.org/svntogit/packages.git/plain/trunk/makepkg-fix-one-more-file-seccomp-issue.patch?h=packages/pacman"
        "https://git.archlinux.org/svntogit/packages.git/plain/trunk/pacman-5.2.1-fix-pactest-package-tar-format.patch?h=packages/pacman"
        "https://git.archlinux.org/svntogit/packages.git/plain/trunk/pacman.conf?h=packages/pacman"
        "https://git.archlinux.org/svntogit/packages.git/plain/trunk/makepkg.conf?h=packages/pacman"
    )
    local depends=('libarchive' 'curl' 'gpgme')
    download ${source}
    print_info "Resolve dependies for ${pkgname}"
    resolve_deps ${depends[@]}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    # prepare
    cd ${pkgname}-${pkgver}
    for src in ${source_deps[@]}; do
        wget $src -O $(echo $src|sed -r 's|.*trunk/([^?]+).*|\1|') --no-check-certificate
    done
    patch -Np1 < pacman-5.2.1-fix-pactest-package-tar-format.patch
    patch -Np1 < makepkg-fix-one-more-file-seccomp-issue.patch
    sed -ri 's|(<string.h>)|\1\n#include <bits/posix2_lim.h>|' ./*/*/util.h
    # build
    PKG_CONFIG="/usr/bin/pkg-config --static" LDFLAGS="${LDFLAGS} -Wl,-static" BASH_SHELL=/bin/bash CC="$TARGET_CC" ./configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --with-gpgme \
        --with-libcurl \
        --disable-doc \
        --enable-static \
        --localstatedir="$(realpath ${PREFIX}/../var)" \
        --sysconfdir="$(realpath ${PREFIX}/../etc)" \
        --libdir=$PREFIX/lib \
        --disable-shared
    make $PARALLEL_MAKE
    # package
    if ((MAKE_INSTALL)); then
        make install-strip
    fi
    cd ..
}


bzip2_build() {
    local pkgname=bzip2
    local pkgver=1.0.8
    local pkgdesc="A high-quality data compression program"
    local source=https://sourceware.org/pub/bzip2/$pkgname-$pkgver.tar.gz
    download ${source}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    # build
    cd ${pkgname}-${pkgver}
    make libbz2.a bzip2 bzip2recover CC="$TARGET_CC" AR="${AR}" RANLIB="${RANLIB}" CFLAGS="${CFLAGS}" LDFLAGS="${LDFLAGS}"
    # make -f Makefile-libbz2_so CC="$TARGET_CC" 
    # package
    if ((CREATE_PACKAGE)); then
        make PREFIX="${DEB_PACK}/${PREFIX}" install
    fi
    if ((MAKE_INSTALL)); then
        make PREFIX="${PREFIX}" install
    fi
    cd ..
}


wget_build() {
    apt install texinfo
    local pkgname=wget
    local pkgver=1.19
    local pkgdesc="Network utility to retrieve files from the Web"
    local source=http://ftp.gnu.org/gnu/wget/${pkgname}-${pkgver}.tar.gz
    local depends=('zlib' 'openssl')
    download ${source}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    # prepare
    cd ${pkgname}-${pkgver}
  cat >> ../${pkgname}-${pkgver}doc/sample.wgetrc <<EOF

# default root certs location
ca_certificate=/etc/ssl/certs/ca-certificates.crt
EOF
    cd ..
    # build
    mkdir ${pkgname}-${pkgver}-build && cd ${pkgname}-${pkgver}-build
    CC="$TARGET_CC" ../${pkgname}-${pkgver}/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --disable-ntlm \
        --disable-debug \
        --with-ssl=openssl \
        --sysconfdir="$(realpath ${PREFIX}/../etc)"
    make ${PARALLEL_MAKE}
    strip_debug ./src/wget
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install-strip
    fi
    cp ./src/wget ${TOOLS_BIN_DIR}/wget_${DEB_TARGET}
    print_info "You can find it: ${TOOLS_BIN_DIR}/"
    cd ..
}

# TOR build
tor_build() {
    download $TOR_LINK
    print_info "Compile ${pkgname} - ${pkgdesc}"
    mkdir tor-$TORv-build && cd tor-$TORv-build
    LIBS="-lssl -lcrypto -ldl -lpthread" LDFLAGS="${LDFLAGS} -s -static -O2 -L$PREFIX/lib" CFLAGS="${CFLAGS} -static -s -O2 -I$PREFIX/include" CC="$TARGET_CC" ../tor-$TORv/configure \
        --host=$TARGET \
        --disable-gcc-hardening \
        --prefix=$PREFIX \
        --enable-static-openssl \
        --enable-static-zlib \
        --enable-static-tor \
        --enable-static-libevent \
        --with-libevent-dir=$PREFIX \
        --with-zlib-dir=$PREFIX \
        --with-openssl-dir=$PREFIX
    make $PARALLEL_MAKE
    strip_debug ./src/or/tor
    cp ./src/or/tor ${TOOLS_BIN_DIR}/tor_${DEB_TARGET}
    echo "" > ${TOOLS_BIN_DIR}/torrc
    print_info "You can find it: ${TOOLS_BIN_DIR}/"
    cd ..
}

# SSH build
ssh_build() {
    download $SSH_LINK
    print_info "Compile ${pkgname} - ${pkgdesc}"
    mkdir openssh-$SSHv-build && cd openssh-$SSHv-build
    LDFLAGS="${LDFLAGS} -s -Wl,-static" CFLAGS="${CFLAGS} -s -static -I/usr/$TARGET/include" CC="$TARGET_CC" ../openssh-$SSHv/configure \
        --target=$TARGET \
        --host=$TARGET \
        --with-md5-passwords \
        --with-zlib=$PREFIX \
        --with-ssl-dir=$PREFIX \
        --enable-strip \
        --enable-static
    make $PARALLEL_MAKE
    strip_debug ssh
    strip_debug sshd
    strip_debug scp
    cp ssh ${TOOLS_BIN_DIR}/ssh_${DEB_TARGET}
    cp sshd ${TOOLS_BIN_DIR}/sshd_${DEB_TARGET}
    cp scp ${TOOLS_BIN_DIR}/scp_${DEB_TARGET}
    print_info "You can find it: ${TOOLS_BIN_DIR}/"
    cd ..
}

# DROPBEAR build
dropbear_build() {
    download $DROPBEAR_LINK
    print_info "Compile ${pkgname} - ${pkgdesc}"
    mkdir dropbear-$DROPBEARv-build && cd dropbear-$DROPBEARv-build
    LDFLAGS="${LDFLAGS} -s -static -O2" CC="$TARGET_CC" ../dropbear-$DROPBEARv/configure \
        --target=$TARGET \
        --host=$TARGET \
        --disable-wtmpx \
        --disable-wtmp \
        --disable-utmpx \
        --disable-utmp
    make $PARALLEL_MAKE
    strip_debug dropbear
    strip_debug dbclient
    cp dropbear ${TOOLS_BIN_DIR}/dropbear_${DEB_TARGET}
    cp dbclient ${TOOLS_BIN_DIR}/dbclient_${DEB_TARGET}
    print_info "You can find it: ${TOOLS_BIN_DIR}/"
    cd ..
}

# Python2 build
python2_build() {
    download $PYTHON2_LINK
    print_info "Compile ${pkgname} - ${pkgdesc}"
    mkdir python-$PYTHON2v-build && cd python-$PYTHON2v-build
    CFLAGS="${CFLAGS} -static -s -O2" CC="$TARGET_CC" ../Python-$PYTHON2v/configure \
        --prefix=$PREFIX \
        --target=$TARGET \
        --host=$TARGET \
        --build=$MACHTYPE \
        --enable-optimizations \
        --disable-ipv6
    make $PARALLEL_MAKE
    make install
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install
    fi
    cd ..
}

# Python3 build
python3_build() {
    local pkgname=python
    local pkgver=3.8.1
    local pkgdesc=""
    local source="https://www.python.org/ftp/python/${pkgver}/Python-${pkgver}.tar.xz"
    download ${source}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    mkdir python-${pkgver}-build && cd python-${pkgver}-build
    CC="$TARGET_CC" CXX="$TARGET_CXX" ../Python-${pkgver}/configure \
        --prefix=$PREFIX \
        --target=$TARGET \
        --host=$TARGET \
        --build=$MACHTYPE \
        --without-pymalloc \
        --with-ensurepip=no \
        --without-cxx-main \
        --enable-shared --sysconfdir=/opt/etc \
        --with-computed-gotos \
        --enable-optimizations \
        ac_cv_file__dev_ptc=no \
        ac_cv_file__dev_ptmx=no \
        ac_cv_header_bluetooth_bluetooth_h=no \
        ac_cv_header_bluetooth_h=no
    make $PARALLEL_MAKE
    make install
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install
    fi
    cd ..
}

rpm_build() {
    download $RPM_LINK
    print_info "Compile ${pkgname} - ${pkgdesc}"
    mkdir rpm-$RPMv-build && cd rpm-$RPMv-build
    LIBS="-lz" LDFLAGS="${LDFLAGS} -static -s" CFLAGS="${CFLAGS} -s -static -O2 -I$PREFIX/include/beecrypt" CC="$TARGET_CC" ../rpm-$RPMv/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --without-cap \
        --without-lua \
        --with-beecrypt \
        --disable-nls \
        --enable-static \
        --with-external-db \
        --without-selinux \
        --without-hackingdocs \
        $BUILDTARGET
    make $PARALLEL_MAKE
    make install-strip
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install-strip
    fi
    cd ..
}

empty_build() {
    download $EMPTY_LINK
    print_info "Compile ${pkgname} - ${pkgdesc}"
    cd empty-$EMPTYv
    $TARGET_CC -static -s -Wall empty.c -lutil -o empty
    strip_debug empty
    make PREFIX=$PREFIX install
    cd ..
}


e2tools_build() {
    download $E2TOOLS_LINK
    print_info "Compile ${pkgname} - ${pkgdesc}"
    mkdir e2tools-$E2TOOLSv-build && cd e2tools-$E2TOOLSv-build
    LIBS="-pthread" LDFLAGS="${LDFLAGS} -Wl,-static -s" CFLAGS="${CFLAGS} -s -w -static -O2" CC="$TARGET_CC" ../e2tools-$E2TOOLSv/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        $BUILDTARGET
    make $PARALLEL_MAKE
    strip_debug e2cp
    make install-strip
    if ((CREATE_PACKAGE)); then
        make DESTDIR=$DEB_PACK install-strip
    fi
    cd ..
}


joe_build() {
    local pkgname=joe
    local pkgver=4.4
    local pkgdesc="A high-quality data compression program"
    local source=https://sourceforge.net/projects/joe-editor/files/JOE%20sources/${pkgname}-${pkgver}/${pkgname}-${pkgver}.tar.gz
    download ${source}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    # build
    cd ${pkgname}-${pkgver}
    CC="$TARGET_CC" ./configure \
        --prefix=$PREFIX \
        --target=$TARGET \
        --host=$TARGET \
        --disable-curses \
        --disable-termcap
    make $PARALLEL_MAKE
    # package
    strip_debug ./joe/joe
    cp ./joe/joe ${TOOLS_BIN_DIR}/joe_${DEB_TARGET}
    print_info "You can find it: ${TOOLS_BIN_DIR}/"
    if ((MAKE_INSTALL)); then
        make install
    fi
    cd ..
}


gdb_build() {
    apt-get install -y gcc g++
    local pkgname=gdb
    local pkgver=7.12
    local source=https://ftp.gnu.org/gnu/${pkgname}/${pkgname}-${pkgver}.tar.gz
    local depends=('zlib')
    download ${source}
    print_info "Resolve dependies for ${pkgname}"
    resolve_deps ${depends[@]}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    # prepare
    mkdir ${pkgname}-${pkgver}-build && cd ${pkgname}-${pkgver}-build
    sed -i 's/*argp ==/*argp[0] ==/' ../${pkgname}-${pkgver%%[!0-9.]*}*/gdb/location.c
    for x in $(grep -rl "RDYNAMIC=[\'\"]-Wl.*[\'\"]" ../${pkgname}-${pkgver%%[!0-9.]*}*/); do
        sed -i "s|RDYNAMIC=[\'\"]-Wl.*[\'\"]|RDYNAMIC=\"\"|g" $x;
    done
    # build
    LDFLAGS="${LDFLAGS} -L${PREFIX}/lib" CFLAGS="${CFLAGS} -I${PREFIX}/include" CXXFLAGS=${CFLAGS} CC="$TARGET_CC" CXX="$TARGET_CXX" ../${pkgname}-${pkgver%%[!0-9.]*}*/configure \
        --host=$TARGET \
        --target=$TARGET \
        --with-system-zlib \
        --without-guile \
        --disable-libada \
        --enable-gdbserver
    make $PARALLEL_MAKE
    strip_debug ./gdb/gdb
    strip_debug ./gdb/gdbserver/gdbserver
    cp ./gdb/gdb ${TOOLS_BIN_DIR}/gdb_${DEB_TARGET}
    cp ./gdb/gdbserver/gdbserver ${TOOLS_BIN_DIR}/gdbserver_${DEB_TARGET}
    print_info "You can find it: ${TOOLS_BIN_DIR}/"
    cd ..
}


distcc_build() {
    apt install -y autoconf
    local pkgname=distcc
    local pkgver=3.3.3
    local pkgdesc='Distributed compilation service for C, C++ and Objective-C'
    local source="https://github.com/distcc/${pkgname}/releases/download/v${pkgver}/${pkgname}-${pkgver}.tar.gz"
    local depends=('popt' 'python3')
    download ${source}
    print_info "Resolve dependies for ${pkgname}"
    # resolve_deps ${depends[@]}
    print_info "Compile ${pkgname} - ${pkgdesc}"
    # prepare
    cd ${pkgname}-${pkgver}
    ./autogen.sh
    setconf gnome/distccmon-gnome.desktop Name 'DistCC Monitor'
    sed -i 's/ install-gnome-data//g' Makefile.in
    # FS#66418, support Python 3.9
    find . -name "*.py" -type f -exec sed -i 's/time.clock()/time.perf_counter()/g' {} \;
    # build
    CC="$TARGET_CC" ./configure \
        --prefix=${PREFIX} \
        --target=$TARGET \
        --host=$TARGET \
        --enable-rfc2553 \
        --mandir=${PREFIX}/share/man \
        --sbindir=${PREFIX}/bin \
        --sysconfdir="$(realpath -sm ${PREFIX}/../etc)" \
        --without-avahi \
        --without-libiberty
        # --with-gtk
    make WERROR_CFLAGS= INCLUDESERVER_PYTHON=/bin/python
    if ((MAKE_INSTALL)); then
        make INCLUDESERVER_PYTHON=/bin/python install-conf install-program
    fi
    exit
    cd ..
}


options="ho:a:t:l:idv"
if (! getopts $options opt); then usage; fi

while getopts $options opt; do
    case $opt in
    i   ) MAKE_INSTALL=1 ;;
    o   ) export TOOLS_BIN_DIR=$OPTARG ;;
    d   ) CREATE_PACKAGE=1 ;;
    v   ) VERBOSE=1 ;;
    a   ) case $OPTARG in
            armel   )
                export TARGET=${TARGET:=arm-linux-gnueabi}
                export SSL_ARCH=linux-armv4
                export SSL_MARCH=${SSL_MARCH:=armv5}
                ;;
            armbe   )
                export TARGET=${TARGET:=armbe-linux-gnueabi}
                export CFLAGS_FOR_TARGET="-mbig-endian"
                export SSL_ARCH=linux-armv4
                export SSL_MARCH=${SSL_MARCH:=armv5}
                ;;
            mipsel  )
                export TARGET=${TARGET:=mipsel-linux-gnu}
                export SSL_ARCH=linux-mips32
                export SSL_MARCH=${SSL_MARCH:=mips1}
                ;;
            mips    )
                export TARGET=${TARGET:=mips-linux-gnu}
                export SSL_ARCH=linux-mips32
                export SSL_MARCH=${SSL_MARCH:=mips1}
                ;;
            powerpc )
                export TARGET=${TARGET:=powerpc-linux-gnu}
                export SSL_ARCH=linux-ppc
                ;;
            i686     )
                export TARGET=${TARGET:=i686-linux-gnu}
                export SSL_ARCH=linux-generic32
                # export SSL_MARCH=i386
                ;;
            *       ) usage ;;
        esac
        export PREFIX_TARCH=$OPTARG
        init $PREFIX_TARCH;;
    l   ) for lib in $OPTARG; do
            case $lib in
                openssl      )  openssl_build $PREFIX_TARCH ;;
                zlib         )  zlib_build ;;
                libtasn1     )  libtasn1_build ;;
                libevent     )  libevent_build ;;
                libpcap      )  libpcap_build ;;
                flex         )  flex_build $PREFIX_TARCH ;;
                libarchive   )  libarchive_build ;;
                e2fsprogs    )  e2fsprogs_build ;;
                libmagic     )  magic_build ;;
                libpopt      )  popt_build ;;
                libdb        )  db_build ;;
                curl         )  curl_build ;;
                libunistring )  libunistring_build ;;
                libassuan    )  libassuan_build ;;
                libgpg-error )  libgpg-error_build ;;
                gnutls       )  gnutls_build ;;
                gpgme        )  gpgme_build ;;
                *            )  ${lib}_build ;; # usage ;;
            esac
        done
        TOOLS_NAME+="-libs" ;;
    t   ) for item in $OPTARG; do
            case $item in
                wget     )  wget_build ;;
                tor      )  tor_build ;;
                ssh      )  ssh_build ;;
                dropbear )  dropbear_build ;;
                python2  )  python2_build ;;
                python3  )  python3_build ;;
                rpm      )  rpm_build ;;
                e2tools  )  e2tools_build ;;
                empty    )  empty_build ;;
                joe      )  joe_build ;;
                gdb      )  gdb_build ;;
                *        )  usage ;;
            esac
        done ;;
    h|* ) usage;;
    esac
done

cd ..

if ((CREATE_PACKAGE)); then
    print_info "Start create deb package"
    apt-get -y install md5deep fakeroot
    rm -rf $DEB_PACK/DEBIAN
    rm -rf $DEB_PACK/usr/share
    mkdir -p $DEB_PACK/DEBIAN
    TOOL_DIR=$(echo $DEB_PACK|sed -e "s|$(pwd)/||")
    # NAME=$(echo $TOOL_DIR|sed 's/_/-/g')
    echo "Package: $TOOLS_NAME" >> $DEB_PACK/DEBIAN/control
    echo "Version: ${DEBv}" >> $DEB_PACK/DEBIAN/control
    echo "Architecture: ${DEB_ARCH}" >> $DEB_PACK/DEBIAN/control
    echo "Maintainer: Admin" >> $DEB_PACK/DEBIAN/control
    echo "Priority: optional" >> $DEB_PACK/DEBIAN/control
    echo "Installed-Size: $(du -s $DEB_PACK/usr|awk '{print $1}')" >> $DEB_PACK/DEBIAN/control
    echo "Section: devel" >> $DEB_PACK/DEBIAN/control
    echo "Depends: make, autoconf, libtool" >> $DEB_PACK/DEBIAN/control
    echo -e $DEB_DESC >> $DEB_PACK/DEBIAN/control

    md5deep -l -o f -r $DEB_PACK/usr > $DEB_PACK/DEBIAN/md5sums
    fakeroot dpkg-deb --build $TOOL_DIR
    print_success "Tools was packed into the deb package $TOOL_DIR.deb"
fi

print_info "Remove unneeded files"
apt-get autoremove -y --purge md5deep fakeroot libfile-dircompare-perl gcc g++ >/dev/null
apt-get autoclean -y
apt-get clean -y
if [ -f /.dockerenv ]; then
    rm -rf /var/cache/* 2>/dev/null
    rm -rf ${LOGS_DIR} ${WORK_DIRECTORY} 2>/dev/null
fi
