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

# Set script params
trap 'err_report $LINENO $BASH_LINENO "$BASH_COMMAND" $(printf "::%s" ${FUNCNAME[@]:-})' ERR
trap 'restore_output' EXIT
trap 'previous_command=$this_command; this_command=$BASH_COMMAND' DEBUG

redirect_output() {
    if [[ -z ${VERBOSE} ]]; then
        # Save stdout and stderr
        exec 3>&1
        exec 4>&2
        # Set output log files
        exec 1>>$LOG_FILE
        exec 2>>$ERROR_FILE
    fi
}

restore_output() {
    if [[ -z ${VERBOSE} ]]; then
        # Restore original stdout
        exec 1>&3 3>&- # Восстановить stdout и закрыть дескр. #3
        exec 2>&4 4>&- # Восстановить stderr и закрыть дескр. #4
    fi
}

download() {
    SRC_ARC=$(echo $1|grep -o '[a-zA-Z0-9\.\-]\+\.tar\.[a-z0-9]\+'|head -n1)
    print_info "Start download $SRC_ARC"
    if [ ! -f $SRC_ARC ]; then
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
    if [[ -z ${VERBOSE} ]]; then
        ERROR_FILE=$(pwd)/error.log
        LOG_FILE=$(pwd)/output.log
        # Clear logs
        rm -f $LOG_FILE $ERROR_FILE 2>/dev/null
    else
        ERROR_FILE=""
        LOG_FILE=""
    fi
    RESULT_FILE=$(pwd)/result.log
    redirect_output
}

upgrade_system() {
    print_info "Update apt-get"
    apt-get update && apt-get -y upgrade
    apt-get install -y make gawk wget
    apt-get -y autoremove
}

init() {
    init_logs
    upgrade_system
    TOOLCHAIN_DIR=/usr
    export TARGET_CC="$TARGET-gcc $CFLAGS_FOR_TARGET"
    export TARGET_CXX="$TARGET-g++ $CFLAGS_FOR_TARGET"

    export USR=$TOOLCHAIN_DIR
    if [[ -z $PREFIX ]]; then
        export PREFIX=$USR/$TARGET
    fi
    export PATH=$PATH:$PREFIX/bin:$USR/bin
    export PARALLEL_MAKE=-j3
    # if [[ $(uname -m) == x86_64 ]]; then
    #     export DEB_ARCH=amd64
    # else
    #     export DEB_ARCH=i386
    # fi
    export DEB_ARCH=all
    export DEBv=1.0
    export DEB_TARGET=$1 #$(echo $TARGET|tr '-' ' '|awk '{print $1}')
    export DEB_PACK=$(pwd)/${DEB_TARGET}_tools_v${DEBv}_${DEB_ARCH}
    export TMP_BUILD_DIR=$(pwd)/$DEB_TARGET-cross
    if [[ -z $TOOLS_BIN_DIR ]]; then
        export TOOLS_BIN_DIR=$(pwd)/BIN
    fi
    if [[ $1 == i686 ]]; then
        export BUILDTARGET="--build=$TARGET"
    else
        export BUILDTARGET=""
    fi
    export DEB_DESC="Description: Tools for $DEB_TARGET toolchain"
    export TOOLS_NAME="$DEB_TARGET"
    
    if [[ ! -d $TMP_BUILD_DIR ]]; then
        mkdir $TMP_BUILD_DIR
        cd $TMP_BUILD_DIR
    else
        cd $TMP_BUILD_DIR
        print_info "Remove previous sources"
        ls|grep -v "\.tar\."| xargs rm -rf
    fi
    # Check BIN dir
    if [[ ! -d $TOOLS_BIN_DIR ]]; then
        mkdir $TOOLS_BIN_DIR
    fi
    if [[ -d $DEB_PACK ]]; then
        rm -rf $DEB_PACK
    fi
    mkdir -p $DEB_PACK
}

usage() {
    restore_output
cat << EOF
usage: args.py [-h] -a ARCH [-t TOOLS] [-l LIBS] [-i] [-v] [-d] [-o DIR]

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
export ZLIBv=1.2.11
export OPENSSLv=1.1.1
export LIBEVENTv=2.1.8-stable
export LIBPCAPv=1.8.1
export FLEXv=2.6.4
export LIBTASN1v=4.12
export LIBARCHIVEv=3.3.2
export E2FSv=1.43.4
export LMAGICv=5.31
export POPTv=1.16
export BEECRYPTv=4.1.2
export LDBv=6.2.23.NC
export CURLv=7.53.1
export WGETv=1.19
export TORv=0.3.4.9
export SSHv=7.4p1
export DROPBEARv=2017.75
export PYTHON2v=2.7.13
export PYTHON3v=3.4.6
export RPMv=4.12.0
export JOEv=4.4
export E2TOOLSv=0.0.16
export EMPTYv=0.6.20b
export GDBv=7.12
# Links
export SSL_LINK=https://www.openssl.org/source/openssl-$OPENSSLv.tar.gz
export ZLIB_LINK=https://zlib.net/zlib-$ZLIBv.tar.gz
export EVENT_LINK=https://github.com/libevent/libevent/releases/download/release-$LIBEVENTv/libevent-$LIBEVENTv.tar.gz
export TASN1_LINK=http://ftp.gnu.org/gnu/libtasn1/libtasn1-$LIBTASN1v.tar.gz
export PCAP_LINK=http://www.tcpdump.org/release/libpcap-$LIBPCAPv.tar.gz
export FLEX_LINK=https://github.com/westes/flex/files/981163/flex-$FLEXv.tar.gz
export ARCHIVE_LINK=https://www.libarchive.org/downloads/libarchive-$LIBARCHIVEv.tar.gz
export E2FSPROGS_LINK=https://www.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v$E2FSv/e2fsprogs-$E2FSv.tar.xz
export LMAGIC_LINK=ftp://ftp.astron.com/pub/file/file-$LMAGICv.tar.gz
export POPT_LINK=http://rpm5.org/files/popt/popt-$POPTv.tar.gz
export BEECRYPT_LINK=http://prdownloads.sourceforge.net/beecrypt/beecrypt-$BEECRYPTv.tar.gz
export LDB_LINK=http://download.oracle.com/berkeley-db/db-$LDBv.tar.gz
export CURL_LINK=https://curl.haxx.se/download/curl-$CURLv.tar.gz
export WGET_LINK=http://ftp.gnu.org/gnu/wget/wget-$WGETv.tar.gz
export TOR_LINK=https://www.torproject.org/dist/tor-$TORv.tar.gz
export SSH_LINK=http://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-$SSHv.tar.gz
export DROPBEAR_LINK=https://matt.ucc.asn.au/dropbear/releases/dropbear-$DROPBEARv.tar.bz2
export PYTHON2_LINK=https://www.python.org/ftp/python/$PYTHON2v/Python-$PYTHON2v.tar.xz
export PYTHON3_LINK=https://www.python.org/ftp/python/$PYTHON3v/Python-$PYTHON3v.tar.xz
export RPM_LINK=http://ftp.rpm.org/releases/rpm-4.12.x/rpm-$RPMv.tar.bz2
export JOE_LINK=https://sourceforge.net/projects/joe-editor/files/JOE%20sources/joe-$JOEv/joe-$JOEv.tar.gz
export E2TOOLS_LINK=http://home.earthlink.net/~k_sheff/sw/e2tools/e2tools-$E2TOOLSv.tar.gz
export EMPTY_LINK=https://downloads.sourceforge.net/project/empty/empty/empty-$EMPTYv/empty-$EMPTYv.tgz
export GDB_LINK=https://ftp.gnu.org/gnu/gdb/gdb-$GDBv.tar.gz


ARCHS=(armel armbe mipsel mips i686 powerpc tile)
TOOLS=(wget tor ssh dropbear python2 python3 rpm e2tools empty joe gdb)
LIBS=(zlib openssl libtasn1 libevent libpcap flex libmagic e2fsprogs libdb curl)
# redirect_output


#####################################################################################################
#                                               LIBS
#####################################################################################################


check_lib() {
    if [[ $? == 0 ]]
    then
        print_success "$1 Installed"
        rm a.out test.c >/dev/null
    else
        print_error "compile $1"
        exit 1
    fi
}


zlib_build() {
    download $ZLIB_LINK
    print_info "Compile zlib"
    cd zlib-$ZLIBv
    CFLAGS="-static -s -O2" CC="$TARGET_CC" ./configure \
        --prefix=$PREFIX \
        --static
    make $PARALLEL_MAKE
    if [[ -e $CREATE_DEB ]]; then
        make DESTDIR=$DEB_PACK install
    fi
    make install
    cd ..
    DEB_DESC+="\n .\n zlib-$ZLIBv"
    TOOLS_NAME+="-zlib"
}


openssl_build() {
    download $SSL_LINK
    print_info "Compile OpenSSL"
    apt-get install -y libfile-dircompare-perl
    cd openssl-$OPENSSLv
    if [[ $1 == i686 ]]; then
        LDFLAGS="-static -s" CFLAGS=" -static -s -O2" CC="$TARGET_CC" ./Configure $SSL_ARCH --prefix=$PREFIX no-shared --openssldir=$PREFIX -m32 -fPIC -I$PREFIX/include -L$PREFIX/lib
    elif [[ $1 == powerpc ]]; then
        LDFLAGS="-static -s" CFLAGS=" -static -s -O2" CC="$TARGET_CC" ./Configure $SSL_ARCH --prefix=$PREFIX no-shared --openssldir=$PREFIX -fPIC -I$PREFIX/include -L$PREFIX/lib
    else
        LDFLAGS="-static -s" CFLAGS=" -static -s -O2" CC="$TARGET_CC" ./Configure $SSL_ARCH --prefix=$PREFIX no-shared --openssldir=$PREFIX -march=$SSL_MARCH -fPIC -I$PREFIX/include -L$PREFIX/lib
    fi
    make $PARALLEL_MAKE
    make install
    if [[ -e $CREATE_DEB ]]; then
        # Create DEB
        if [[ $1 == i686 ]]; then
            LDFLAGS="-static -s" CFLAGS=" -static -s -O2" CC="$TARGET_CC" ./Configure $SSL_ARCH --prefix=$DEB_PACK/$PREFIX no-shared --openssldir=$PREFIX -m32 -fPIC -I$PREFIX/include -L$PREFIX/lib
        elif [[ $1 == powerpc ]]; then
            LDFLAGS="-static -s" CFLAGS=" -static -s -O2" CC="$TARGET_CC" ./Configure $SSL_ARCH --prefix=$DEB_PACK/$PREFIX no-shared --openssldir=$DEB_PACK/$PREFIX -fPIC -I$PREFIX/include -L$PREFIX/lib
        else
            LDFLAGS="-static -s" CFLAGS=" -static -s -O2" CC="$TARGET_CC" ./Configure $SSL_ARCH --prefix=$DEB_PACK/$PREFIX no-shared --openssldir=$DEB_PACK/$PREFIX -march=$SSL_MARCH -fPIC -I$PREFIX/include -L$PREFIX/lib
        fi
        make $PARALLEL_MAKE
        make install
    fi
    cd ..

    # Test openssl
    echo "void main(){}" > test.c
    $TARGET_CC test.c -lssl -lcrypto -static
    check_lib "OpenSSL"
    DEB_DESC+="\n .\n openssl-$OPENSSLv"
    TOOLS_NAME+="-openssl"
}


libevent_build() {
    download $EVENT_LINK
    print_info "Compile libEvent"
    mkdir libevent-$LIBEVENTv-build && cd libevent-$LIBEVENTv-build
    LDFLAGS="-static -s" CFLAGS="-static -O2 -s -ldl" CC="$TARGET_CC" ../libevent-$LIBEVENTv/configure \
        --host=$TARGET \
        --with-pic \
        --prefix=$PREFIX \
        --enable-static \
        $BUILDTARGET
    make $PARALLEL_MAKE
    make install
    if [[ -e $CREATE_DEB ]]; then
        make DESTDIR=$DEB_PACK install
    fi
    cd ..

    # Test libevent
    echo "void main(){}" > test.c
    $TARGET_CC test.c -levent -static
    check_lib "LibEvent"
    DEB_DESC+="\n .\n libevent-$LIBEVENTv"
    TOOLS_NAME+="-libevent"
}


libtasn1_build() {
    download $TASN1_LINK
    print_info "Compile libTasn1"
    mkdir libtasn1-$LIBTASN1v-build && cd libtasn1-$LIBTASN1v-build
    LDFLAGS="-static -s" CFLAGS="-static -O2 -s" CC="$TARGET_CC" ../libtasn1-$LIBTASN1v/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --disable-doc \
        --enable-static \
        $BUILDTARGET
    make $PARALLEL_MAKE
    make install-strip
    if [[ -e $CREATE_DEB ]]; then
        make DESTDIR=$DEB_PACK install-strip
    fi
    cd ..

    # Test libtasn1
    echo "void main(){}" > test.c
    $TARGET_CC test.c -ltasn1 -static
    check_lib "LibTasn1"
    DEB_DESC+="\n .\n libtasn1-$LIBTASN1v"
    TOOLS_NAME+="-libtasn1"
}


flex_build() {
    download $FLEX_LINK
    print_info "Compile flex"
    mkdir flex-$FLEXv-build && cd flex-$FLEXv-build
    if [[ $(uname -m) == x86_64 ]]; then
        apt-get -y install gcc-multilib
        LDFLAGS="-static -s" CFLAGS="-static -O2 -s" CXXFLAGS=$CFLAGS CC="$TARGET_CC" ../flex-$FLEXv/configure --prefix=$PREFIX --enable-static --host=$TARGET $BUILDTARGET CFLAGS_FOR_BUILD="-s -O2 -m32"
    else
        LDFLAGS="-static -s" CFLAGS="-static -O2 -s" CXXFLAGS=$CFLAGS CC="$TARGET_CC" ../flex-$FLEXv/configure --prefix=$PREFIX --enable-static --host=$TARGET $BUILDTARGET
    fi
    make $PARALLEL_MAKE
    make install-strip
    make DESTDIR=$DEB_PACK install-strip
    if [[ $1 != i686 ]] || [[ $1 != i686 ]]; then
        rm -rf $PREFIX/bin/flex*
        if [[ $(uname -m) == x86_64 ]]; then
            LDFLAGS="-static -s" CFLAGS="-static -O2 -s" CXXFLAGS=$CFLAGS CC=gcc ../flex-$FLEXv/configure --prefix=$PREFIX --enable-static --disable-libfl CFLAGS_FOR_BUILD="-s -O2 -m32"
        else
            LDFLAGS="-static -s" CFLAGS="-static -O2 -s" CXXFLAGS=$CFLAGS CC=gcc ../flex-$FLEXv/configure --prefix=$PREFIX --enable-static --disable-libfl
        fi
        make $PARALLEL_MAKE
        make install-strip
    fi
    cd ..

    # Test libfl
    echo "void main(){}" > test.c
    $TARGET_CC test.c -static -lfl
    check_lib "flex"
    DEB_DESC+="\n .\n flex-$FLEXv"
    TOOLS_NAME+="-flex"
}


libpcap_build() {
    if [[ ! -x flex ]]; then
        flex_build $(echo $TARGET|tr "-" " "|awk '{print $1}')
    fi
    download $PCAP_LINK
    print_info "Compile libPcap"
    mkdir libpcap-$LIBPCAPv-build && cd libpcap-$LIBPCAPv-build
    LDFLAGS="-static -s" CFLAGS="-static -O2 -s" CC="$TARGET_CC" ../libpcap-$LIBPCAPv/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --with-pcap=linux \
        --disable-shared \
        $BUILDTARGET
    make $PARALLEL_MAKE
    make install
    if [[ -e $CREATE_DEB ]]; then
        make DESTDIR=$DEB_PACK install
    fi
    cd ..

    # Test libpcap
    echo "void main(){}" > test.c
    $TARGET_CC test.c -lpcap -static
    check_lib "LibPCAP"
    DEB_DESC+="\n .\n libpcap-$LIBPCAPv"
    TOOLS_NAME+="-libpcap"
}

# Not tested for deb
libarchive_build() {
    download $ARCHIVE_LINK
    print_info "Compile libArchive"
    mkdir libarchive-$LIBARCHIVEv-build && cd libarchive-$LIBARCHIVEv-build
    LDFLAGS="-static -s" CFLAGS="-static -s -O2" CC="$TARGET_CC" ../libarchive-$LIBARCHIVEv/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --enable-static \
        --without-xml2 \
        --without-lzma \
        --without-openssl \
        --with-zlib \
        $BUILDTARGET
    make $PARALLEL_MAKE
    if [[ -e $CREATE_DEB ]]; then
        make DESTDIR=$DEB_PACK install-strip
    fi
    make install-strip
    cd ..

    # Test libarchive
    echo "void main(){}" > test.c
    $TARGET_CC test.c -static -larchive
    check_lib "LibArchive"
    DEB_DESC+="\n .\n libarchive-$LIBARCHIVEv"
    TOOLS_NAME+="-libarchive"
}


e2fsprogs_build() {
    download $E2FSPROGS_LINK
    print_info "Compile e2fsprogs"
    mkdir e2fsprogs-$E2FSv-build && cd e2fsprogs-$E2FSv-build
    LDFLAGS="-static -s" CFLAGS="-s -static -O2" CC="$TARGET_CC" ../e2fsprogs-$E2FSv/configure \
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
    if [[ -e $CREATE_DEB ]]; then
        make DESTDIR=$DEB_PACK install-libs
    fi
    make install-libs
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
    print_info "Compile libMagic"
    mkdir file-$LMAGICv-build && cd file-$LMAGICv-build
    LDFLAGS="-static -s" CFLAGS="-s -w -static -O2" CC="$TARGET_CC" ../file-$LMAGICv/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --enable-static \
        --includedir=$PREFIX/include \
        --libdir=$PREFIX/lib \
        $BUILDTARGET
    make $PARALLEL_MAKE
    if [[ -e $CREATE_DEB ]]; then
        make DESTDIR=$DEB_PACK install-strip
    fi
    make install-strip
    cd ..

    # Test libmagic
    echo "void main(){}" > test.c
    $TARGET_CC test.c -static -lmagic -lz
    check_lib "libmagic"
    DEB_DESC+="\n .\n file-$LMAGICv"
    TOOLS_NAME+="-file"
}


popt_build() {
    download $POPT_LINK
    print_info "Compile libPopt"
    mkdir popt-$POPTv-build && cd popt-$POPTv-build
    LDFLAGS="-static -s" CFLAGS="-s -static -O2" CC="$TARGET_CC" ../popt-$POPTv/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --enable-static \
        --disable-nls \
        $BUILDTARGET
    make $PARALLEL_MAKE
    if [[ -e $CREATE_DEB ]]; then
        make DESTDIR=$DEB_PACK install-strip
    fi
    make install-strip
    cd ..

    # Test libpopt
    echo "void main(){}" > test.c
    $TARGET_CC test.c -static -lpopt
    check_lib "libpopt"
    DEB_DESC+="\n .\n popt-$POPTv"
    TOOLS_NAME+="-popt"
}


beecrypt_build() {
    download $BEECRYPT_LINK
    print_info "Compile beecrypt"
    mkdir beecrypt-$BEECRYPTv-build && cd beecrypt-$BEECRYPTv-build
    LDFLAGS="-static -s" CFLAGS="-s -static -O2" CC="$TARGET_CC" ../beecrypt-$BEECRYPTv/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --enable-static \
        --enable-openmp \
        --disable-debug \
        --without-java \
        $BUILDTARGET
    make $PARALLEL_MAKE
    if [[ -e $CREATE_DEB ]]; then
        make DESTDIR=$DEB_PACK install-strip
    fi
    make install-strip
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
    print_info "Compile libDB"
    mkdir db-$LDBv-build && cd db-$LDBv-build
    LDFLAGS="-static -s" CFLAGS="-s -static -O2" CC="$TARGET_CC" ../db-$LDBv/dist/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --disable-java \
        --enable-static \
        $BUILDTARGET
    make $PARALLEL_MAKE
    if [[ -e $CREATE_DEB ]]; then
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


curl_build() {
    download $CURL_LINK
    print_info "Compile libCURL. Please check that you have installed zLib and OpenSSL"
    mkdir curl-$CURLv-build && cd curl-$CURLv-build
    LIBS="-ldl" CFLAGS="-s -static -O2 -fPIC -I$PREFIX/include" CPPFLAGS="-DCURL_STATICLIB" LDFLAGS="-Wl,-static -s -L$PREFIX/lib" CC=$TARGET_CC ../curl-$CURLv/configure \
        --host=$TARGET \
        --target=$TARGET \
        --prefix=$PREFIX \
        --disable-rt \
        --enable-http \
        --enable-cookies \
        --disable-ipv6 \
        --disable-ftp \
        --disable-ldap \
        --disable-ldaps \
        --disable-rtsp \
        --with-proxy \
        --disable-dict \
        --disable-telnet \
        --disable-tftp \
        --disable-pop3 \
        --disable-imap \
        --disable-smb \
        --disable-smtp \
        --disable-gopher \
        --disable-pthreads \
        --disable-crypto-auth \
        --disable-sspi \
        --disable-shared \
        --enable-static \
        --disable-debug \
        --disable-curldebug \
        --with-zlib \
        --with-ssl=$PREFIX \
        --without-axtls
    make $PARALLEL_MAKE
    strip_debug src/curl
    if [[ -e $CREATE_DEB ]]; then
        make DESTDIR=$DEB_PACK install-strip
    fi
    make install-strip

    # Test libdb
    echo "void main(){}" > test.c
    $TARGET_CC test.c -static -lcurl
    check_lib "libCURL"
    DEB_DESC+="\n .\n curl-$CURLv"
    TOOLS_NAME+="-curl"
}


#####################################################################################################
#                                               SOFT
#####################################################################################################


wget_build() {
    download $WGET_LINK
    print_info "Compile WGET"
    mkdir wget-$WGETv-build && cd wget-$WGETv-build
    LDFLAGS="-static -s" CFLAGS="-s -static -O2" CC="$TARGET_CC" ../wget-$WGETv/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        --disable-ntlm \
        --disable-ipv6 \
        --disable-debug \
        --without-zlib \
        --without-ssl
    make $PARALLEL_MAKE
    strip_debug ./src/wget
    cp ./src/wget $TOOLS_BIN_DIR/wget_${DEB_TARGET}
    cd ..
}

# TOR build
tor_build() {
    download $TOR_LINK
    print_info "Compile Tor"
    mkdir tor-$TORv-build && cd tor-$TORv-build
    LIBS="-lssl -lcrypto -ldl -lpthread" LDFLAGS="-s -static -O2 -L$PREFIX/lib" CFLAGS="-static -s -O2 -I$PREFIX/include" CC="$TARGET_CC" ../tor-$TORv/configure \
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
    cp ./src/or/tor $TOOLS_BIN_DIR/tor_${DEB_TARGET}
    echo "" > $TOOLS_BIN_DIR/torrc
    cd ..
}

# SSH build
ssh_build() {
    download $SSH_LINK
    print_info "Compile SSH"
    mkdir openssh-$SSHv-build && cd openssh-$SSHv-build
    LDFLAGS="-s -Wl,-static" CFLAGS="-s -static -I/usr/$TARGET/include" CC="$TARGET_CC" ../openssh-$SSHv/configure \
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
    cp ssh $TOOLS_BIN_DIR/ssh_${DEB_TARGET}
    cp sshd $TOOLS_BIN_DIR/sshd_${DEB_TARGET}
    cp scp $TOOLS_BIN_DIR/scp_${DEB_TARGET}
    cd ..
}

# DROPBEAR build
dropbear_build() {
    download $DROPBEAR_LINK
    print_info "Compile Dropbear"
    mkdir dropbear-$DROPBEARv-build && cd dropbear-$DROPBEARv-build
    LDFLAGS="-s -static -O2" CC="$TARGET_CC" ../dropbear-$DROPBEARv/configure \
        --target=$TARGET \
        --host=$TARGET \
        --disable-wtmpx \
        --disable-wtmp \
        --disable-utmpx \
        --disable-utmp
    make $PARALLEL_MAKE
    strip_debug dropbear
    strip_debug dbclient
    cp dropbear $TOOLS_BIN_DIR/dropbear_${DEB_TARGET}
    cp dbclient $TOOLS_BIN_DIR/dbclient_${DEB_TARGET}
    cd ..
}

# Python2 build
python2_build() {
    download $PYTHON2_LINK
    print_info "Compile Python$PYTHON2v"
    mkdir python-$PYTHON2v-build && cd python-$PYTHON2v-build
    CFLAGS="-static -s -O2" CC="$TARGET_CC" ../Python-$PYTHON2v/configure \
        --prefix=$PREFIX \
        --target=$TARGET \
        --enable-optimizations
    make $PARALLEL_MAKE
    make install
    if [[ -e $CREATE_DEB ]]; then
        make DESTDIR=$DEB_PACK install
    fi
    cd ..
}

# Python3 build
python3_build() {
    download $PYTHON3_LINK
    print_info "Compile Python$PYTHON3v"
    mkdir python-$PYTHON3v-build && cd python-$PYTHON3v-build
    RANLIB=$TARGET-ranlib CC="$TARGET_CC" CFLAGS="-static -s" ../Python-$PYTHON3v/configure \
        --prefix=$PREFIX \
        --target=$TARGET
    make $PARALLEL_MAKE
    make install
    if [[ -e $CREATE_DEB ]]; then
        make DESTDIR=$DEB_PACK install
    fi
    cd ..
}

rpm_build() {
    download $RPM_LINK
    print_info "Compile RPM"
    mkdir rpm-$RPMv-build && cd rpm-$RPMv-build
    LIBS="-lz" LDFLAGS="-static -s" CFLAGS="-s -static -O2 -I$PREFIX/include/beecrypt" CC="$TARGET_CC" ../rpm-$RPMv/configure \
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
    if [[ -e $CREATE_DEB ]]; then
        make DESTDIR=$DEB_PACK install-strip
    fi
    cd ..
}

empty_build() {
    download $EMPTY_LINK
    print_info "Compile Empty"
    cd empty-$EMPTYv
    $TARGET_CC -static -s -Wall empty.c -lutil -o empty
    strip_debug empty
    make PREFIX=$PREFIX install
    cd ..
}


e2tools_build() {
    download $E2TOOLS_LINK
    print_info "Compile e2tools"
    mkdir e2tools-$E2TOOLSv-build && cd e2tools-$E2TOOLSv-build
    LIBS="-pthread" LDFLAGS="-Wl,-static -s" CFLAGS="-s -w -static -O2" CC="$TARGET_CC" ../e2tools-$E2TOOLSv/configure \
        --prefix=$PREFIX \
        --host=$TARGET \
        $BUILDTARGET
    make $PARALLEL_MAKE
    strip_debug e2cp
    make install-strip
    if [[ -e $CREATE_DEB ]]; then
        make DESTDIR=$DEB_PACK install-strip
    fi
    cd ..
}


joe_build() {
    download $JOE_LINK
    print_info "Compile joe"
    cd joe-$JOEv
    LDFLAGS="-Wl,-static -s" CFLAGS="-static -s -O2" CC="$TARGET_CC" ./configure \
        --prefix=$PREFIX \
        --target=$TARGET \
        --host=$TARGET \
        --disable-curses \
        --disable-termcap
    make $PARALLEL_MAKE
    strip_debug ./joe/joe
    cp ./joe/joe $TOOLS_BIN_DIR/joe_${DEB_TARGET}
    cd ..
}


gdb_build() {
    download $GDB_LINK
    apt-get install -y gcc g++
    print_info "Compile gdb"
    mkdir gdb-$GDBv-build && cd gdb-$GDBv-build
    sed -i 's/*argp ==/*argp[0] ==/' ../gdb-$GDBv/gdb/location.c
    for x in $(grep -rl "RDYNAMIC=[\'\"]-Wl.*[\'\"]" ../gdb-$GDBv/); do sed -i "s|RDYNAMIC=[\'\"]-Wl.*[\'\"]|RDYNAMIC=\"\"|g" $x; done
    LDFLAGS="-s -static -L$PREFIX/lib" CFLAGS="-s -static -O2 -I$PREFIX/include" CXXFLAGS=$CFLAGS CC="$TARGET_CC" CXX="$TARGET_CXX" ../gdb-$GDBv/configure \
        --host=$TARGET \
        --target=$TARGET \
        --with-system-zlib \
        --without-guile \
        --disable-libada \
        --enable-gdbserver
    make $PARALLEL_MAKE
    strip_debug ./gdb/gdb
    strip_debug ./gdb/gdbserver/gdbserver
    cp ./gdb/gdb $TOOLS_BIN_DIR/gdb_${DEB_TARGET}
    cp ./gdb/gdbserver/gdbserver $TOOLS_BIN_DIR/gdbserver_${DEB_TARGET}
    cd ..
}


options="ho:a:t:l:idv"
if (! getopts $options opt); then usage; fi

while getopts $options opt; do
    case $opt in
    i   ) export MAKE_INSTALL=true;;
    o   ) export TOOLS_BIN_DIR=$OPTARG;;
    d   ) export CREATE_DEB=true;;
    v   ) export VERBOSE=true;;
    a   ) case $OPTARG in
            armel   )
                export TARGET=arm-linux-gnueabi
                export SSL_ARCH=linux-armv4
                export SSL_MARCH=armv5
                ;;
            armbe   )
                export TARGET=armbe-linux-gnueabi
                export CFLAGS_FOR_TARGET="-mbig-endian"
                export SSL_ARCH=linux-armv4
                export SSL_MARCH=armv5
                ;;
            mipsel  )
                export TARGET=mipsel-linux-gnu
                export SSL_ARCH=linux-mips32
                export SSL_MARCH=mips1
                ;;
            mips    )
                export TARGET=mips-linux-gnu
                export SSL_ARCH=linux-mips32
                export SSL_MARCH=mips1
                ;;
            powerpc )
                export TARGET=powerpc-linux-gnu
                export SSL_ARCH=linux-ppc
                ;;
            i686     )
                export TARGET=i686-linux-gnu
                export SSL_ARCH=linux-generic32
                # export SSL_MARCH=i386
                ;;
            tile    )
                export TARGET=tilegx-linux-gnu
                export CFLAGS_FOR_TARGET="-m32"
                ;;
            *       ) usage ;;
        esac
        export PREFIX_TARCH=$OPTARG
        init $PREFIX_TARCH;;
    l   ) for lib in $OPTARG; do
            case $lib in
                openssl    )  openssl_build $PREFIX_TARCH ;;
                zlib       )  zlib_build ;;
                libtasn1   )  libtasn1_build ;;
                libevent   )  libevent_build ;;
                libpcap    )  libpcap_build ;;
                flex       )  flex_build $PREFIX_TARCH ;;
                libarchive )  libarchive_build ;;
                e2fsprogs  )  e2fsprogs_build ;;
                libmagic   )  magic_build ;;
                libpopt    )  popt_build ;;
                libdb      )  db_build ;;
                curl       )  curl_build ;;
                *          )  usage ;;
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

if [[ -e $CREATE_DEB ]]; then
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
echo ok
apt-get autoremove -y --purge md5deep fakeroot libfile-dircompare-perl gcc g++
apt-get autoclean -y
apt-get clean -y
if [ -f /.dockerenv ]; then
    rm -rf /tmp/* && rm -rf /var/cache/*
fi
