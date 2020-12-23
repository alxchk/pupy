#!/bin/sh

set -x

PACKAGES_BUILD="netifaces construct watchdog impacket zeroconf==0.19.1 ushlex"
PACKAGES_BUILD="$PACKAGES_BUILD pycryptodomex pycryptodome paramiko asn1crypto"

PACKAGES="rsa pefile bcrypt win_inet_pton netaddr==0.7.19 pywin32 win_inet_pton dnslib"
PACKAGES="$PACKAGES https://github.com/amol-/dukpy/archive/master.zip"
PACKAGES="$PACKAGES https://github.com/secdev/scapy/archive/master.zip colorama"
PACKAGES="$PACKAGES https://github.com/warner/python-ed25519/archive/master.zip"
PACKAGES="$PACKAGES https://github.com/alxchk/tinyec/archive/master.zip"
PACKAGES="$PACKAGES https://github.com/alxchk/urllib-auth/archive/master.zip"
PACKAGES="$PACKAGES https://github.com/alxchk/winkerberos/archive/master.zip"
PACKAGES="$PACKAGES https://github.com/alxchk/pyuv/archive/v1.x.zip"
PACKAGES="$PACKAGES idna http-parser pyodbc wmi==1.4.9 pylzma"

if [ "$PYMAJ" = "2" ]; then
    PACKAGES="$PACKAGES u-msgpack-python msgpack-python"
    PACKAGES="$PACKAGES https://github.com/alxchk/pypykatz/archive/master.zip"
else
    PACKAGES="$PACKAGES https://github.com/skelsec/pypykatz/archive/master.zip"
fi


SELF=$(readlink -f "$0")
SELFPWD=$(dirname "$SELF")
SRC=${SELFPWD:-$(pwd)}
PUPY=$(readlink -f ../../pupy)

cd $SRC

EXTERNAL=$(readlink -f ../../pupy/external)
TEMPLATES=$(readlink -f ../../pupy/payload_templates)
WINPTY=$EXTERNAL/winpty
PYKCP=$EXTERNAL/pykcp
PYOPUS=$EXTERNAL/pyopus/src

set -e

echo "[+] Install python packages"
for PYTHON in $PYTHON32 $PYTHON64; do
    $PYTHON -m pip install -q --upgrade pip
    $PYTHON -m pip install -q --upgrade setuptools cython

    # Still problems here
    $PYTHON -m pip install -q --upgrade pynacl

    if [ "$PYMAJ" = "2" ]; then
	$PYTHON -m pip install --upgrade --no-binary \
		cryptography,pyOpenSSL \
		cryptography pyOpenSSL
    else
	# Prebuilt uses same openssl version as python
	$PYTHON -m pip install --upgrade cryptography pyOpenSSL
    fi
    
    $PYTHON -m pip install --upgrade \
	    --no-binary :all: \
	    --only-binary pip,setuptools,wheel,cryptography,pyOpenSSL,bcrypt \
	    $PACKAGES_BUILD

    if [ "$PYMAJ" = "2" ]; then
	# Broken for now
	$PYTHON -m pip install --upgrade pyaudio
	NO_JAVA=1 \
               $PYTHON -m pip install --upgrade --force-reinstall \
               https://github.com/alxchk/pyjnius/archive/master.zip
    fi

    $PYTHON -m pip install --upgrade --force-reinstall \
        https://github.com/alxchk/scandir/archive/master.zip

    $PYTHON -m pip install --upgrade $PACKAGES

    $PYTHON -c "from Crypto.Cipher import AES; AES.new"
    if [ ! $? -eq 0 ]; then
        echo "pycryptodome build failed"
        exit 1
    fi

    $PYTHON -c "import pylzma"
    if [ ! $? -eq 0 ]; then
        echo "pylzma installation failed"
        exit 1
    fi

    rm -rf $PYKCP/{kcp.so,kcp.pyd,kcp.dll,build,KCP.egg-info}
    $PYTHON -m pip install --upgrade --force $PYKCP
    $PYTHON -c 'import kcp' || exit 1
done

echo "[+] Install psutil"
if [ "$PYMAJ" = "2" ]; then
    $PYTHON32 -m pip install --no-binary :all: psutil==4.3.1
else
    # Old windows versions are not supported by new python anyway
    $PYTHON32 -m pip install --no-binary :all: psutil
fi
$PYTHON64 -m pip install --upgrade --no-binary :all: psutil

for PYTHON in $PYTHON32 $PYTHON64; do
    $PYTHON -m pip install -q --force pycparser==2.17
done

if [ "$PYMAJ" = "2" ]; then
    # FIXME: Add opus support

    cd $PYOPUS
    echo "[+] Compile opus /32"
    git clean -fdx
    make -f Makefile.msvc CL=$CL32
    mv opus.pyd ${PYTHONPATH32}/Lib/site-packages/

    echo "[+] Compile opus /64"
    git clean -fdx
    make -f Makefile.msvc CL=$CL64
    mv -f opus.pyd ${PYTHONPATH64}/Lib/site-packages/
fi

echo "[+] Compile winpty /32"
rm -f $WINPTY/build/winpty.dll
make -C ${WINPTY} clean
make -C ${WINPTY} MINGW_CXX="${MINGW32}-win32 -mabi=ms -Os" V=1 build/winpty.dll
if [ ! -f $WINPTY/build/winpty.dll ]; then
    echo "WinPTY/x86 build failed"
    exit 1
fi

mv $WINPTY/build/winpty.dll ${PYTHONPATH32}/DLLs/

echo "[+] Compile winpty /64"
rm -f $WINPTY/build/winpty.dll
make -C ${WINPTY} clean
make -C ${WINPTY} MINGW_CXX="${MINGW64}-win32 -mabi=ms -Os" V=1 build/winpty.dll
if [ ! -f $WINPTY/build/winpty.dll ]; then
    echo "WinPTY/x64 build failed"
    exit 1
fi

mv ${WINPTY}/build/winpty.dll ${PYTHONPATH64}/DLLs/

echo 'pyd' >> ${PYTHONPATH32}/DLLs/extension-suffix
echo 'pyd' >> ${PYTHONPATH64}/DLLs/extension-suffix

echo "[+] Build templates /32"
cd ${PYTHONPATH32}
rm -f ${TEMPLATES}/windows-x86.zip
for dir in Lib DLLs; do
    cd $dir
    zip -q -y \
        -x "*.a" -x "*.o" -x "*.whl" -x "*.txt" -x "*.pyo" -x "*.pyc" -x "*.chm" \
        -x "*test/*" -x "*tests/*" -x "*examples/*" -x "pythonwin/*"\
        -x "idlelib/*" -x "lib-tk/*" -x "tk*" -x "tcl*" -x "*__pycache__/*" \
        -x "*.egg-info/*" -x "*.dist-info/*" -x "*.exe" \
        -r9 ${TEMPLATES}/windows-x86-${PYTHON_ABI}.zip .
    cd -
done

cd ${PYTHONPATH64}
rm -f ${TEMPLATES}/windows-amd64.zip

echo "[+] Build templates /64"
for dir in Lib DLLs; do
    cd $dir
    zip -q -y \
        -x "*.a" -x "*.o" -x "*.whl" -x "*.txt" -x "*.pyo" -x "*.pyc" -x "*.chm" \
        -x "*test/*" -x "*tests/*" -x "*examples/*" -x "pythonwin/*"\
        -x "idlelib/*" -x "lib-tk/*" -x "tk*" -x "tcl*" -x "*__pycache__/*" \
        -x "*.egg-info/*" -x "*.dist-info/*" -x "*.exe" \
        -r9 ${TEMPLATES}/windows-amd64-${PYTHON_ABI}.zip .
    cd -
done

echo "[+] Build pupy"

TARGETS="pupyx64d-${PYTHON_ABI}.dll pupyx64d-${PYTHON_ABI}.exe"
TARGETS="$TARGETS pupyx64-${PYTHON_ABI}.dll pupyx64-${PYTHON_ABI}.exe"
TARGETS="$TARGETS pupyx86d-${PYTHON_ABI}.dll pupyx86d-${PYTHON_ABI}.exe"
TARGETS="$TARGETS pupyx86-${PYTHON_ABI}.dll pupyx86-${PYTHON_ABI}.exe"
TARGETS="$TARGETS "

cd ${SRC}

for target in $TARGETS; do rm -f $TEMPLATES/$target; done

set -e

ARGS="PYMAJ=$PYMAJ PYMIN=$PYMIN FEATURE_POSTMORTEM=y"

ARGS32="$ARGS PYTHON=$PYTHON32 CC=$CL32 PYTHONPATH=$PYTHONPATH32 ARCH=win32"
ARGS64="$ARGS PYTHON=$PYTHON64 CC=$CL64 PYTHONPATH=$PYTHONPATH64 ARCH=win64"

make -f Makefile -j BUILDENV=/build $ARGS32 distclean
make -f Makefile -j BUILDENV=/build $ARGS64 distclean
make -f Makefile -j BUILDENV=/build $ARGS32  
make -f Makefile -j BUILDENV=/build $ARGS32 DEBUG=1 clean
make -f Makefile -j BUILDENV=/build $ARGS32 DEBUG=1
make -f Makefile -j BUILDENV=/build $ARGS64 clean
make -f Makefile -j BUILDENV=/build $ARGS64  
make -f Makefile -j BUILDENV=/build $ARGS64 DEBUG=1 clean
make -f Makefile -j BUILDENV=/build $ARGS64 DEBUG=1

for object in $TARGETS; do
    if [ -z "$object" ]; then
        continue
    fi

    if [ ! -f $TEMPLATES/$object ]; then
        echo "[-] $object - failed"
        FAILED=1
    fi
done

if [ -z "$FAILED" ]; then
    echo "[+] Build complete"
else
    echo "[-] Build failed"
    exit 1
fi
