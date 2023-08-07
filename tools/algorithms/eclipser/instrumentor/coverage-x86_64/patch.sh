
SOURCE_DIR=${1}
PATCH_DIR=${2}

if [ ! -e patched ]
then
echo "[*] Backup target files of patches-common/ (for later use)"
cp ${SOURCE_DIR}/configure ${SOURCE_DIR}/configure.orig
cp ${SOURCE_DIR}/accel/tcg/cpu-exec.c ${SOURCE_DIR}/accel/tcg/cpu-exec.c.orig
cp ${SOURCE_DIR}/linux-user/elfload.c ${SOURCE_DIR}/linux-user/elfload.c.orig
cp ${SOURCE_DIR}/util/memfd.c ${SOURCE_DIR}/util/memfd.c.orig
cp ${SOURCE_DIR}/linux-user/signal.c ${SOURCE_DIR}/linux-user/signal.c.orig
cp ${SOURCE_DIR}/linux-user/syscall.c ${SOURCE_DIR}/linux-user/syscall.c.orig
cp ${SOURCE_DIR}/target/i386/helper.h ${SOURCE_DIR}/target/i386/helper.h.orig

echo "[*] Applying common patches..."
patch -p1 <${PATCH_DIR}/patches-common/configure.diff || exit 1
patch -p1 <${PATCH_DIR}/patches-common/cpu-exec.diff || exit 1
patch -p1 <${PATCH_DIR}/patches-common/elfload.diff || exit 1
patch -p1 <${PATCH_DIR}/patches-common/memfd.diff || exit 1
patch -p1 <${PATCH_DIR}/patches-common/signal.diff || exit 1
patch -p1 <${PATCH_DIR}/patches-common/syscall.diff || exit 1
patch -p1 <${PATCH_DIR}/patches-common/target-helper.diff || exit 1

echo "[*] Applying patches for coverage..."

cp ${PATCH_DIR}/patches-coverage/afl-qemu-cpu-inl.h ${SOURCE_DIR}/accel/tcg/
cp ${PATCH_DIR}/patches-coverage/eclipser.c ${SOURCE_DIR}/accel/tcg/
patch -p1 <${PATCH_DIR}/patches-coverage/makefile-objs.diff || exit 1
patch -p1 <${PATCH_DIR}/patches-coverage/target-translate.diff || exit 1
touch patched
fi

