#!/bin/sh
# BoringSSL (boring-sys) enables its tests and benchmarks by default, and the bundled benchmark library cannot configure when cross-compiling for Android. boring-sys gives cmake no way to turn them off, so build.sh points the CMAKE variable of the cmake crate at this wrapper, which adds the flag to every configure step. boring-sys configures twice in one build directory, and cmake throws the cache away on the second run because the compiler it finds differs from the one in the cache, which loses the flag: the wrapper deletes the old cache first so that the second run starts clean with it.
case "$1" in
	--build|--install) exec cmake "$@" ;;
esac
previous=""
for argument in "$@"; do
	[ "$previous" = "-B" ] && rm -f "$argument/CMakeCache.txt"
	previous=$argument
done
exec cmake "$@" -DBUILD_TESTING=OFF
