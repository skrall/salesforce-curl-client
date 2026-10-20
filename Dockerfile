# sfcc -- a small Salesforce REST client in C.
#
# Alpine rather than Debian because musl's resolver works in a static build,
# whereas glibc's needs NSS -- which is the reason a statically linked glibc
# HTTP client silently fails DNS at runtime. That advantage is why Alpine is the
# base, even though this image is not itself fully static (see below).
#
# Alpine has openssl-libs-static but no libcurl.a, so a scratch-based fully
# static build would mean compiling curl from source in the build stage. Not
# worth it for a CLI: the dynamic runtime below is already ~15 MB, and it keeps
# the supply chain to packages Alpine actually ships.

# --- build ------------------------------------------------------------------
FROM alpine:3.24 AS build

# build-base gives gcc/musl-dev/make. cmake builds the project; pkgconfig lets
# it find libcurl; curl-dev is the headers and the shared library to link.
# openssl-dev is the libcrypto headers and static library for the cache
# encryption backend (curl-dev pulls it in transitively today; named here so
# that dependency staying a fact is this file's job, not alpine's).
RUN apk add --no-cache \
      build-base \
      cmake \
      pkgconf \
      curl-dev \
      openssl-dev

WORKDIR /src

# The package install above is its own layer, so it stays cached when only the
# sources change. The source itself must be copied before cmake is run at all:
# add_library/add_executable need their files present at configure time, so a
# "smoke build" against a sources-only tree does not work.
COPY . .

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DSFCC_BUILD_TESTS=OFF \
 && cmake --build build --target sfcc_cli \
 && strip build/bin/sfcc \
 && build/bin/sfcc --version

# --- runtime ----------------------------------------------------------------
FROM alpine:3.24

# libcurl and its TLS backend. ca-certificates is not optional: without a trust
# store TLS verification fails, and the tempting "fix" is --insecure-skip-verify,
# which must never be how this is solved.
RUN apk add --no-cache libcurl ca-certificates

# A numeric uid with no /etc/passwd entry would work under scratch, but this is
# a real Alpine base so a named account is clearer and still gives a writable
# HOME for the token cache if one is mounted.
RUN adduser -D -u 10001 -h /home/sfcc sfcc

COPY --from=build /src/build/bin/sfcc /usr/local/bin/sfcc

USER sfcc
WORKDIR /home/sfcc

ENTRYPOINT ["/usr/local/bin/sfcc"]
CMD ["--help"]