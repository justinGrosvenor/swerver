/* Spike shim: Zig's translate-c (@cImport) does not take wasm3_defs.h's clang
 * bswap branch, so the header falls through to `#include <endian.h>`, which does
 * not exist on macOS. This shim satisfies that include with __builtin bswaps so
 * @cImport succeeds. The actual .c files are compiled by zig cc (clang), take
 * the clang builtin branch, and never include this. Harmless either way. */
#ifndef WASM3_SHIM_ENDIAN_H
#define WASM3_SHIM_ENDIAN_H
#include <stdint.h>
#define __bswap_16(x) __builtin_bswap16((uint16_t)(x))
#define __bswap_32(x) __builtin_bswap32((uint32_t)(x))
#define __bswap_64(x) __builtin_bswap64((uint64_t)(x))
#endif
