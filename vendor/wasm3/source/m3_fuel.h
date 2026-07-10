// swerver fuel patch externs (design 10.0 resource-bounding).
//
// Upstream wasm3 ships no fuel/op-count metering. swerver adds a minimal
// localized patch: a fuel counter charged once per loop back-edge in op_Loop
// (m3_exec.h), trapping when exhausted. This bounds a runaway guest filter,
// which is mandatory because the reactor is single-threaded (a runaway filter
// otherwise wedges the whole worker, and a housekeeping-tick deadline cannot
// fire while the guest spins).
//
// swerver forks one process per worker with a single-threaded event loop, so a
// plain process-global counter is correct here (no threads to share it across).
// Defined in m3_core.c, charged in m3_exec.h, driven from src/wasm/runtime.zig.
#ifndef M3_FUEL_H
#define M3_FUEL_H
#include <stdint.h>
extern int64_t m3_swerver_fuel;           // decremented per loop iteration
extern const char* const m3Err_trapFuel;  // trap message when exhausted
#endif
