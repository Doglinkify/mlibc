#pragma once

#include <nr.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

uint64_t enter_syscall(
    uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t idx
);
