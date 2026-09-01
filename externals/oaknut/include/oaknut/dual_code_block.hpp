// SPDX-FileCopyrightText: Copyright (c) 2024 merryhime <https://mary.rs>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <new>

#if defined(_WIN32)
#    define NOMINMAX
#    include <windows.h>
#elif defined(__APPLE__)
#    include <mach/mach.h>
#    include <mach/vm_map.h>
#    include <mach-o/loader.h>

#    include <CoreFoundation/CoreFoundation.h>
#    include <IOKit/IOKitLib.h>
#    include <TargetConditionals.h>
#    include <libkern/OSCacheControl.h>
#    include <pthread.h>
#    include <sys/mman.h>
#    include <unistd.h>
#else
#    if !defined(_GNU_SOURCE)
#        define _GNU_SOURCE
#    endif
#    include <sys/mman.h>
#    include <sys/types.h>
#    include <unistd.h>
#endif

#if defined(__APPLE__)
extern "C" std::uint32_t dyld_get_active_platform(void);
#endif

namespace oaknut {

#if defined(__APPLE__)
namespace detail {

inline bool RunningOnPhysicalIOS()
{
    return dyld_get_active_platform() == PLATFORM_IOS;
}

inline bool RunningOnIOS26OrLater()
{
    if (!RunningOnPhysicalIOS())
        return false;

    if (__builtin_available(iOS 19.0, *))
        return true;
    return false;
}

inline bool RequiresDualMapping()
{
    if (!RunningOnPhysicalIOS())
        return false;

    // Skip dual mapping on jailbroken devices(?)
    if (::access("/usr/lib/systemhook.dylib", F_OK) == 0)
        return false;

    return RunningOnIOS26OrLater();
}

}  // namespace detail
#endif

class DualCodeBlock {
public:
    explicit DualCodeBlock(std::size_t size)
        : m_size(size)
    {
#if defined(_WIN32)
        m_wmem = m_xmem = (std::uint32_t*)VirtualAlloc(nullptr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (m_wmem == nullptr)
            throw std::bad_alloc{};
#elif defined(__APPLE__)
        m_xmem = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
        if (m_xmem == MAP_FAILED)
            throw std::bad_alloc{};

        if (DeviceHasTXM()) {
            if (detail::RunningOnIOS26OrLater()) {
                JIT26PrepareRegion(m_xmem, m_size);
            } else if (detail::RunningOnPhysicalIOS() &&
                       !PreparePreIOS26TXMRegion()) {
                munmap(m_xmem, m_size);
                throw std::bad_alloc{};
            }
        }

        vm_address_t wmem = 0;
        vm_prot_t cur_prot, max_prot;
        kern_return_t ret = vm_remap(mach_task_self(), &wmem, size, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR, mach_task_self(), reinterpret_cast<vm_address_t>(m_xmem), false, &cur_prot, &max_prot, VM_INHERIT_NONE);
        if (ret != KERN_SUCCESS) {
            munmap(m_xmem, m_size);
            throw std::bad_alloc{};
        }
        m_wmem = reinterpret_cast<std::uint32_t*>(wmem);

        if (mprotect(m_wmem, size, PROT_READ | PROT_WRITE) != 0) {
            munmap(m_xmem, m_size);
            munmap(m_wmem, m_size);
            throw std::bad_alloc{};
        }
#else
#    if defined(__OpenBSD__)
        char tmpl[] = "oaknut_dual_code_block.XXXXXXXXXX";
        fd = shm_mkstemp(tmpl);
        if (fd < 0)
            throw std::bad_alloc{};
        shm_unlink(tmpl);
#    else
        fd = memfd_create("oaknut_dual_code_block", 0);
        if (fd < 0)
            throw std::bad_alloc{};
#    endif

        int ret = ftruncate(fd, size);
        if (ret != 0)
            throw std::bad_alloc{};

        m_wmem = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        m_xmem = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);

        if (m_wmem == MAP_FAILED || m_xmem == MAP_FAILED)
            throw std::bad_alloc{};
#endif
    }

    ~DualCodeBlock()
    {
#if defined(_WIN32)
        VirtualFree((void*)m_xmem, 0, MEM_RELEASE);
#elif defined(__APPLE__)
        munmap(m_xmem, m_size);
        munmap(m_wmem, m_size);
#else
        munmap(m_wmem, m_size);
        munmap(m_xmem, m_size);
        close(fd);
#endif
    }

    DualCodeBlock(const DualCodeBlock&) = delete;
    DualCodeBlock& operator=(const DualCodeBlock&) = delete;
    DualCodeBlock(DualCodeBlock&&) = delete;
    DualCodeBlock& operator=(DualCodeBlock&&) = delete;

    /// Pointer to executable mirror of memory (permissions: R-X)
    std::uint32_t* xptr() const
    {
        return m_xmem;
    }

    /// Pointer to writeable mirror of memory (permissions: RW-)
    std::uint32_t* wptr() const
    {
        return m_wmem;
    }

    /// Invalidate should be used with executable memory pointers.
    void invalidate(std::uint32_t* mem, std::size_t size)
    {
#if defined(__APPLE__)
        sys_icache_invalidate(mem, size);
#elif defined(_WIN32)
        FlushInstructionCache(GetCurrentProcess(), mem, size);
#else
        static std::size_t icache_line_size = 0x10000, dcache_line_size = 0x10000;

        std::uint64_t ctr;
        __asm__ volatile("mrs %0, ctr_el0"
                         : "=r"(ctr));

        const std::size_t isize = icache_line_size = std::min<std::size_t>(icache_line_size, 4 << ((ctr >> 0) & 0xf));
        const std::size_t dsize = dcache_line_size = std::min<std::size_t>(dcache_line_size, 4 << ((ctr >> 16) & 0xf));

        const std::uintptr_t end = (std::uintptr_t)mem + size;

        for (std::uintptr_t addr = ((std::uintptr_t)mem) & ~(dsize - 1); addr < end; addr += dsize) {
            __asm__ volatile("dc cvau, %0"
                             :
                             : "r"(addr)
                             : "memory");
        }
        __asm__ volatile("dsb ish\n"
                         :
                         :
                         : "memory");

        for (std::uintptr_t addr = ((std::uintptr_t)mem) & ~(isize - 1); addr < end; addr += isize) {
            __asm__ volatile("ic ivau, %0"
                             :
                             : "r"(addr)
                             : "memory");
        }
        __asm__ volatile("dsb ish\nisb\n"
                         :
                         :
                         : "memory");
#endif
    }

    void invalidate_all()
    {
        invalidate(m_xmem, m_size);
    }

protected:
#if !defined(_WIN32) && !defined(__APPLE__)
    int fd = -1;
#endif
    std::uint32_t* m_xmem = nullptr;
    std::uint32_t* m_wmem = nullptr;
    std::size_t m_size = 0;

#if defined(__APPLE__)
    bool PreparePreIOS26TXMRegion() const {
        // iOS 17 and 18 require every page in the executable backing to be
        // materialized before vm_remap creates its writable alias.  Retain
        // W^X while doing so: fault the pages through a temporary RW mapping,
        // then restore the original RX protection before continuing.
        if (mprotect(m_xmem, m_size, PROT_READ | PROT_WRITE) != 0)
            return false;

        volatile std::uint8_t* const bytes =
            reinterpret_cast<volatile std::uint8_t*>(m_xmem);
        const std::size_t page_size =
            static_cast<std::size_t>(getpagesize());
        for (std::size_t offset = 0; offset < m_size;
             offset += page_size) {
            const std::uint8_t value = bytes[offset];
            bytes[offset] = value;
        }

        return mprotect(m_xmem, m_size, PROT_READ | PROT_EXEC) == 0;
    }

    bool DeviceHasTXM() const {
        // https://github.com/opa334/Dopamine/commit/e8438b4a64ead3997d2c70a575431cb1b4070fb9
        io_registry_entry_t memory_map = IORegistryEntryFromPath(0, "IODeviceTree:/chosen/memory-map");
        if (memory_map == IO_OBJECT_NULL)
            return false;
        
        CFArrayRef keys = (CFArrayRef)IORegistryEntryCreateCFProperty(memory_map, CFSTR(kIORegistryEntryPropertyKeysKey), 0, 0);
        IOObjectRelease(memory_map);
        if (!keys)
            return false;
        
        CFRange range = CFRangeMake(0, CFArrayGetCount(keys));
        bool hasTXM = CFArrayContainsValue(keys, range, CFSTR("SPTM")) && CFArrayContainsValue(keys, range, CFSTR("TXM"));
        CFRelease(keys);
        return hasTXM;
    }
    
    __attribute__((noinline,optnone,naked))
    void JIT26PrepareRegion(void *addr, std::size_t len) const {
        asm("mov x0, x1 \n"
            "mov x1, x2 \n"
            "mov x16, #1 \n"
            "brk #0xf00d \n"
            "ret");
    }
#endif
};

}  // namespace oaknut
