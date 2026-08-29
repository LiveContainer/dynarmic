// SPDX-FileCopyrightText: Copyright (c) 2024 merryhime <https://mary.rs>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdlib>
#include <memory>

#include "oaknut/code_block.hpp"

#if defined(__APPLE__)
#    include "oaknut/dual_code_block.hpp"
#endif

namespace oaknut {

class ConfigurableCodeBlock {
public:
    // The environment must be configured before Dynarmic is loaded because
    // some code blocks are constructed during static initialization. On Apple
    // hosts, presence of DYNARMIC_DUAL_MAPPED opts into separate RW and RX
    // aliases. Other hosts retain their existing single-mapping behavior.
    explicit ConfigurableCodeBlock(std::size_t size) {
#if defined(__APPLE__)
        const std::size_t allocation_size = round_page(size);
        bool use_dual_mapping = std::getenv("DYNARMIC_DUAL_MAPPED") != nullptr;
        if (!use_dual_mapping)
            use_dual_mapping = detail::RunningOnIOS26OrLater();
        if (use_dual_mapping) {
            m_dual_code = std::make_unique<DualCodeBlock>(allocation_size);
            return;
        }
        m_single_code = std::make_unique<CodeBlock>(allocation_size);
#else
        m_single_code = std::make_unique<CodeBlock>(size);
#endif
    }

    ~ConfigurableCodeBlock() = default;

    ConfigurableCodeBlock(const ConfigurableCodeBlock&) = delete;
    ConfigurableCodeBlock& operator=(const ConfigurableCodeBlock&) = delete;
    ConfigurableCodeBlock(ConfigurableCodeBlock&&) = delete;
    ConfigurableCodeBlock& operator=(ConfigurableCodeBlock&&) = delete;

    bool is_dual_mapped() const
    {
#if defined(__APPLE__)
        return static_cast<bool>(m_dual_code);
#else
        return false;
#endif
    }

    void protect()
    {
        if (m_single_code) {
            m_single_code->protect();
        }
    }

    void unprotect()
    {
        if (m_single_code) {
            m_single_code->unprotect();
        }
    }

    /// Pointer to executable memory (permissions: R-X while protected).
    std::uint32_t* xptr() const
    {
#if defined(__APPLE__)
        if (m_dual_code) {
            return m_dual_code->xptr();
        }
#endif
        return m_single_code->ptr();
    }

    /// Pointer to writable memory (permissions: RW- while unprotected).
    std::uint32_t* wptr() const
    {
#if defined(__APPLE__)
        if (m_dual_code) {
            return m_dual_code->wptr();
        }
#endif
        return m_single_code->ptr();
    }

    /// Invalidate should be used with executable memory pointers.
    void invalidate(std::uint32_t* mem, std::size_t size)
    {
#if defined(__APPLE__)
        if (m_dual_code) {
            m_dual_code->invalidate(mem, size);
            return;
        }
#endif
        m_single_code->invalidate(mem, size);
    }

    void invalidate_all()
    {
#if defined(__APPLE__)
        if (m_dual_code) {
            m_dual_code->invalidate_all();
            return;
        }
#endif
        m_single_code->invalidate_all();
    }

private:
    std::unique_ptr<CodeBlock> m_single_code;
#if defined(__APPLE__)
    std::unique_ptr<DualCodeBlock> m_dual_code;
#endif
};

}  // namespace oaknut
