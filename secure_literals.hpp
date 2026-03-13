#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace anonsec {
namespace detail {

constexpr std::uint32_t rotl32(std::uint32_t value, unsigned shift) {
    return (value << shift) | (value >> (32U - shift));
}

constexpr std::uint32_t time_seed() {
    return static_cast<std::uint32_t>(
        (__TIME__[0] - '0') * 36000 +
        (__TIME__[1] - '0') * 3600 +
        (__TIME__[3] - '0') * 600 +
        (__TIME__[4] - '0') * 60 +
        (__TIME__[6] - '0') * 10 +
        (__TIME__[7] - '0')
    );
}

template <std::uint32_t Salt>
constexpr std::uint32_t compile_seed() {
    std::uint32_t value = 0x9E3779B9u ^ time_seed() ^ (Salt * 0x85EBCA6Bu);
    value ^= static_cast<std::uint32_t>(__LINE__) * 0x27D4EB2Fu;
    value = rotl32(value, 13);
    value *= 0xC2B2AE35u;
    return value ^ (value >> 16);
}

constexpr std::uint32_t mix(std::uint32_t v, std::uint32_t key, std::size_t idx, std::size_t layer) {
    v ^= key + static_cast<std::uint32_t>(idx * 0x45D9F3Bu + layer * 0x119DE1F3u);
    v = rotl32(v, static_cast<unsigned>(((idx + layer) % 13U) + 5U));
    v ^= (key >> ((idx + layer) % 17U));
    return v;
}

constexpr std::uint32_t unmix(std::uint32_t v, std::uint32_t key, std::size_t idx, std::size_t layer) {
    v ^= (key >> ((idx + layer) % 17U));
    const auto shift = static_cast<unsigned>(((idx + layer) % 13U) + 5U);
    v = (v >> shift) | (v << (32U - shift));
    v ^= key + static_cast<std::uint32_t>(idx * 0x45D9F3Bu + layer * 0x119DE1F3u);
    return v;
}

template <typename CharT>
inline void secure_wipe(CharT* data, std::size_t size) {
    volatile CharT* ptr = data;
    for (std::size_t i = 0; i < size; ++i) {
        ptr[i] = static_cast<CharT>(0);
    }
}

} // namespace detail

template <typename CharT, std::size_t N, std::uint32_t Seed, std::size_t Layers>
class basic_encrypted_string {
public:
    constexpr explicit basic_encrypted_string(const CharT (&plain)[N]) : encrypted_{} {
        for (std::size_t i = 0; i < N; ++i) {
            std::uint32_t v = static_cast<std::uint32_t>(plain[i]);
            for (std::size_t layer = 0; layer < Layers; ++layer) {
                v = detail::mix(v, key_for(layer), i, layer);
            }
            encrypted_[i] = static_cast<CharT>(v & value_mask());
        }
    }

    const CharT* decrypt() const {
        if (!decrypted_) {
            for (std::size_t i = 0; i < N; ++i) {
                std::uint32_t v = static_cast<std::uint32_t>(encrypted_[i]);
                for (std::size_t layer = Layers; layer-- > 0;) {
                    v = detail::unmix(v, key_for(layer), i, layer);
                }
                cache_[i] = static_cast<CharT>(v & value_mask());
            }
            decrypted_ = true;
        }
        return cache_.data();
    }

    const CharT* c_str() const { return decrypt(); }
    operator const CharT*() const { return decrypt(); }

    void secure_clear_cache() const {
        detail::secure_wipe(cache_.data(), N);
        decrypted_ = false;
    }

private:
    static constexpr std::uint32_t value_mask() {
        return sizeof(CharT) == 1 ? 0xFFu : 0xFFFFu;
    }

    static constexpr std::uint32_t key_for(std::size_t layer) {
        auto k = Seed ^ static_cast<std::uint32_t>((layer + 1) * 0x9E3779B9u);
        k = detail::rotl32(k, static_cast<unsigned>((layer % 11U) + 3U));
        return k ^ static_cast<std::uint32_t>(layer * 0x7F4A7C15u);
    }

    std::array<CharT, N> encrypted_;
    mutable std::array<CharT, N> cache_{};
    mutable bool decrypted_{ false };
};

template <std::uint32_t Salt, std::size_t Layers, typename CharT, std::size_t N>
constexpr auto make_encrypted(const CharT (&plain)[N]) {
    return basic_encrypted_string<CharT, N, detail::compile_seed<Salt>(), Layers>(plain);
}

template <std::uint32_t Salt, typename CharT, std::size_t N>
class stack_string {
public:
    explicit stack_string(const CharT (&plain)[N])
        : impl_(make_encrypted<Salt, 2>(plain)) {
        const CharT* decrypted = impl_.decrypt();
        for (std::size_t i = 0; i < N; ++i) {
            buffer_[i] = decrypted[i];
        }
        impl_.secure_clear_cache();
    }

    ~stack_string() {
        detail::secure_wipe(buffer_.data(), N);
    }

    const CharT* c_str() const { return buffer_.data(); }
    operator const CharT*() const { return c_str(); }

private:
    basic_encrypted_string<CharT, N, detail::compile_seed<Salt>(), 2> impl_;
    std::array<CharT, N> buffer_{};
};

template <std::uint32_t Salt, typename CharT, std::size_t N>
stack_string<Salt, CharT, N> make_stack_string(const CharT (&plain)[N]) {
    return stack_string<Salt, CharT, N>(plain);
}

} // namespace anonsec

#define CW_STR(s) ([]() -> auto& { static auto _s = ::anonsec::make_encrypted<__COUNTER__, 1>(s); return _s; }())
#define CW_STR_LAYERED(s) ([]() -> auto& { static auto _s = ::anonsec::make_encrypted<__COUNTER__, 3>(s); return _s; }())
#define CW_STR_STACK(s) ::anonsec::make_stack_string<__COUNTER__>(s)
#define CW_WSTR(s) ([]() -> auto& { static auto _s = ::anonsec::make_encrypted<__COUNTER__, 2>(s); return _s; }())
#define CW_STACK_STR(name, ...) char name[] = { __VA_ARGS__, '\0' }
