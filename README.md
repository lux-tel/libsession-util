# Lux Session Utility Library

> Fork of [libsession-util](https://github.com/session-foundation/libsession-util) for Lux Network integration

## Overview

This is the core C++ library that handles Session protocol operations including:
- Configuration management
- Encryption/decryption
- Network communication (onion requests)
- Protocol encoding/decoding

## Current Status

**Integration Status: Needs Modification**

This library contains hardcoded network endpoints for the Session/Oxen network. To enable Lux Network connectivity, the following changes are needed:

### Required Modifications

1. **Network Configuration** (`src/session_network.cpp`)
   - Make seed node URLs configurable
   - Add runtime network selection
   - Support environment-based configuration

2. **File Server** (`src/session_network.cpp:250`)
   ```cpp
   // Current: hardcoded
   constexpr auto file_server = "filev2.getsession.org"sv;

   // Needed: configurable
   std::string file_server = get_config("LUX_FILE_SERVER", "filev2.getsession.org");
   ```

3. **Protocol URLs** (`src/session_protocol.cpp`)
   - Update hardcoded getsession.org URLs
   - Make URLs configurable or update to lux.network equivalents

## Build

```bash
# Configure the build
cmake -G Ninja -S . -B Build

# Options:
#   -D ENABLE_ONIONREQ           # Enable onion request APIs
#   -D LUX_NETWORK=1             # Enable Lux network configuration (TODO)

# Regenerate protobuf files
cmake --build Build --target regen-protobuf --parallel --verbose

# Build
cmake --build Build --parallel --verbose
```

## Usage

### C API

```c
#include <session/session_encrypt.h>

// Encrypt a message
session_encrypt(...);
```

### C++ API

```cpp
#include <session/session_encrypt.hpp>

// Use session utilities
session::encrypt(...);
```

## Integration Points

This library is used by:
- [lux-tel/session-ios](https://github.com/lux-tel/session-ios) - iOS app (Swift/ObjC bindings)
- [lux-tel/session-android](https://github.com/lux-tel/session-android) - Android app (JNI bindings)
- [lux-tel/session-desktop](https://github.com/lux-tel/session-desktop) - Uses Node.js bindings

## Related Repositories

| Repository | Description |
|------------|-------------|
| [luxfi/session](https://github.com/luxfi/session) | Go SessionVM + API layer |
| [luxcpp/session](https://github.com/luxcpp/session) | C++ storage server |
| [lux-tel/session-desktop](https://github.com/lux-tel/session-desktop) | Desktop client |
| [lux-tel/session-ios](https://github.com/lux-tel/session-ios) | iOS client |
| [lux-tel/session-android](https://github.com/lux-tel/session-android) | Android client |

## Architecture

```
libsession-util/
├── include/session/       # Public headers
│   ├── session_encrypt.h  # Encryption APIs
│   ├── session_network.h  # Network APIs
│   └── config/            # Configuration handling
├── src/
│   ├── session_network.cpp    # Network implementation (needs modification)
│   ├── session_protocol.cpp   # Protocol constants
│   └── ...
├── proto/                 # Protobuf definitions
└── external/              # Dependencies
```

## Documentation

- C Library: https://api.oxen.io/libsession-util-c/#/
- C++ Library: https://api.oxen.io/libsession-util-cpp/#/

## License

GPL-3.0

## Upstream

This project is a fork of [libsession-util](https://github.com/session-foundation/libsession-util) by the Session Technology Foundation.
