# KeyAuth Protected Loader

This project is a secure loader application developed using the KeyAuth API. It includes advanced security measures and anti-debug techniques.

## Features

- ✨ Advanced Anti-Debug Protection
- 🛡️ Anti-VM Detection
- 🔒 Anti-Dump Protection
- 🕒 NTP Time Synchronization
- 🔑 License Verification System
- 💾 Encrypted License Storage in Registry
- 🔍 Continuous Security Monitoring
- 🎨 Modern Console Interface

## Security Features

- Debugger Detection
- Virtual Machine Detection
- Memory Dump Protection
- Code Integrity Check
- String Encryption
- Time Manipulation Detection
- Continuous Security Scanning

## Requirements

- Windows Operating System
- Visual Studio 2019 or higher
- KeyAuth
- Windows SDK

## Build Requirements

- Build Configuration: Release
- Platform: x64

## Installation

1. Clone the project:
```bash
git clone https://github.com/devc313/KeyAuth-Protected-Loader.git
```

2. Open the project in Visual Studio
3. Update your KeyAuth API information in `main.cpp`:
```cpp
Security::SecureString<32> NAME("your_name");
Security::SecureString<32> OWNERID("your_ownerid");
Security::SecureString<32> VERSION("your_version");
```

4. Set build configuration to Release x64
5. Build and run the project

## Usage

1. Run the program
2. Enter your license key
3. Select your desired operation from the menu

## Contributing

1. Fork this project
2. Create a new branch (`git checkout -b feature/amazing`)
3. Commit your changes (`git commit -m 'Add new feature'`)
4. Push to the branch (`git push origin feature/amazing`)
5. Create a Pull Request

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.

## Security

The security of this loader is continuously being improved. If you find a security vulnerability, please create an Issue.

## Contact

You can create an Issue for your questions or visit the project's GitHub page. 
