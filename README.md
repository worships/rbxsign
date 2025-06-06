# rbxsign

`rbxsign` is a replacement for Roblox.KeyGenerator and similar projects, with full support for generating rbxsig2 certificates.

## Building

Building for debug targets:
```bash
cargo run build
```

Building for release targets:
```bash
cargo run build -r
```

## Usage
Powershell:
```ps
.\rbxsign.exe --bits [bits]
```

Bash:
```bash
./rbxsign --bits [bits]
```

### Available Bit Options

| Bits  | Signature Type         |
|-------|------------------------|
| 1024  | `rbxsig`               |
| 2048  | `rbxsig2` / `rbxsig4`  |
---
