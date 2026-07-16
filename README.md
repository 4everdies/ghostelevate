# GhostElevate

UAC bypass builder for Windows. Feed it a .exe, get a `{name}-UAC.exe` back that elevates silently.
built with Go, tested on Win10 22H2.

## build
requires [Go](https://go.dev/dl/go1.26.5.windows-386.msi) installed.
```
set CGO_ENABLED=0
go build -ldflags="-s -w" -o ghostelevate.exe
```

## usage

```
ghostelevate.exe <target.exe> [options]
```

```
options:
  --technique <name>   build with a specific technique
  --list               list available techniques
```

### examples

```
ghostelevate.exe payload.exe
ghostelevate.exe payload.exe --technique icmluautil
ghostelevate.exe --list
```

double-click the generated `{name}-UAC.exe` and it runs the target as admin without the UAC prompt.

## how it works
the generated wrapper tries these in order:

1. COM elevation moniker (ICMLuaUtil) — zero footprint, no registry writes
2. fodhelper / computerdefaults / slui / silentcleanup registry hijacks
3. token manipulation — steals a token from an already-elevated process
registry hijack stuff only works if UAC is at Default level. if you have Always Notify on, only COM and token manipulation have a shot.
also strips Zone.Identifier so you don't get the "publisher not verified" warning.

## notes
- user has to be in the Administrators group already
- token manipulation works on Win7 through Win10 RS5 (17686). Win11 returns BAD_IMPERSONATION
- ICMLuaUtil might get patched down the line
- registry hijack techniques need Default UAC level
- the builder needs Go installed. the generated .exe does not.

## credits
@4everdies - UAC BYPASS
@ChatGPT - README.MD
@go community (bypasses)
