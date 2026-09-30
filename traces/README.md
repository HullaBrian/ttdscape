# traces/

Put your own TTD recordings (`.run`) here. The viewer's **Open trace** dialog lists them, and
`npm run test:integration` runs the model-invariant smoke test on each one.

Recordings are never committed (see `.gitignore`), for two reasons:
- a trace embeds the recording machine's environment: user name, paths and environment variables;
- samples may be malware.

Record a process with the TTD command line (elevated):

```powershell
ttd.exe -out C:\path\to\ttdscape\traces -launch C:\path\to\program.exe
```

Analyze malware only in an isolated machine or VM. TTDscape never runs the traced program, but the
CAPA pass writes memory snapshots of it to disk. See `SECURITY.md`.
