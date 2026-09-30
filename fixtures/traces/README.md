# fixtures/traces/

Recordings of the test fixture (`fixtures/app/fixture.cpp`) and their ground truth. The fixture
writes the ground truth itself. They are not committed, because a recording embeds the machine's
environment. Create them with (a UAC prompt appears):

```powershell
powershell -ExecutionPolicy Bypass -File fixtures\record-fixture.ps1            # x64 -> fixture01.run + fixture01.truth.json
powershell -ExecutionPolicy Bypass -File fixtures\record-fixture.ps1 -Arch x86  # WoW64 -> fixture86.run + fixture86.truth.json
```

`tests/integration/fixture.test.mjs` then checks the analyzer's model against the truth exactly;
without the recordings those tests are skipped.
