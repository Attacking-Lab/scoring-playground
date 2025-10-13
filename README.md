# Scoring Playground

A tool for simulating A/D scoring formulas against real data.

```
usage: scoring-playground [-h]
                          --data {ECSC2024,ECSC2025,ENOWARS2024,FaustCTF2024,SaarCTF2024}
                          --formula {ATKLABv1,ATKLABv2,ECSC2024,ECSC2025,SaarCTF2024}
                          [--output-format {json,table}]
                          [--from-round FROM_ROUND] [--to-round TO_ROUND]
                          [--scale-to SCALE_TO]

options:
  -h, --help            show this help message and exit
  --data {ECSC2024,ECSC2025,ENOWARS2024,FaustCTF2024,SaarCTF2024}
                        Selects the CTF data source
  --formula {ATKLABv1,ATKLABv2,ECSC2024,ECSC2025,SaarCTF2024}
                        Selects the scoring formula
  --output-format {json,table}
                        Output format
  --from-round FROM_ROUND
                        Assume the CTF started in this round (this round is
                        included in scoring)
  --to-round TO_ROUND   Assume the CTF ended in this round (this round is
                        included in scoring)
  --scale-to SCALE_TO   Scale the final scoreboard to this maximum point count

```

For example:

```
uv run scoring-playground --data ECSC2025 --formula ECSC2025
```
