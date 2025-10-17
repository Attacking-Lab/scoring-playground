import json
import sys
import scoring_playground

with open("ctfs/ecsc2024/scores.json") as file:
    round_scores = json.load(file)

ctf = scoring_playground.data.ECSC2024.load()
formula = scoring_playground.scoring.ECSC2024()
for r, expected in zip(range(len(ctf.rounds)+1), round_scores):
    print("ROUND", r, file=sys.stderr)
    scoreboard = formula.evaluate(ctf.slice(0, r))
    zipped = [(k,scoreboard[k],expected[k]) for k in scoreboard]
    assert len(zipped) == len(expected)
    if not all(round(v1.combined, 5) == round(v2["combined"], 5) for _,v1,v2 in zipped):
        for k,v1,v2 in zipped:
            if round(v1.combined, 5) != round(v2["combined"], 5):
                print(r, k, v1.combined, v2["combined"], v2["meta"])
        raise ValueError(f"Scores do not match for round {r}")
