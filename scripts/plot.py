#!/bin/sh
from matplotlib.lines import Line2D

import os
import json

import matplotlib.pyplot as plt
from collections import defaultdict

attacking = [defaultdict(lambda: False) for i in range(2)]
d = [[], []]
for f in sorted(os.listdir("out"), key=lambda v: 0 if "-" not in v else int(v.split("-")[1].split(".")[0])):
  if f.startswith("jeopardy-") or f.startswith("saarctf-"):
    x = int(f.split("-")[1].split(".")[0])
    c = int(f.split("-")[0] == "jeopardy")
    data = json.load(open(f"out/{f}"))
    teams = sorted(list(data.keys()))
    for i, team in enumerate(teams):
      attacking[c][i] = attacking[c][i] or data[team]["categories"]["ATK"] > 0
    d[c].append([(x, data[team]["combined"]) for team in teams])
    
data1, data2 = [list(zip(*dd)) for dd in d]
max1 = max(max(y for _,y in line) for line in data1)
max2 = max(max(y for _,y in line) for line in data2)

plt.figure(figsize=(10, 6))
for i,line in enumerate(data1):
  x,y = zip(*line)
  plt.plot(x, y, color="lightblue" if not attacking[0][i] else "blue", alpha=0.5)
for i,line in enumerate(data2):
  line = [(x, y / max2 * max1) for x,y in line]
  x,y = zip(*line)
  plt.plot(x, y, color="orange" if not attacking[1][i] else "red", alpha=0.5)
plt.xlabel("Rounds")
plt.ylabel("Points")
plt.title("Scoring Formula Comparison")
plt.legend(handles=[
  Line2D([0], [0], color='blue', lw=4, label='SaarCTF 2024'),
  Line2D([0], [0], color='red', lw=4, label='ATKLAB v2')])
plt.grid(True)
plt.show()
