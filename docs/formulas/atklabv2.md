# ATKLAB v2

In Jeopardy CTFs, dynamic scoring is scoring is used to infer the difficulty
of a challenge by the number of teams who are able to solve it. We want to
apply this concept to A/D, because (1) it removes the need to manually
weight services to address differences in exploiting / patching difficulty,
and (2) because it helps keep the proportion between teams scores in the A/D
scoreboard similar to that of a Jeopardy scoreboard, which allows for easier
merging in competitions with both an A/D and a Jeopardy part.

## Summary

In effect, each round is treated as a Jeopardy CTF with the following challenges:

- For each service and each flagstore, you receive **DEF points** for each
  actively exploiting team that you did not get your flag captured by,
  proportional to the amount of teams whose flag that team did capture.
- For each flag you capture, you receive **ATK points** based on the number
  of teams that also managed to captured that flag.

Additionally, you gain a **fixed amount of SLA points** for each flag available
from the *retention period*, as long as the checker status is `OK` or `RECOVERING`.

## Review

- Since the capture count of each stored flag determines its worth,
  attackers are rewarded based on how difficult it is to exploit each specific team.
- The same goes for defense; a patch is rewarded based on the amount of other
  teams which were not able to defend againt the exploiting team.
- Not attacking a team effectively gives that team defense points, thus there
  is an incentive to attack everyone beyond attack points. Teams will need to
  decide if the points gained from not attacking a team offset the expected
  loss of having the exploit stolen from their traffic.

