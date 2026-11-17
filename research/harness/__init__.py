"""The closed-loop simulation harness (RS.3): production's controllers and loop rules,
loaded by path, run against research/twin_plant. Standard library + PyYAML only; FLC and
MPC run their real code paths only where numpy/scikit-fuzzy/gekko are installed
(research/.venv), and a run that fell back to bang-bang is marked invalid."""
