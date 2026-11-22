# Skill: controller campaign (local model)

Call one tool per turn, with arguments that match its schema. Do not write a call as text.
1. lake.snapshots: see what the lake holds.
2. sim.estimate with the spec, then sim.run with the same spec. Call sim.run again with the same spec to read its progress and result.
3. propose.parameter_set with the PID setting that the campaign ran and the campaign as evidence. Then say the plan is complete and stop.
