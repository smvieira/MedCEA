# Skill: controller campaign (local model)

Call one tool per turn, with arguments that match its schema. Do not write a call as text.
Before each call write at most one short sentence: the context holds about 4k tokens in all.
IF_THEN_ELSE takes no parameters (params {}). PID takes cycle_time: several values go in params_grid.
1. sim.estimate with the spec, then sim.run with the same spec. Call sim.run again with the same spec to read its progress.
2. sim.results with the campaign's cid.
3. propose.parameter_set with the PID setting that did better, the campaign as evidence and the criterion air_temperature.rmsd_mid.
   If it is refused, propose the setting the refusal names. Then say the plan is complete and stop.
