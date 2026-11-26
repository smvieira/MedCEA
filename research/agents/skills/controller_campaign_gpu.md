# Skill: controller campaign (an endpoint with a larger context)

Call one tool per turn, with arguments that match its schema. Do not write a call as text.
Before each call, write one or two sentences on what you are doing and why.
IF_THEN_ELSE takes no parameters (params {}). A parameter with several values goes in params_grid; a controller
without params runs with its defaults.

1. sim.estimate with the spec, then sim.run with the same spec. Call sim.run again with the same spec to read its
   progress until it is done.
2. sim.results with the campaign's cid and sort set to your criterion. by_setting has one row per setting, in
   its columns' order, with the mean over its valid runs, best first; take every number you quote from it.
3. propose.parameter_set with the setting you judge best, the campaign's cid as evidence and the criterion you
   judged it on (lower is better). mcp-sim compares your setting with every other setting of the campaign on the
   runs they share and refuses a proposal that another setting beats on that criterion; its refusal names that
   setting and both numbers. If refused, propose the setting it names, with the same evidence and criterion.
4. Once a proposal is accepted, say the plan is complete and stop. Quote numbers only from tool results.
