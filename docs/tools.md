# Tools

Generated from the tool catalogue by `ha-airlock tools`. Do not edit; a test
fails when this file and the catalogue differ.

Every tool belongs to one risk tier and touches only the Home Assistant
endpoints listed for it. There are no other tools, and none can be added
at run time.

| Tool | Tier | What it does | Home Assistant endpoints |
| --- | --- | --- | --- |
| `system_log_list` | R0 | Returns the errors and warnings Home Assistant Core has collected since it started, newest first: logger name, message, level, source, count and timestamps. | `websocket: system_log/list` |
| `repairs_list_issues` | R0 | Returns the issues Home Assistant's Repairs dashboard lists: the integration, severity, whether the issue is fixable or ignored, and the version in which it breaks. | `websocket: repairs/list_issues` |
| `config_entries_list` | R0 | Returns the configured integrations (config entries) with their state, for example loaded, setup_error or setup_retry, and the reason of a failure. Optionally for one integration domain. | `websocket: config_entries/get` |
| `trace_list` | R0 | Returns summaries of the stored runs of automations or scripts: when a run started and finished, how it ended, and its error if it failed. Optionally for one automation or script. | `websocket: trace/list` |
| `logbook_events` | R0 | Returns logbook entries of a period of time, oldest first: state changes, automation runs and service calls, with the entity, the time and what caused them. Optionally for certain entities. | `websocket: logbook/get_events` |
| `light_turn_on` | R1 | Calls the service light.turn_on on one entity of the domain light. The entity must be released for control by the owner. Depending on the policy the call waits for the owner's approval: it then returns without having run, and runs when it is repeated with the same arguments after the approval. | `websocket: call_service (light.turn_on)` |
| `light_turn_off` | R1 | Calls the service light.turn_off on one entity of the domain light. The entity must be released for control by the owner. Depending on the policy the call waits for the owner's approval: it then returns without having run, and runs when it is repeated with the same arguments after the approval. | `websocket: call_service (light.turn_off)` |
| `switch_turn_on` | R1 | Calls the service switch.turn_on on one entity of the domain switch. The entity must be released for control by the owner. Depending on the policy the call waits for the owner's approval: it then returns without having run, and runs when it is repeated with the same arguments after the approval. | `websocket: call_service (switch.turn_on)` |
| `switch_turn_off` | R1 | Calls the service switch.turn_off on one entity of the domain switch. The entity must be released for control by the owner. Depending on the policy the call waits for the owner's approval: it then returns without having run, and runs when it is repeated with the same arguments after the approval. | `websocket: call_service (switch.turn_off)` |
| `input_boolean_turn_on` | R1 | Calls the service input_boolean.turn_on on one entity of the domain input_boolean. The entity must be released for control by the owner. Depending on the policy the call waits for the owner's approval: it then returns without having run, and runs when it is repeated with the same arguments after the approval. | `websocket: call_service (input_boolean.turn_on)` |
| `input_boolean_turn_off` | R1 | Calls the service input_boolean.turn_off on one entity of the domain input_boolean. The entity must be released for control by the owner. Depending on the policy the call waits for the owner's approval: it then returns without having run, and runs when it is repeated with the same arguments after the approval. | `websocket: call_service (input_boolean.turn_off)` |
