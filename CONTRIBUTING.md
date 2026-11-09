# Contributing to AgentGate

AgentGate is security software, so correctness and honest evidence come before
features.

1. **Every behaviour change needs a test** in `tests/test_core.py`, and, when it
   changes what is allowed or refused, a scenario in the evaluation.
2. **Never edit `evaluation/scenarios.py` to make a result pass.** The scenarios
   are frozen by their SHA-256 hash; new cases go in a new, separately frozen set.
3. **No claims without evidence.** `agentgate/regulatory.py` only lists tests,
   scenarios and files that prove the exact function claimed.
4. **Keep the licence notices.** Apache-2.0: keep `NOTICE` (the mcp-gate notice
   first), and keep the notice at the top of every changed file.
5. Run before proposing a change:

   ```bash
   python tests/test_core.py
   python tests/test_samples.py
   python -m agentgate.cli check --policy examples/policy.yaml
   python evaluation/run_eval.py --gate
   ```
