# AS — Anti-Spam Gateway (ASG)

Python multi-stage anti-spam gateway per ASG Specifications / Algorithm / Architecture v1.0.

## Pipeline

1. Geo/CIDR hard reject
2. SPF / DKIM / DMARC
3. Reputation / RBL
4. Content heuristics + Bayesian classifier
5. Rate limiting
6. Score → **accept / quarantine / reject**
7. Optional **platform bridge** → Phase 0 Event + Decision Core

## Run

```bash
cd AS
python3 linux/asg_cli.py train-demo
python3 linux/asg_cli.py demo clean
python3 linux/asg_cli.py demo phish
python3 tests/test_asg.py
```

© VectorStryke
