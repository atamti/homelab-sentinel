# Wazuh Configuration Reference

These files are **reference configurations** — not files to deploy wholesale.
Merge them into your existing Wazuh config selectively.

## Files

| File | Description |
|---|---|
| `local_rules.xml.example` | Custom rules for port monitoring and alert tuning |
| `ossec-active-response.xml.example` | Active response commands, rules, and IP whitelist |
| `generate_rules.py` | Generates port whitelist rules from `homelab-sentinel.yaml` |

## local_rules.xml

### Rule ID ranges

homelab-sentinel uses **100100–100299**. Adjust if these conflict with your existing custom rules.

The generator allocates IDs automatically:
- 100100+ — per-agent port whitelist rules (one per agent, stepping by 10)
- 100200 — catch-all for unexpected port changes (Level 12)

### Per-agent port whitelisting

Edit the `<hostname>` and `<match>` values to match your environment.
The example file covers two agents — add or remove blocks as needed.

The recommended workflow is to maintain your port whitelist in `homelab-sentinel.yaml` under `wazuh.port_whitelist` and regenerate the XML with `generate_rules.py`:

```bash
python3 wazuh/generate_rules.py > /tmp/new_port_rules.xml
# review the output
cat /tmp/new_port_rules.xml
# merge into your local_rules.xml
```

### YAML configuration

The `wazuh` section in `homelab-sentinel.yaml` controls rule generation:

```yaml
wazuh:
  unexpected_port_level: 12      # level assigned to rule 100200
  expected_port_rule_level: 3    # level assigned to whitelisted port rules
  port_whitelist:
    masterserver:
      - { port: 22,    proto: tcp, service: "SSH" }
      - { port: 443,   proto: tcp, service: "HTTPS" }
      # ... add your ports
    minibolt:
      - { port: 22,   proto: tcp, service: "SSH" }
      - { port: 8080, proto: tcp, service: "LND REST" }
      # ... add your ports
```

## ossec-active-response.xml

Contains the command definition and all active-response rule blocks for:
- SSH brute force (30-minute ban)
- Repeated auth failures (10-minute ban)
- Web attacks / SQL injection (1-hour ban)
- Rootkit detection (1-hour ban)
- Level 12 safety net (1-hour ban)
- IP whitelist template

### Timeout rationale

| Trigger | Timeout | Reasoning |
|---|---|---|
| SSH brute force (5763) | 30 min | Long enough to stop scanner, short enough to recover from false positive |
| Auth failures (5710/5711) | 10 min | Lighter trigger, lighter ban |
| Web attacks (31151/31153/31164) | 1 hour | Scanners retry quickly; short bans are ineffective |
| Rootkit (510) | 1 hour | High severity; gives time to investigate |
| Level 12 catch-all | 1 hour | Conservative default for unexpected events |

## generate_rules.py

Reads the `wazuh.port_whitelist` section from `homelab-sentinel.yaml` and outputs merge-ready XML rule blocks. Self-contained — no imports from `sentinel/`.

```bash
# Generate from default config location
python3 wazuh/generate_rules.py

# Generate from a specific config file
python3 wazuh/generate_rules.py --config /path/to/homelab-sentinel.yaml

# Output to file for review
python3 wazuh/generate_rules.py > /tmp/port_rules.xml
```

The output includes start/end comment markers for easy identification when merging.

## Verification

After merging rules into `/var/ossec/etc/rules/local_rules.xml`:

```bash
# Test rule parsing
sudo /var/ossec/bin/wazuh-logtest

# Restart manager to load new rules
sudo systemctl restart wazuh-manager

# Check for errors
sudo grep "Error" /var/ossec/logs/ossec.log
```

After merging active response into `/var/ossec/etc/ossec.conf`:

```bash
# Validate config
sudo /var/ossec/bin/wazuh-control info

# Restart manager
sudo systemctl restart wazuh-manager

# Verify active response is loaded
sudo grep "active-response" /var/ossec/logs/ossec.log
```
