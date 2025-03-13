# Ignoring the `<namespace>` for Falco Alerts

## Installation and Usage

```sh
git clone <repository_url>
go run main.go <name_file.yaml> <namespace>
```

## Tutorial: Configuring Notifications from a Selected Namespace and Ignoring a Specific Namespace

### Step 1: Environment Setup
Install Falco, Helm, Minikube, and the required plugin:

- Follow the guide: [Falco K8sMeta Plugin](https://falco.org/blog/falco-k8smeta-plugin/)

### Step 2: Create a Telegram Bot
- Obtain the chat ID where the bot is located: [Get Updates](https://api.telegram.org/bot/getUpdates)

### Step 3: Create the Final `.yaml` Configuration
Example configuration file:

```yaml
driver:
  kind: modern_ebpf

falco:
  load_default_rules: false  
  rules_files:
    - /etc/falco/rules.d

falcosidekick:
  enabled: true
  config:
    telegram:
      chatid: "your_chatid"
      token: "your_token"

plugins:
  - name: k8smeta
    library_path: libk8smeta.so
    init_config:
      collectorPort: 45000  # (required)
      collectorHostname: localhost  # (required)
      nodeName: kind-control-plane  # (required)
      verbosity: warning  # (optional, default: info)
      caPEMBundle: /etc/ssl/certs/ca-certificates.crt  # (optional)
      hostProc: /host  # (optional, default: /host)

load_plugins: [k8smeta]

kubernetes:
  enabled: true

customRules:
  rules.yaml: |-    
    # Your custom rule
  default_rules_mod: |-
    # Insert the corrected default rules obtained from the script
```

