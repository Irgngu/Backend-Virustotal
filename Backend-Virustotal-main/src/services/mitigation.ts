

export interface NormalizedIndicator {
  type: string;
  vt_score: number;
  vt_total: number;
  abuse_score: number;
  misp_confidence: "High" | "Medium" | "Low" | string;
  tags: string[];
  malware_family?: string | null;
  threat_category?: string | null;
  source?: string | null;
}

export interface MitigationAction {
  id: string;
  name: string;
  description: string;
  framework: string;
}

export interface TechniqueMatch {
  technique: string;
  techniqueName: string;
  tactic: string;
  confidence: number;
  reasons: string[];
}

export interface TechniqueEntry {
  technique: string;
  name: string;
  tactic: string;
  score: (n: NormalizedIndicator) => number;
  reasons: (n: NormalizedIndicator) => string[];
  mitigations: MitigationAction[];
}

export interface ThreatIntelResult {
  primaryTechnique: string | null;
  primaryTechniqueName: string | null;
  techniques: TechniqueMatch[];
  mitigations: MitigationAction[];
  cve: string | null;
  cwe: string | null;
}

// ================================================================
// Helpers
// ================================================================

function hasTag(n: NormalizedIndicator, values: string[]): boolean {
  return values.some((v) =>
    n.tags?.map((t) => t.toLowerCase()).includes(v.toLowerCase()),
  );
}

function hasTagPartial(n: NormalizedIndicator, partials: string[]): boolean {
  return partials.some((p) =>
    n.tags?.some((t) => t.toLowerCase().includes(p.toLowerCase())),
  );
}

function isMalwareFamily(n: NormalizedIndicator, names: string[]): boolean {
  if (!n.malware_family) return false;
  return names.some((name) =>
    n.malware_family!.toLowerCase().includes(name.toLowerCase()),
  );
}

// ================================================================
// MITRE ATT&CK v19 — Full Technique Map
// ================================================================

const TECHNIQUE_MAP: TechniqueEntry[] = [

  // TA0043 — RECONNAISSANCE
  {
    technique: "T1595",
    name: "Active Scanning",
    tactic: "Reconnaissance",
    score: (n) => {
      let s = 0;
      if (n.type === "ip") s += 20;
      if (hasTag(n, ["scanner", "scanning", "masscan", "shodan", "censys"])) s += 50;
      if (n.abuse_score >= 30) s += 20;
      if (hasTagPartial(n, ["scan", "probe", "sweep"])) s += 20;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["scan", "probe"])) r.push("IOC tagged as active scanning activity");
      if (n.abuse_score >= 30) r.push("AbuseIPDB score consistent with port scanning");
      return r;
    },
    mitigations: [
      {
        id: "M1056",
        name: "Pre-compromise Mitigation",
        description: "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls. Efforts should focus on minimizing the amount and sensitivity of data available to external parties.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1596",
    name: "Search Open Technical Databases",
    tactic: "Reconnaissance",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["osint", "shodan", "censys", "fofa", "zoomeye"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["osint", "shodan", "censys"])) r.push("IOC associated with open-database OSINT reconnaissance");
      return r;
    },
    mitigations: [
      {
        id: "M1056",
        name: "Pre-compromise Mitigation",
        description: "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls. Efforts should focus on minimizing the amount and sensitivity of data available to external parties.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1598",
    name: "Phishing for Information",
    tactic: "Reconnaissance",
    score: (n) => {
      let s = 0;
      if (n.type === "url" && hasTag(n, ["phishing", "spearphishing"])) s += 60;
      if (n.type === "domain" && hasTagPartial(n, ["phish"])) s += 40;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["phish"])) r.push("IOC tagged as phishing infrastructure for information gathering");
      return r;
    },
    mitigations: [
      {
        id: "M1017",
        name: "User Training",
        description: "Users can be trained to identify social engineering techniques and spearphishing attempts.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1054",
        name: "Software Configuration",
        description: "Use anti-spoofing and email authentication mechanisms to filter messages based on validity checks of the sender domain (using SPF) and integrity of messages (using DKIM). Enabling these mechanisms within an organization (through policies such as DMARC) may enable recipients (intra-org and cross domain) to perform similar message filtering and validation.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  // TA0043 — RECONNAISSANCE

{
  technique: "T1592",
  name: "Gather Victim Host Information",
  tactic: "Reconnaissance",
  score: (n) => {
    let s = 0;

    if (n.type === "domain") s += 20;
    if (n.type === "ip") s += 20;

    if (
      hasTag(n, [
        "whois",
        "dnsenum",
        "subdomain",
        "asset-discovery",
        "host-enumeration",
      ])
    )
      s += 50;

    if (hasTagPartial(n, ["host", "dns", "subdomain", "enumeration"]))
      s += 25;

    return s;
  },

  reasons: (n) => {
    const r: string[] = [];

    if (hasTagPartial(n, ["host", "dns", "subdomain"])) {
      r.push("IOC associated with victim host enumeration activity");
    }

    return r;
  },

  mitigations: [
    {
      id: "M1056",
      name: "Pre-compromise Mitigation",
      description:
        "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls. Efforts should focus on minimizing the amount and sensitivity of data available to external parties.",
      framework: "MITRE ATT&CK",
    },
  ],
},

{
  technique: "T1589",
  name: "Gather Victim Identity Information",
  tactic: "Reconnaissance",
  score: (n) => {
    let s = 0;

    if (
      hasTag(n, [
        "linkedin",
        "employee",
        "identity",
        "email-harvesting",
        "credential-harvest",
      ])
    )
      s += 60;

    if (hasTagPartial(n, ["identity", "employee", "email"])) s += 25;

    return s;
  },

  reasons: (n) => {
    const r: string[] = [];

    if (hasTagPartial(n, ["employee", "identity", "email"])) {
      r.push("IOC associated with identity harvesting reconnaissance");
    }

    return r;
  },

  mitigations: [
    {
      id: "M1056",
      name: "Pre-compromise Mitigation",
      description:
        "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls. Efforts should focus on minimizing the amount and sensitivity of data available to external parties.",
      framework: "MITRE ATT&CK",
    },
  ],
},

{
  technique: "T1590",
  name: "Gather Victim Network Information",
  tactic: "Reconnaissance",
  score: (n) => {
    let s = 0;

    if (n.type === "ip") s += 25;

    if (
      hasTag(n, [
        "network-enum",
        "topology",
        "asn",
        "bgp",
        "routing",
        "network-scan",
      ])
    )
      s += 55;

    if (hasTagPartial(n, ["network", "asn", "routing", "topology"]))
      s += 20;

    return s;
  },

  reasons: (n) => {
    const r: string[] = [];

    if (hasTagPartial(n, ["network", "routing", "asn"])) {
      r.push("IOC associated with victim network reconnaissance");
    }

    return r;
  },

  mitigations: [
    {
      id: "M1056",
      name: "Pre-compromise Mitigation",
      description:
        "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls. Efforts should focus on minimizing the amount and sensitivity of data available to external parties.",
      framework: "MITRE ATT&CK",
    },
  ],
},

{
  technique: "T1591",
  name: "Gather Victim Org Information",
  tactic: "Reconnaissance",
  score: (n) => {
    let s = 0;

    if (
      hasTag(n, [
        "organization",
        "company-profile",
        "business-info",
        "org-chart",
        "partner",
      ])
    )
      s += 60;

    if (hasTagPartial(n, ["organization", "company", "business"]))
      s += 25;

    return s;
  },

  reasons: (n) => {
    const r: string[] = [];

    if (hasTagPartial(n, ["organization", "company"])) {
      r.push("IOC associated with organizational information gathering");
    }

    return r;
  },

  mitigations: [
    {
      id: "M1056",
      name: "Pre-compromise Mitigation",
      description:
        "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls. Efforts should focus on minimizing the amount and sensitivity of data available to external parties.",
      framework: "MITRE ATT&CK",
    },
  ],
},

{
  technique: "T1682",
  name: "Query Public AI Services",
  tactic: "Reconnaissance",
  score: (n) => {
    let s = 0;

    if (
      hasTag(n, [
        "ai-query",
        "llm",
        "chatgpt",
        "gemini",
        "prompt-injection",
      ])
    )
      s += 60;

    if (hasTagPartial(n, ["ai", "llm", "prompt"])) s += 25;

    return s;
  },

  reasons: (n) => {
    const r: string[] = [];

    if (hasTagPartial(n, ["ai", "llm", "prompt"])) {
      r.push("IOC associated with reconnaissance using public AI services");
    }

    return r;
  },

  mitigations: [
    {
      id: "M1056",
      name: "Pre-compromise Mitigation",
      description:
        "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls. Efforts should focus on designing defenses that are not reliant on atomic indicators.",
      framework: "MITRE ATT&CK",
    },
  ],
},

{
  technique: "T1597",
  name: "Search Closed Sources",
  tactic: "Reconnaissance",
  score: (n) => {
    let s = 0;

    if (
      hasTag(n, [
        "closed-forum",
        "darkweb",
        "breach-forum",
        "underground-market",
      ])
    )
      s += 65;

    if (hasTagPartial(n, ["darkweb", "breach", "underground"])) s += 20;

    return s;
  },

  reasons: (n) => {
    const r: string[] = [];

    if (hasTagPartial(n, ["darkweb", "breach"])) {
      r.push("IOC associated with closed-source reconnaissance activity");
    }

    return r;
  },

  mitigations: [
    {
      id: "M1056",
      name: "Pre-compromise Mitigation",
      description:
        "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls. Efforts should focus on minimizing the amount and sensitivity of data available to external parties.",
      framework: "MITRE ATT&CK",
    },
  ],
},

{
  technique: "T1593",
  name: "Search Open Websites/Domains",
  tactic: "Reconnaissance",
  score: (n) => {
    let s = 0;

    if (n.type === "domain" || n.type === "url") s += 20;

    if (
      hasTag(n, [
        "website-enum",
        "domain-enum",
        "google-dork",
        "osint",
      ])
    )
      s += 50;

    if (hasTagPartial(n, ["website", "domain", "dork"])) s += 25;

    return s;
  },

  reasons: (n) => {
    const r: string[] = [];

    if (hasTagPartial(n, ["website", "domain", "dork"])) {
      r.push("IOC associated with open website/domain reconnaissance");
    }

    return r;
  },

  mitigations: [
    {
      id: "M1013",
      name: "Application Developer Guidance",
      description:
        "Application developers uploading to public code repositories should be careful to avoid publishing sensitive information such as credentials and API keys.",
      framework: "MITRE ATT&CK",
    },
    {
      id: "M1047",
      name: "Audit",
      description:
        "Scan public code repositories for exposed credentials or other sensitive information before making commits. Ensure that any leaked credentials are removed from the commit history, not just the current latest version of the code.",
      framework: "MITRE ATT&CK",
    },
  ],
},

{
  technique: "T1681",
  name: "Search Threat Vendor Data",
  tactic: "Reconnaissance",
  score: (n) => {
    let s = 0;

    if (
      hasTag(n, [
        "virustotal",
        "abuseipdb",
        "threatfox",
        "otx",
        "threatintel",
      ])
    )
      s += 60;

    if (hasTagPartial(n, ["threat", "intel", "vendor"])) s += 20;

    return s;
  },

  reasons: (n) => {
    const r: string[] = [];

    if (hasTagPartial(n, ["threat", "intel"])) {
      r.push("IOC associated with threat intelligence reconnaissance");
    }

    return r;
  },

  mitigations: [
    {
      id: "M1056",
      name: "Pre-compromise Mitigation",
      description:
        "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls. Efforts should focus on designing defenses that are not reliant on atomic indicators.",
      framework: "MITRE ATT&CK",
    },
  ],
},

{
  technique: "T1594",
  name: "Search Victim-Owned Websites",
  tactic: "Reconnaissance",
  score: (n) => {
    let s = 0;

    if (n.type === "domain" || n.type === "url") s += 20;

    if (
      hasTag(n, [
        "victim-website",
        "website-recon",
        "cms-enum",
        "directory-bruteforce",
      ])
    )
      s += 55;

    if (hasTagPartial(n, ["website", "cms", "directory"])) s += 20;

    return s;
  },

  reasons: (n) => {
    const r: string[] = [];

    if (hasTagPartial(n, ["website", "cms"])) {
      r.push("IOC associated with victim-owned website reconnaissance");
    }

    return r;
  },

  mitigations: [
    {
      id: "M1056",
      name: "Pre-compromise Mitigation",
      description:
        "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls. Efforts should focus on minimizing the amount and sensitivity of data available to external parties.",
      framework: "MITRE ATT&CK",
    },
  ],
},
  // TA0042 — RESOURCE DEVELOPMENT
  {
    technique: "T1583",
    name: "Acquire Infrastructure",
    tactic: "Resource Development",
    score: (n) => {
      let s = 0;
      if (n.type === "ip" && hasTagPartial(n, ["bulletproof", "hosting", "vps"])) s += 50;
      if (n.type === "domain" && hasTagPartial(n, ["newly", "registered"])) s += 40;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["bulletproof"])) r.push("IOC associated with bulletproof hosting infrastructure");
      if (hasTagPartial(n, ["newly-registered", "new-domain"])) r.push("Newly registered domain typical of attacker infra");
      return r;
    },
    mitigations: [
      {
        id: "M1056",
        name: "Pre-compromise Mitigation",
        description: "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1584",
    name: "Compromise Infrastructure",
    tactic: "Resource Development",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["compromised", "hijacked", "watering-hole"])) s += 60;
      if (n.vt_score >= 3 && (n.type === "ip" || n.type === "domain")) s += 20;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["compromised", "hijacked"])) r.push("IOC tagged as compromised/hijacked infrastructure");
      return r;
    },
    mitigations: [
      {
        id: "M1056",
        name: "Pre-compromise Mitigation",
        description: "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1587",
    name: "Develop Capabilities",
    tactic: "Resource Development",
    score: (n) => {
      let s = 0;
      if (n.type.includes("hash") && n.vt_score >= 5) s += 30;
      if (hasTag(n, ["custom-malware", "implant", "rat", "backdoor"])) s += 50;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["custom", "implant", "rat"])) r.push("IOC indicates custom-built malware capability");
      return r;
    },
    mitigations: [
      {
        id: "M1056",
        name: "Pre-compromise Mitigation",
        description: "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1650",
    name: "Acquire Access",
    tactic: "Resource Development",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "initial-access",
          "access-broker",
          "rdp-access",
          "vpn-access",
          "stolen-access",
        ])
      )
        s += 60;

      if (hasTagPartial(n, ["access", "broker", "vpn", "rdp"])) s += 25;

      if (n.abuse_score >= 30) s += 10;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["access", "broker", "rdp"])) {
        r.push("IOC associated with acquired unauthorized access infrastructure");
      }

      if (n.abuse_score >= 30) {
        r.push("AbuseIPDB score consistent with malicious remote access activity");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1056",
        name: "Pre-compromise Mitigation",
        description:
          "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1586",
    name: "Compromise Accounts",
    tactic: "Resource Development",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "account-takeover",
          "credential-theft",
          "compromised-account",
          "stolen-credentials",
        ])
      )
        s += 60;

      if (hasTagPartial(n, ["compromise", "credential", "account"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["credential", "account"])) {
        r.push("IOC associated with compromised account activity");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1056",
        name: "Pre-compromise Mitigation",
        description:
          "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1585",
    name: "Establish Accounts",
    tactic: "Resource Development",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "fake-account",
          "burner-account",
          "bot-account",
          "registered-account",
        ])
      )
        s += 60;

      if (hasTagPartial(n, ["account", "fake", "burner"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["fake", "burner", "bot-account"])) {
        r.push("IOC associated with attacker-created accounts");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1056",
        name: "Pre-compromise Mitigation",
        description:
          "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1683",
    name: "Generate Content",
    tactic: "Resource Development",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "phishing-template",
          "fake-login",
          "spoofed-content",
          "malicious-document",
        ])
      )
        s += 60;

      if (hasTagPartial(n, ["template", "spoof", "malicious-doc"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["spoof", "template", "fake-login"])) {
        r.push("IOC associated with attacker-generated malicious content");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1056",
        name: "Pre-compromise Mitigation",
        description:
          "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1588",
    name: "Obtain Capabilities",
    tactic: "Resource Development",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "exploit-kit",
          "malware-builder",
          "c2-framework",
          "toolkit",
          "payload",
        ])
      )
        s += 60;

      if (hasTagPartial(n, ["exploit", "payload", "toolkit"])) s += 25;

      if (n.vt_score >= 5) s += 10;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["exploit", "toolkit", "payload"])) {
        r.push("IOC associated with attacker capability acquisition");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1056",
        name: "Pre-compromise Mitigation",
        description:
          "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1608",
    name: "Stage Capabilities",
    tactic: "Resource Development",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "payload-staging",
          "dropper",
          "stager",
          "malware-hosting",
          "loader",
        ])
      )
        s += 60;

      if (hasTagPartial(n, ["staging", "dropper", "loader"])) s += 25;

      if (n.type === "url" || n.type === "domain") s += 10;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["dropper", "loader", "staging"])) {
        r.push("IOC associated with staged malicious capabilities");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1056",
        name: "	Pre-compromise Mitigation",
        description:
          "This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  // TA0001 — INITIAL ACCESS
  {
    technique: "T1133",
    name: "External Remote Services",
    tactic: "Initial Access",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["rdp", "ssh", "vpn", "citrix", "remote-access", "remote-desktop"])) s += 60;
      if (n.type === "ip" && n.abuse_score >= 30) s += 20;
      if (hasTagPartial(n, ["brute", "credential"])) s += 20;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["rdp", "ssh", "vpn"])) r.push("IOC associated with remote service exploitation");
      if (n.abuse_score >= 30) r.push("AbuseIPDB score indicates remote service abuse attempts");
      return r;
    },
    mitigations: [
      {
        id: "M1035",
        name: "Limit Access to Resource Over Network",
        description: "Limit access to remote services through centrally managed concentrators such as VPNs and other managed remote access systems.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description: "Use strong two-factor or multi-factor authentication for remote service accounts to mitigate an adversary's ability to leverage stolen credentials, but be aware of Multi-Factor Authentication Interception techniques for some two-factor authentication implementations.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description: "Disable or block remotely available services that may be unnecessary.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1030",
        name: "Network Segmentation",
        description: "Deny direct remote access to internal systems through the use of network proxies, gateways, and firewalls.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1021",
        name: "Restrict Web-Based Content", 
        description: "Restrict all traffic to and from public Tor nodes.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1566",
    name: "Phishing",
    tactic: "Initial Access",
    score: (n) => {
      let s = 0;
      if (n.type === "url") s += 15;
      if (hasTag(n, ["phishing", "credential-phishing", "spearphishing"])) s += 55;
      if (n.misp_confidence === "High") s += 15;
      if (n.vt_score >= 5) s += 10;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["phish"])) r.push("IOC tagged as phishing delivery infrastructure");
      if (n.type === "url") r.push("URL-type IOC consistent with phishing link");
      return r;
    },
    mitigations: [
      {
        id: "M1049",
        name: "Antivirus/Antimalware",
        description: "Anti-virus can automatically quarantine suspicious files.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1054",
        name: "Software Configuration",
        description: "Use anti-spoofing and email authentication mechanisms to filter messages based on validity checks of the sender domain (using SPF) and integrity of messages (using DKIM). Enabling these mechanisms within an organization (through policies such as DMARC) may enable recipients (intra-org and cross domain) to perform similar message filtering and validation.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1017",
        name: "User Training",
        description: "Users can be trained to identify social engineering techniques and phishing emails.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1047",
        name: "Audit",
        description: "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Network intrusion prevention systems and systems designed to scan and remove malicious email attachments or links can be used to block activity.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1021",
        name: "Restrict Web-Based Content",
        description: "Determine if certain websites or attachment types (ex: .scr, .exe, .pif, .cpl, etc.) that can be used for phishing are necessary for business operations and consider blocking access if activity cannot be monitored well or if it poses a significant risk.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1189",
    name: "Drive-by Compromise",
    tactic: "Initial Access",
    score: (n) => {
      let s = 0;
      if (n.type === "url" && hasTag(n, ["exploit", "drive-by", "exploit-kit"])) s += 65;
      if (n.type === "domain" && hasTagPartial(n, ["exploit", "malvert"])) s += 40;
      if (n.vt_score >= 5) s += 10;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["drive-by", "exploit-kit"])) r.push("IOC associated with drive-by exploit kit delivery");
      return r;
    },
    mitigations: [
      {
        id: "M1050",
        name: "Exploit Protection",
        description: "Security applications that look for behavior used during exploitation such as Windows Defender Exploit Guard (WDEG) and the Enhanced Mitigation Experience Toolkit (EMET) can be used to mitigate some exploitation behavior. Control flow integrity checking is another way to potentially identify and stop a software exploit from occurring. Many of these protections depend on the architecture and target application binary for compatibility.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1021",
        name: "Restrict Web-Based Content",
        description: "Adblockers can help prevent malicious code served through ads from executing in the first place. Script blocking extensions can also help to prevent the execution of JavaScript. Consider disabling browser push notifications from certain applications and browsers",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1048",
        name: "Application Isolation and Sandboxing",
        description: "Browser sandboxes can be used to mitigate some of the impact of exploitation, but sandbox escapes may still exist. Other types of virtualization and application microsegmentation may also mitigate the impact of client-side exploitation. The risks of additional exploits and weaknesses in implementation may still exist for these types of systems.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1051",
        name: "Update Software",
        description: "Ensuring that all browsers and plugins are kept updated can help prevent the exploit phase of this technique. Use modern browsers with security features turned on.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1017",
        name: "User Training",
        description: "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1195",
    name: "Supply Chain Compromise",
    tactic: "Initial Access",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["supply-chain", "solarwinds", "3cx", "dependency-confusion"])) s += 70;
      if (n.type.includes("hash") && hasTagPartial(n, ["supply", "package", "npm", "pypi"])) s += 40;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["supply-chain", "package"])) r.push("IOC linked to software supply chain compromise");
      return r;
    },
    mitigations: [
      {
        id: "M1051",
        name: "Update Software",
        description: "A patch management process should be implemented to check unused dependencies, unmaintained and/or previously vulnerable dependencies, unnecessary features, components, files, and documentation.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1013",
        name: "Application Developer Guidance",
        description: "Application developers should be cautious when selecting third-party libraries to integrate into their application. Additionally, where possible, developers should lock software dependencies to specific versions rather than pulling the latest version on build.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1046",
        name: "Boot Integrity",
        description: "Use secure methods to boot a system and verify the integrity of the operating system and loading mechanisms.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1033",
        name: "Limit Software Installation",
        description: "Where possible, consider requiring developers to pull from internal repositories containing verified and approved packages rather than from external ones.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description: "Implement robust user account management practices to limit permissions associated with software execution. Ensure that software runs with the lowest necessary privileges, avoiding the use of root or administrator accounts when possible. By restricting permissions, you can minimize the risk of propagation and unauthorized actions in the event of a supply chain compromise, reducing the attack surface for adversaries to exploit within compromised systems.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1016",
        name: "Vulnerability Scanning",
        description: "Continuous monitoring of vulnerability sources and the use of automatic and manual code review tools should also be implemented as well.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1078",
    name: "Valid Accounts",
    tactic: "Initial Access",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["valid-accounts", "stolen-creds", "credential-access"])) s += 55;
      if (n.misp_confidence === "High") s += 25;
      if (hasTagPartial(n, ["credential", "password", "token", "stolen"])) s += 20;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["credential", "stolen"])) r.push("IOC associated with stolen/abused valid credentials");
      if (n.misp_confidence === "High") r.push("MISP high-confidence threat actor IOC");
      return r;
    },
    mitigations: [
      {
        id: "M1026",
        name: "Privileged Account Management",
        description: "Audit domain and local accounts as well as their permission levels routinely to look for situations that could allow an adversary to gain wide access by obtaining credentials of a privileged account. These audits should also include if default accounts have been enabled, or if new local accounts are created that have not been authorized. Follow best practices for design and administration of an enterprise network to limit privileged account use across administrative tiers.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description: "Implement multi-factor authentication (MFA) across all account types, including default, local, domain, and cloud accounts, to prevent unauthorized access, even if credentials are compromised. MFA provides a critical layer of security by requiring multiple forms of verification beyond just a password. This measure significantly reduces the risk of adversaries abusing valid accounts to gain initial access, escalate privileges, maintain persistence, or evade defenses within your network.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1036",
        name: "Account Use Policies",
        description: "Use conditional access policies to block logins from non-compliant devices or from outside defined organization IP ranges.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1015",
        name: "Active Directory Configuration",
        description: "Disable legacy authentication, which does not support MFA, and require the use of modern authentication protocols instead.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1013",
        name: "Application Developer Guidance",
        description: "Ensure that applications do not store sensitive data or credentials insecurely. (e.g. plaintext credentials in code, published credentials in repositories, or credentials in public cloud storage).",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1027",
        name: "Password Policies",
        description: "Applications and appliances that utilize default username and password should be changed immediately after the installation, and before deployment to a production environment. When possible, applications that use SSH keys should be updated periodically and properly secured. Policies should minimize (if not eliminate) reuse of passwords between different user accounts, especially employees using the same credentials for personal accounts that may not be defended by enterprise security resources.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description: "Regularly audit user accounts for activity and deactivate or remove any that are no longer needed.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1017",
        name: "User Training",
        description: "Applications may send push notifications to verify a login as a form of multi-factor authentication (MFA). Train users to only accept valid push notifications and to report suspicious push notifications.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1659",
    name: "Content Injection",
    tactic: "Initial Access",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "content-injection",
          "script-injection",
          "html-injection",
          "js-injection",
          "malvertising",
        ])
      )
        s += 65;

      if (
        n.type === "url" &&
        hasTagPartial(n, ["inject", "malvert", "script"])
      )
        s += 30;

      if (n.vt_score >= 5) s += 10;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["inject", "script", "malvert"])) {
        r.push("IOC associated with malicious content injection activity");
      }

      if (n.type === "url") {
        r.push("URL-type IOC consistent with injected malicious content");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1054",
        name: "Encrypt Sensitive Information",
        description:
          "Where possible, ensure that online traffic is appropriately encrypted through services such as trusted VPNs.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1021",
        name: "Restrict Web-Based Content",
        description:
          "Consider blocking download/transfer and execution of potentially uncommon file types known to be used in adversary campaigns.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1190",
    name: "Exploit Public-Facing Application",
    tactic: "Initial Access",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "exploit",
          "webshell",
          "sqli",
          "rce",
          "lfi",
          "rfi",
          "ssrf",
        ])
      )
        s += 60;

      if (
        n.type === "url" &&
        hasTagPartial(n, ["exploit", "injection", "shell"])
      )
        s += 30;

      if (n.vt_score >= 5) s += 10;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["exploit", "rce", "sqli", "ssrf"])) {
        r.push("Tags indicate web application exploitation");
      }

      if (n.type === "url") {
        r.push("URL-type IOC consistent with exploit delivery or webshell");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1048",
        name: "Application Isolation and Sandboxing",
        description:
          "Application isolation will limit what other processes and system features the exploited target can access.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1016",
        name: "Vulnerability Scanning",
        description:
          "Regularly scan externally facing systems for vulnerabilities and establish procedures to rapidly patch systems when critical vulnerabilities are discovered through scanning and through public disclosure.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1030",
        name: "Network Segmentation",
        description:
          "Segment externally facing servers and services from the rest of the network with a DMZ or on separate hosting infrastructure.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1050",
        name: "Exploit Protection",
        description:
          "Web Application Firewalls may be used to limit exposure of applications to prevent exploit traffic from reaching the application.",
        framework: "MITRE ATT&CK",
      },
     {
        id: "M1037",
        name: "Filter Network Traffic",
        description:
          "Restrict outbound network traffic from public-facing servers to prevent unauthorized connections from initiating communications with attacker-controlled infrastructure. While this may not prevent the initial exploitation, it limits the attacker's ability to verify and control the compromised server post-exploit, reducing the overall impact of the attack.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1035",
        name: "Limit Access to Resource Over Network",
        description:
          "Ensure that all publicly exposed services are actually intended to be so, and restrict access to any that should only be available internally.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "Privileged Account Management",
        description:
          "Use least privilege for service accounts will limit what permissions the exploited process gets on the rest of the system.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1051",
        name: "Update Software",
        description:
          "Update software regularly by employing patch management for externally exposed applications.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1200",
    name: "Hardware Additions",
    tactic: "Initial Access",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "usb",
          "rubber-ducky",
          "rogue-device",
          "hardware-implant",
          "malicious-usb",
        ])
      )
        s += 65;

      if (hasTagPartial(n, ["usb", "hardware", "implant"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["usb", "hardware", "implant"])) {
        r.push("IOC associated with malicious hardware additions");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1035",
        name: "Limit Access to Resource Over Network",
        description:
          "Establish network access control policies, such as using device certificates and the 802.1x standard. Restrict use of DHCP to registered devices to prevent unregistered devices from communicating with trusted systems.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1034",
        name: "Limit Hardware Installation",
        description:
          "Block unknown devices and accessories by endpoint security configuration and monitoring agent.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1091",
    name: "Replication Through Removable Media",
    tactic: "Initial Access",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "usb-worm",
          "autorun",
          "removable-media",
          "infected-usb",
        ])
      )
        s += 65;

      if (hasTagPartial(n, ["usb", "autorun", "worm"])) s += 25;

      if (n.type.includes("hash") && n.vt_score >= 5) s += 10;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["usb", "worm", "autorun"])) {
        r.push("IOC associated with malware replication through removable media");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description:
          "Disable Autorun if it is unnecessary. Disallow or restrict removable media at an organizational policy level if it is not required for business operations.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description:
          "On Windows 10, enable Attack Surface Reduction (ASR) rules to block unsigned/untrusted executable files (such as .exe, .dll, or .scr) from running from USB removable drives.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1034",
        name: "Limit Hardware Installation",
        description:
          "Limit the use of USB devices and removable media within a network.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1199",
    name: "Trusted Relationship",
    tactic: "Initial Access",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "trusted-relationship",
          "partner-access",
          "third-party",
          "vendor-compromise",
          "supply-chain",
        ])
      )
        s += 70;

      if (hasTagPartial(n, ["vendor", "partner", "third-party"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["vendor", "partner", "third-party"])) {
        r.push("IOC associated with abuse of trusted third-party relationships");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1018",
        name: "User Account Management",
        description:
          "Properly manage accounts and permissions used by parties in trusted relationships to minimize potential abuse by the party and if the party is compromised by an adversary. In Office 365 environments, partner relationships and roles can be viewed under the 'Partner Relationships' page.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1030",
        name: "Network Segmentation",
        description:
          "Network segmentation can be used to isolate infrastructure components that do not require broad network access.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description:
          "Require MFA for all delegated administrator accounts.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1669",
    name: "Wi-Fi Networks",
    tactic: "Initial Access",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "wifi",
          "rogue-ap",
          "evil-twin",
          "wireless-attack",
          "wifi-phishing",
        ])
      )
        s += 65;

      if (hasTagPartial(n, ["wifi", "wireless", "evil-twin"])) s += 25;

      if (n.abuse_score >= 20) s += 10;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["wifi", "rogue-ap", "evil-twin"])) {
        r.push("IOC associated with malicious Wi-Fi network activity");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1030",
        name: "Network Segmentation",
        description:
          "Network segmentation can be used to isolate infrastructure components that do not require broad network access. Separate networking environments for Wi-Fi and Ethernet-wired networks, particularly where Ethernet-based networks allow for access to sensitive resources.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description:
          "Harden access requirements for Wi-Fi networks through using two or more pieces of evidence to authenticate, such as a username and password in addition to a token from a physical smart card or token generator.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1041",
        name: "Encrypt Sensitive Information",
        description:
          "Ensure that all wired and/or wireless traffic is encrypted appropriately. Use best practices for authentication protocols, such as Kerberos, and ensure that web traffic that may contain credentials is protected by SSL/TLS.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  // TA0002 — EXECUTION
  {
    technique: "T1677",
    name: "Poisoned Pipeline Execution",
    tactic: "Execution",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "poisoned-pipeline",
          "cicd-attack",
          "pipeline-injection",
          "github-actions-abuse",
          "pull-request-target",
          "build-script-tamper",
        ])
      )
        s += 70;

      if (
        hasTagPartial(n, [
          "cicd",
          "pipeline",
          "github-actions",
          "gitlab-ci",
          "jenkins",
          "build-script",
          "self-hosted-runner",
          "workflow",
          "makefi",
          "supply-chain",
        ])
      )
        s += 30;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["cicd", "pipeline", "github-actions", "gitlab-ci"])) {
        r.push("IOC associated with CI/CD pipeline poisoning or build process injection");
      }

      if (hasTagPartial(n, ["pull-request-target", "self-hosted-runner"])) {
        r.push("Tags indicate exploitation of insecure CI/CD triggers (pull_request_target or self-hosted runner)");
      }

      if (hasTagPartial(n, ["build-script", "makefile", "workflow"])) {
        r.push("IOC linked to indirect pipeline execution via tampered build scripts or workflow files");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1054",
        name: "Software Configuration",
        description:
          "Where possible, avoid allowing pipelines to run unreviewed code. Where this is necessary, ensure that these pipelines are executed on isolated nodes without access to secrets. In GitHub, avoid using the pull_request_target trigger if possible, do not treat user-controlled inputs (such as branch names) as trusted, and do not use self-hosted runners on public repositories.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description:
          "Ensure that CI/CD pipelines only have permissions they require to complete their operations. Additionally, limit the number of users who have write access to internal repositories to only those necessary.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1204",
    name: "User Execution",
    tactic: "Execution",
    score: (n) => {
      let s = 0;
      if (n.type.includes("hash")) s += 35;
      if (hasTag(n, ["trojan", "dropper", "downloader", "malware"])) s += 40;
      if (n.vt_score >= 5) s += 15;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (n.type.includes("hash")) r.push("Indicator is a malicious file hash");
      if (hasTagPartial(n, ["trojan", "dropper", "malware"])) r.push("Tags indicate user-executed malware delivery");
      return r;
    },
    mitigations: [
      {
        id: "M1038",
        name: "Execution Prevention",
        description: "Application control may be able to prevent the running of executables masquerading as other files.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description: "On Windows 10, enable Attack Surface Reduction (ASR) rules to prevent executable files from running unless they meet a prevalence, age, or trusted list criteria and to prevent Office applications from creating potentially malicious executable content by blocking malicious code from being written to disk. Note: cloud-delivered protection must be enabled to use certain rules.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1033",
        name: "Limit Software Installation",
        description: "Where possible, consider requiring developers to pull from internal repositories containing verified and approved packages rather than from external ones.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "If a link is being visited by a user, network intrusion prevention systems and systems designed to scan and remove malicious downloads can be used to block activity.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1021",
        name: "Restrict Web-Based Content",
        description: "If a link is being visited by a user, block unknown or unused files in transit by default that should not be downloaded or by policy from suspicious sites as a best practice to prevent some vectors, such as .scr, .exe, .pif, .cpl, etc. Some download scanning devices can open and analyze compressed and encrypted formats, such as zip and rar that may be used to conceal malicious files.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1017",
        name: "User Training",
        description: "Use user training as a way to bring awareness to common phishing and spearphishing techniques and how to raise suspicion for potentially malicious events.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1072",
    name: "Software Deployment Tools",
    tactic: "Execution",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["sccm", "ansible", "puppet", "chef", "deployment-tool"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["deployment", "sccm", "ansible"])) r.push("IOC associated with software deployment tool abuse");
      return r;
    },
    mitigations: [
      {
        id: "M1026",
        name: "Privileged Account Management",
        description: "Grant access to application deployment systems only to a limited number of authorized administrators.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1015",
        name: "Active Directory Configuration",
        description: "Ensure proper system and access isolation for critical network systems through use of group policy.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1033",
        name: "	Limit Software Installation",
        description: "Restrict the use of third-party software suites installed within an enterprise network.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description: "Ensure proper system and access isolation for critical network systems through use of multi-factor authentication.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1030",
        name: "Network Segmentation",
        description: "Ensure proper system isolation for critical network systems through use of firewalls.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1027",
        name: "Password Policies",
        description: "Verify that account credentials that may be used to access deployment systems are unique and not used throughout the enterprise network.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1029",
        name: "Remote Data Storage",
        description: "If the application deployment system can be configured to deploy only signed binaries, then ensure that the trusted signing certificates are not co-located with the application deployment system and are instead located on a system that cannot be accessed remotely or to which remote access is tightly controlled.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1051",
        name: "Update Software",
        description: "Patch deployment systems regularly to prevent potential remote access through Exploitation for Privilege Escalation.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "	User Account Management",
        description: "Ensure that any accounts used by third-party providers to access these systems are traceable to the third-party and are not used throughout the network or used by other third-party providers in the same environment. Ensure there are regular reviews of accounts provisioned to these systems to verify continued business need, and ensure there is governance to trace de-provisioning of access that is no longer required. Ensure proper system and access isolation for critical network systems through use of account privilege separation.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1017",
        name: "User Training",
        description: "Have a strict approval policy for use of deployment systems.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1197",
    name: "BITS Jobs",
    tactic: "Execution",
    score: (n) => {
      let s = 0;

      if (hasTag(n, ["bits", "bitsadmin", "background-intelligent-transfer"]))
        s += 65;

      if (hasTagPartial(n, ["bits", "bitsadmin"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["bits", "bitsadmin"])) {
        r.push("IOC associated with malicious BITS job execution");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description:
          "Modify network and/or host firewall rules, as well as other network controls, to only allow legitimate BITS traffic.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1028",
        name: "Operating System Configuration",
        description:
          "Consider reducing the default BITS job lifetime in Group Policy or by editing the JobInactivityTimeout and MaxDownloadTime Registry values in HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\BITS.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description:
          "Consider limiting access to the BITS interface to specific users or groups",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1651",
    name: "Cloud Administration Command",
    tactic: "Execution",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "aws-cli",
          "azure-cli",
          "gcloud",
          "cloud-admin",
          "cloud-command",
        ])
      )
        s += 65;

      if (hasTagPartial(n, ["aws", "azure", "gcloud", "cloud"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["aws", "azure", "cloud"])) {
        r.push("IOC associated with cloud administration command execution");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1026",
        name: "Privileged Account Management",
        description:
          "Limit the number of cloud accounts with permissions to remotely execute commands on virtual machines, and ensure that these are not used for day-to-day operations. In Azure, limit the number of accounts with the roles Azure Virtual Machine Contributer and above, and consider using temporary Just-in-Time (JIT) roles to avoid permanently assigning privileged access to virtual machines.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1059",
    name: "Command and Scripting Interpreter",
    tactic: "Execution",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "powershell",
          "cmd",
          "bash",
          "python",
          "wscript",
          "cscript",
        ])
      )
        s += 55;

      if (hasTagPartial(n, ["script", "shell", "interpreter"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["powershell", "bash", "script"])) {
        r.push("IOC associated with command interpreter abuse");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1038",
        name: "Execution Prevention",
        description:
          "Use application control where appropriate. For example, PowerShell Constrained Language mode can be used to restrict access to sensitive or otherwise dangerous language elements such as those used to execute arbitrary Windows APIs or files (e.g., Add-Type).",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1049",
        name: "Antivirus/Antimalware",
        description:
          "Anti-virus can be used to automatically quarantine suspicious files.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1047",
        name: "Audit",
        description:
          "Inventory systems for unauthorized command and scripting interpreter installations.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description:
          "On Windows 10, enable Attack Surface Reduction (ASR) rules to prevent Visual Basic and JavaScript scripts from executing potentially malicious downloaded content.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1045",
        name: "Code Signing",
        description:
          "Where possible, only permit execution of signed scripts.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description:
          "Disable or remove any unnecessary or unused shells or interpreters.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1033",
        name: "Limit Software Installation",
        description:
          "Prevent user installation of unrequired command and scripting interpreters.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "Privileged Account Management",
        description:
          "When PowerShell is necessary, consider restricting PowerShell execution policy to administrators. Be aware that there are methods of bypassing the PowerShell execution policy, depending on environment configuration. PowerShell JEA (Just Enough Administration) may also be used to sandbox administration and limit what commands admins/users can execute through remote PowerShell sessions.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1021",
        name: "Restrict Web-Based Content",
        description:
          "Script blocking extensions can help prevent the execution of scripts and HTA files that may commonly be used during the exploitation process. For malicious code served up through ads, adblockers can help prevent that code from executing in the first place.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1609",
    name: "Container Administration Command",
    tactic: "Execution",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "docker",
          "kubectl",
          "container-admin",
          "kubernetes",
        ])
      )
        s += 65;

      if (hasTagPartial(n, ["docker", "kubectl", "container"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["docker", "kubectl"])) {
        r.push("IOC associated with container administration abuse");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description:
          "Remove unnecessary tools and software from containers.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1038",
        name: "Execution Prevention",
        description:
          "Use read-only containers, read-only file systems, and minimal images when possible to prevent the execution of commands. Where possible, also consider using application control and software restriction tools (such as those provided by SELinux) to restrict access to files, processes, and system calls in containers.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1035",
        name: "Limit Access to Resource Over Network",
        description:
          "Limit communications with the container service to managed and secured channels, such as local Unix sockets or remote access via SSH. Require secure port access to communicate with the APIs over TLS by disabling unauthenticated access to the Docker API and Kubernetes API Server. In Kubernetes clusters deployed in cloud environments, use native cloud platform features to restrict the IP ranges that are permitted to access to API server. Where possible, consider enabling just-in-time (JIT) access to the Kubernetes API to place additional restrictions on access.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "Privileged Account Management",
        description:
          "Ensure containers are not running as root by default. In Kubernetes environments, consider defining Pod Security Standards that prevent pods from running privileged containers and using the NodeRestriction admission controller to deny the kublet access to nodes and pods outside of the node it belongs to.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description:
          "Enforce authentication and role-based access control on the container service to restrict users to the least privileges required. When using Kubernetes, avoid giving users wildcard permissions or adding users to the system:masters group, and use RoleBindings rather than ClusterRoleBindings to limit user privileges to specific namespaces.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1610",
    name: "Deploy Container",
    tactic: "Execution",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "container-deploy",
          "docker-run",
          "k8s-deploy",
          "malicious-container",
        ])
      )
        s += 65;

      if (hasTagPartial(n, ["container", "docker", "kubernetes"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["container", "docker"])) {
        r.push("IOC associated with malicious container deployment");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1047",
        name: "Audit",
        description:
          "Scan images before deployment, and block those that are not in compliance with security policies. In Kubernetes environments, the admission controller can be used to validate images after a container deployment request is authenticated but before the container is deployed.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1035",
        name: "Limit Access to Resource Over Network",
        description:
          "Limit communications with the container service to managed and secured channels, such as local Unix sockets or remote access via SSH. Require secure port access to communicate with the APIs over TLS by disabling unauthenticated access to the Docker API, Kubernetes API Server, and container orchestration web applications. In Kubernetes clusters deployed in cloud environments, use native cloud platform features to restrict the IP ranges that are permitted to access to API server. Where possible, consider enabling just-in-time (JIT) access to the Kubernetes API to place additional restrictions on access.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1030",
        name: "Network Segmentation",
        description:
          "Deny direct remote access to internal systems through the use of network proxies, gateways, and firewalls.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description:
          "Enforce the principle of least privilege by limiting container dashboard access to only the necessary users. When using Kubernetes, avoid giving users wildcard permissions or adding users to the system:masters group, and use RoleBindings rather than ClusterRoleBindings to limit user privileges to specific namespaces.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1675",
    name: "ESXi Administration Command",
    tactic: "Execution",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, ["esxi", "vim-cmd", "vcenter", "vmware"])
      )
        s += 70;

      if (hasTagPartial(n, ["esxi", "vmware", "vim-cmd"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["esxi", "vmware"])) {
        r.push("IOC associated with ESXi administration command abuse");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1018",
        name: "User Account Management",
        description:
          "If not required, restrict the permissions of users to perform Guest Operations on ESXi-hosted VMs.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1203",
    name: "Exploitation for Client Execution",
    tactic: "Execution",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "exploit",
          "client-execution",
          "office-exploit",
          "browser-exploit",
        ])
      )
        s += 65;

      if (hasTagPartial(n, ["exploit", "client", "browser"])) s += 25;

      if (n.vt_score >= 5) s += 10;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["exploit", "browser"])) {
        r.push("IOC associated with client-side exploitation");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1050",
        name: "Exploit Protection",
        description:
          "Security applications that look for behavior used during exploitation such as Windows Defender Exploit Guard (WDEG) and the Enhanced Mitigation Experience Toolkit (EMET) can be used to mitigate some exploitation behavior. Control flow integrity checking is another way to potentially identify and stop a software exploit from occurring. Many of these protections depend on the architecture and target application binary for compatibility.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1048",
        name: "Application Isolation and Sandboxing",
        description:
          "Browser sandboxes can be used to mitigate some of the impact of exploitation, but sandbox escapes may still exist. Other types of virtualization and application microsegmentation may also mitigate the impact of client-side exploitation. Risks of additional exploits and weaknesses in those systems may still exist.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1051",
        name: "Update Software",
        description:
          "Perform regular software updates to mitigate exploitation risk. Keeping software up-to-date with the latest security patches helps prevent adversaries from exploiting known vulnerabilities in client software, reducing the risk of successful attacks.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1574",
    name: "Hijack Execution Flow",
    tactic: "Execution",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "dll-hijack",
          "path-hijack",
          "execution-flow",
          "search-order",
        ])
      )
        s += 65;

      if (hasTagPartial(n, ["hijack", "dll", "search-order"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["dll", "hijack"])) {
        r.push("IOC associated with execution flow hijacking");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1013",
        name: "Application Developer Guidance",
        description:
          "When possible, include hash values in manifest files to help prevent side-loading of malicious libraries.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1047",
        name: "Audit",
        description:
          `Use auditing tools capable of detecting hijacking opportunities on systems within an enterprise and correct them. Toolkits like the PowerSploit framework contain PowerUp modules that can be used to explore systems for hijacking weaknesses.
          
          Use the program sxstrace.exe that is included with Windows along with manual inspection to check manifest files for side-loading vulnerabilities in software.

          Find and eliminate path interception weaknesses in program configuration files, scripts, the PATH environment variable, services, and in shortcuts by surrounding PATH variables with quotation marks when functions allow for them. Be aware of the search order Windows uses for executing or loading binaries and use fully qualified paths wherever appropriate.

          Clean up old Windows Registry keys when software is uninstalled to avoid keys with no associated legitimate binaries. Periodically search for and correct or report path interception weaknesses on systems that may have been introduced using custom or available tools that report software using insecure path configurations.`,
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description:
          "Some endpoint security solutions can be configured to block some types of behaviors related to process injection/memory tampering based on common sequences of indicators (ex: execution of specific API functions).",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1038",
        name: "Execution Prevention",
        description:
          "Adversaries may use new payloads to execute this technique. Identify and block potentially malicious software executed through hijacking by using application control solutions also capable of blocking libraries loaded by legitimate software.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description:
          "Install software in write-protected locations. Set directory access controls to prevent file writes to the search paths for applications, both in the folders where applications are run from and the standard library folders.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1044",
        name: "Restrict Library Loading",
        description:
          `Disallow loading of remote DLLs. This is included by default in Windows Server 2012+ and is available by patch for XP+ and Server 2003+.
          
          Enable Safe DLL Search Mode to force search for system DLLs in directories with greater restrictions (e.g. %SYSTEMROOT%)to be used before local directory DLLs (e.g. a user's home directory)

          The Safe DLL Search Mode can be enabled via Group Policy at Computer Configuration > [Policies] > Administrative Templates > MSS (Legacy): MSS: (SafeDllSearchMode) Enable Safe DLL search mode. The associated Windows Registry key for this is located at HKLM/SYSTEM/CurrentControlSet/Control/Session Manager/SafeDLLSearchMode`,
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1024",
        name: "Restrict Registry Permissions",
        description:
          "Ensure proper permissions are set for Registry hives to prevent users from modifying keys for system components that may lead to privilege escalation.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1051",
        name: "Update Software",
        description:
          "Update software regularly to include patches that fix DLL side-loading vulnerabilities.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1052",
        name: "User Account Control",
        description:
          "Turn off UAC's privilege elevation for standard users [HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System] to automatically deny elevation requests, add: 'ConsentPromptBehaviorUser'=dword:00000000. Consider enabling installer detection for all users by adding: 'EnableInstallerDetection'=dword:00000001. This will prompt for a password for installation and also log the attempt. To disable installer detection, instead add: 'EnableInstallerDetection'=dword:00000000. This may prevent potential elevation of privileges through exploitation during the process of UAC detecting the installer, but will allow the installation process to continue without being logged. ",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description:
          `Limit privileges of user accounts and groups so that only authorized administrators can interact with service changes and service binary target path locations. Deny execution from user directories such as file download directories and temp directories where able.

            Ensure that proper permissions and directory access control are set to deny users the ability to write files to the top-level directory C: and system directories, such as C:\\Windows\\, to reduce places where malicious files could be placed for execution.`,
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1674",
    name: "Input Injection",
    tactic: "Execution",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "input-injection",
          "keystroke",
          "fake-input",
          "synthetic-input",
        ])
      )
        s += 65;

      if (hasTagPartial(n, ["input", "keystroke"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["input", "keystroke"])) {
        r.push("IOC associated with malicious input injection");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1038",
        name: "Execution Prevention",
        description:
          "Denylist scripting and use application control where appropriate. For example, PowerShell Constrained Language mode can be used to restrict access to sensitive or otherwise dangerous language elements such as those used to execute arbitrary Windows APIs or files (e.g., Add-Type)",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1034",
        name: "Limit Hardware Installation",
        description:
          "Limit the use of USB devices and removable media within a network.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1559",
    name: "Inter-Process Communication",
    tactic: "Execution",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "ipc",
          "named-pipe",
          "rpc",
          "process-communication",
        ])
      )
        s += 60;

      if (hasTagPartial(n, ["pipe", "rpc", "ipc"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["ipc", "pipe", "rpc"])) {
        r.push("IOC associated with malicious inter-process communication");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description:
          "On Windows 10, enable Attack Surface Reduction (ASR) rules to prevent DDE attacks and spawning of child processes from Office programs.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1013",
        name: "Application Developer Guidance",
        description:
          "Enable the Hardened Runtime capability when developing applications. Do not include the com.apple.security.get-task-allow entitlement with the value set to any variation of true.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1048",
        name: "Application Isolation and Sandboxing",
        description:
          "Ensure all COM alerts and Protected View are enabled",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description:
          "Registry keys specific to Microsoft Office feature control security can be set to disable automatic DDE/OLE execution. Microsoft also created, and enabled by default, Registry keys to completely disable DDE execution in Word and Excel.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "Privileged Account Management",
        description:
          `Modify Registry settings (directly or using Dcomcnfg.exe) in HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\AppID\\{AppID_GUID} associated with the process-wide security of individual COM applications.

          Modify Registry settings (directly or using Dcomcnfg.exe) in HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Ole associated with system-wide security defaults for all COM applications that do no set their own process-wide security.`,
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1054",
        name: "Software Configuration",
        description:
          "Consider disabling embedded files in Office programs, such as OneNote, that do not work with Protected View.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1106",
    name: "Native API",
    tactic: "Execution",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "winapi",
          "native-api",
          "ntdll",
          "syscall",
        ])
      )
        s += 65;

      if (hasTagPartial(n, ["api", "syscall", "ntdll"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["syscall", "ntdll"])) {
        r.push("IOC associated with native API abuse");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description:
          "On Windows 10, enable Attack Surface Reduction (ASR) rules to prevent Office VBA macros from calling Win32 APIs.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1038",
        name: "Execution Prevention",
        description:
          "Identify and block potentially malicious software executed that may be executed through this technique by using application control tools, like Windows Defender Application Control, AppLocker, or Software Restriction Policies where appropriate.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1053",
    name: "Scheduled Task/Job",
    tactic: "Execution",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "schtasks",
          "cron",
          "task-scheduler",
          "scheduled-job",
        ])
      )
        s += 65;

      if (hasTagPartial(n, ["cron", "schtasks", "task"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["cron", "schtasks"])) {
        r.push("IOC associated with scheduled task execution");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1026",
        name: "Privileged Account Management",
        description:
          "Configure the Increase Scheduling Priority option to only allow the Administrators group the rights to schedule a priority process. This can be can be configured through GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > User Rights Assignment: Increase scheduling priority.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1047",
        name: "Audit",
        description:
          "Toolkits like the PowerSploit framework contain PowerUp modules that can be used to explore systems for permission weaknesses in scheduled tasks that could be used to escalate privileges.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1028",
        name: "Operating System Configuration",
        description:
          "Configure settings for scheduled tasks to force tasks to run under the context of the authenticated account instead of allowing them to run as SYSTEM. The associated Registry key is located at HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\SubmitControl. The setting can be configured through GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > Security Options: Domain Controller: Allow server operators to schedule tasks, set to disabled.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description:
          "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description:
          "Limit privileges of user accounts and remediate Privilege Escalation vectors so only authorized administrators can create scheduled tasks on remote systems.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1648",
    name: "Serverless Execution",
    tactic: "Execution",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "lambda",
          "azure-function",
          "serverless",
          "cloud-function",
        ])
      )
        s += 65;

      if (hasTagPartial(n, ["lambda", "function", "serverless"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["serverless", "lambda"])) {
        r.push("IOC associated with malicious serverless execution");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1036",
        name: "Account Use Policies",
        description:
          "Where possible, consider restricting access to and use of serverless functions. For examples, conditional access policies can be applied to users attempting to create workflows in Microsoft Power Automate. Google Apps Scripts that use OAuth can be limited by restricting access to high-risk OAuth scopes",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description:
          "Remove permissions to create, modify, or run serverless resources from users that do not explicitly require them.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1129",
    name: "Shared Modules",
    tactic: "Execution",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "shared-library",
          "dll",
          "so-file",
          "module-load",
        ])
      )
        s += 65;

      if (hasTagPartial(n, ["dll", "shared", "module"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["dll", "module"])) {
        r.push("IOC associated with malicious shared module loading");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1038",
        name: "Execution Prevention",
        description:
          "Identify and block potentially malicious software executed through this technique by using application control tools capable of preventing unknown modules from being loaded.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1569",
    name: "System Services",
    tactic: "Execution",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "service-create",
          "service-execution",
          "windows-service",
        ])
      )
        s += 65;

      if (hasTagPartial(n, ["service", "svc"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["service", "svc"])) {
        r.push("IOC associated with malicious system service execution");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description:
          "On Windows 10, enable Attack Surface Reduction (ASR) rules to block processes created by PsExec from running.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "Privileged Account Management",
        description:
          "Ensure that permissions disallow services that run at a higher permissions level from being created or interacted with by a user with a lower permission level.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description:
          "Ensure that high permission level service binaries cannot be replaced or modified by users with a lower permission level.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description:
          "Prevent users from installing their own launch agents or launch daemons.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1127",
    name: "Trusted Developer Utilities Proxy Execution",
    tactic: "Execution",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "msbuild",
          "installutil",
          "regsvr32",
          "trusted-utility",
        ])
      )
        s += 70;

      if (hasTagPartial(n, ["msbuild", "regsvr32", "installutil"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["regsvr32", "msbuild"])) {
        r.push("IOC associated with proxy execution via trusted utilities");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1038",
        name: "Execution Prevention",
        description:
          "Certain developer utilities should be blocked or restricted if not required.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description:
          "Specific developer utilities may not be necessary within a given environment and should be removed if not used.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1021",
        name: "Restrict Web-Based Content",
        description:
          "Consider disabling software installation or execution from the internet via developer utilities.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1047",
    name: "Windows Management Instrumentation",
    tactic: "Execution",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "wmi",
          "wmic",
          "powershell-wmi",
        ])
      )
        s += 70;

      if (hasTagPartial(n, ["wmi", "wmic"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["wmi", "wmic"])) {
        r.push("IOC associated with malicious WMI execution");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description:
          "On Windows 10, enable Attack Surface Reduction (ASR) rules to block processes created by WMI commands from running. Note: many legitimate tools and applications utilize WMI for command execution.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1038",
        name: "Execution Prevention",
        description:
          "Use application control configured to block execution of wmic.exe if it is not required for a given system or network to prevent potential misuse by adversaries. For example, in Windows 10 and Windows Server 2016 and above, Windows Defender Application Control (WDAC) policy rules may be applied to block the wmic.exe application and to prevent abuse",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "Privileged Account Management",
        description:
          "Prevent credential overlap across systems of administrator and privileged accounts.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description:
          "By default, only administrators are allowed to connect remotely using WMI. Restrict other users who are allowed to connect, or disallow all users to connect remotely to WMI.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  // TA0003 — PERSISTENCE
  {
    technique: "T1098",
    name: "Account Manipulation",
    tactic: "Persistence",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["account-manipulation", "backdoor-account", "persistence"])) s += 60;
      if (n.misp_confidence === "High") s += 20;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["account-manip", "backdoor-account"])) r.push("IOC associated with account manipulation for persistence");
      return r;
    },
    mitigations: [
      {
        id: "M1026",
        name: "Privileged Account Management",
        description: "Do not allow domain administrator accounts to be used for day-to-day operations that may expose them to potential adversaries on unprivileged systems.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description: "Remove unnecessary and potentially abusable authentication and authorization mechanisms where possible.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1030",
        name: "Network Segmentation",
        description: "Configure access controls and firewalls to limit access to critical systems and domain controllers. Most cloud environments support separate virtual private cloud (VPC) instances that enable further segmentation of cloud systems.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1028",
        name: "	Operating System Configuration",
        description: "Protect domain controllers by ensuring proper security configuration for critical servers to limit access by potentially unnecessary protocols and services, such as SMB file sharing.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description: "Restrict access to potentially sensitive files that deal with authentication and/or authorization.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description: "Ensure that low-privileged user accounts do not have permissions to modify accounts or account-related policies.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description: "Use multi-factor authentication for user and privileged accounts.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1543",
    name: "Create or Modify System Process",
    tactic: "Persistence",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["service", "systemd", "launchdaemon", "persistence"])) s += 55;
      if (n.type.includes("hash") && hasTagPartial(n, ["service", "process"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["service", "persistence"])) r.push("IOC linked to service/process persistence mechanism");
      return r;
    },
    mitigations: [
      {
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description: "Restrict read/write access to system-level process files to only select privileged users who have a legitimate need to manage system services.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1047",
        name: "Audit",
        description: "Use auditing tools capable of detecting privilege and service abuse opportunities on systems within an enterprise and correct them.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description: "On Windows 10, enable Attack Surface Reduction (ASR) rules to prevent an application from writing a signed vulnerable driver to the system. On Windows 10 and 11, enable Microsoft Vulnerable Driver Blocklist to assist in hardening against third party-developed drivers",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1045",
        name: "Code Signing",
        description: "Enforce registration and execution of only legitimately signed service drivers where possible.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1033",
        name: "Limit Software Installation",
        description: "Restrict software installation to trusted repositories only and be cautious of orphaned software packages.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1028",
        name: "Operating System Configuration",
        description: "Ensure that Driver Signature Enforcement is enabled to restrict unsigned drivers from being installed.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "Privileged Account Management",
        description: "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1054",
        name: "Software Configuration",
        description: "Where possible, consider enforcing the use of container services in rootless mode to limit the possibility of privilege escalation or malicious effects on the host running the container.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description: "Limit privileges of user accounts and groups so that only authorized administrators can interact with system-level process changes and service configurations.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1547",
    name: "Boot or Logon Autostart Execution",
    tactic: "Persistence",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["autorun", "startup", "registry-run", "persistence"])) s += 55;
      if (n.type.includes("hash") && hasTagPartial(n, ["autorun", "startup", "registry"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["autorun", "startup", "registry-run"])) r.push("IOC associated with autostart persistence via registry/startup");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1505",
    name: "Server Software Component",
    tactic: "Persistence",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["webshell", "shell", "backdoor"])) s += 70;
      if (n.type === "url" && hasTagPartial(n, ["shell", "cmd", "exec"])) s += 35;
      if (n.type.includes("hash") && hasTagPartial(n, ["webshell"])) s += 50;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["webshell"])) r.push("IOC is a known webshell/server backdoor");
      if (hasTagPartial(n, ["backdoor"])) r.push("Tags indicate persistent server-side backdoor");
      return r;
    },
    mitigations: [
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description: "Consider disabling software components from servers when possible to prevent abuse by adversaries.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1047",
        name: "Audit",
        description: "Regularly check component software on critical services that adversaries may target for persistence to verify the integrity of the systems and identify if unexpected changes have been made.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1045",
        name: "Code Signing",
        description: "Ensure all application component binaries are signed by the correct application developers.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "Privileged Account Management",
        description: "Do not allow administrator accounts that have permissions to add component software on these services to be used for day-to-day operations that may expose them to potential adversaries on unprivileged systems.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1024",
        name: "Restrict Registry Permissions",
        description: "Consider using Group Policy to configure and block modifications to service and other critical server parameters in the Registry.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description: "Enforce the principle of least privilege by limiting privileges of user accounts so only authorized accounts can modify and/or add server software components.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1136",
    name: "Create Account",
    tactic: "Persistence",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["new-account", "create-account", "backdoor-user"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["create-account", "backdoor-user"])) r.push("IOC linked to unauthorized account creation for persistence");
      return r;
    },
    mitigations: [
      {
        id: "M1026",
        name: "Privileged Account Management",
        description: "Limit the number of accounts with permissions to create other accounts. Do not allow domain administrator accounts to be used for day-to-day operations that may expose them to potential adversaries on unprivileged systems.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1028",
        name: "Operating System Configuration",
        description: "Protect domain controllers by ensuring proper security configuration for critical servers.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1030",
        name: "Network Segmentation",
        description: "Configure access controls and firewalls to limit access to domain controllers and systems used to create and manage accounts.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description: "Use multi-factor authentication for user and privileged accounts.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1037",
    name: "Boot or Logon Initialization Scripts",
    tactic: "Persistence",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "logon-script",
          "startup-script",
          "init-script",
          "login-script",
        ])
      )
        s += 60;

      if (hasTagPartial(n, ["script", "startup", "logon"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["startup-script", "logon-script"])) {
        r.push("IOC associated with boot/logon initialization script persistence");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description:
          "Restrict write access to logon scripts to specific administrators.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1024",
        name: "Restrict Registry Permissions",
        description:
          "Ensure proper permissions are set for Registry hives to prevent users from modifying keys for logon scripts that may lead to persistence.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1671",
    name: "Cloud Application Integration",
    tactic: "Persistence",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "oauth-app",
          "cloud-app",
          "malicious-oauth",
          "api-consent",
        ])
      )
        s += 65;

      if (hasTagPartial(n, ["oauth", "cloud-app", "integration"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["oauth", "integration"])) {
        r.push("IOC associated with malicious cloud application integration");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1047",
        name: "Audit",
        description:
          "Periodically review SaaS integrations for unapproved or potentially malicious applications.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description:
          "Do not allow users to add new application integrations into a SaaS environment. In Entra ID environments, consider enforcing the 'Do not allow user consent' option.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1554",
    name: "Compromise Host Software Binary",
    tactic: "Persistence",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "trojanized-binary",
          "binary-replacement",
          "patched-executable",
        ])
      )
        s += 70;

      if (hasTagPartial(n, ["binary", "trojanized", "patched"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["trojanized", "binary"])) {
        r.push("IOC associated with compromised host software binary");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1045",
        name: "Code Signing",
        description:
          "Ensure all application component binaries are signed by the correct application developers.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1546",
    name: "Event Triggered Execution",
    tactic: "Persistence",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "wmi-event",
          "event-trigger",
          "event-subscription",
          "scheduled-trigger",
        ])
      )
        s += 65;

      if (hasTagPartial(n, ["event", "trigger", "subscription"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["event-trigger", "wmi-event"])) {
        r.push("IOC associated with event-triggered persistence execution");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1026",
        name: "Privileged Account Management",
        description:
          "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1051",
        name: "Update Software",
        description:
          "Perform regular software updates to mitigate exploitation risk.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1668",
    name: "Exclusive Control",
    tactic: "Persistence",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "lockout",
          "exclusive-control",
          "account-lock",
          "resource-lock",
        ])
      )
        s += 60;

      if (hasTagPartial(n, ["exclusive", "lockout", "resource"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["lockout", "exclusive"])) {
        r.push("IOC associated with adversary-exclusive resource control");
      }

      return r;
    },

    mitigations: [
      {
        id: "-",
        name: "-",
        description:
          "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1525",
    name: "Implant Internal Image",
    tactic: "Persistence",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "container-image",
          "vm-image",
          "golden-image",
          "image-implant",
        ])
      )
        s += 70;

      if (hasTagPartial(n, ["image", "implant", "container"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["golden-image", "implant"])) {
        r.push("IOC associated with implanted internal image persistence");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1045",
        name: "Code Signing",
        description:
          "Several cloud service providers support content trust models that require container images be signed by trusted sources.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1047",
        name: "Audit",
        description:
          "Periodically check the integrity of images and containers used in cloud deployments to ensure they have not been modified to include malicious software.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "Privileged Account Management",
        description:
          "Limit permissions associated with creating and modifying platform images or containers based on the principle of least privilege.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1556",
    name: "Modify Authentication Process",
    tactic: "Persistence",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "credential-provider",
          "auth-modification",
          "lsa",
          "pam",
        ])
      )
        s += 70;

      if (hasTagPartial(n, ["auth", "pam", "lsa"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["auth", "lsa", "pam"])) {
        r.push("IOC associated with authentication process modification");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1027",
        name: "Password Policies",
        description:
          "Ensure that AllowReversiblePasswordEncryption property is set to disabled unless there are application requirements.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1047",
        name: "Audit",
        description:
          `Review authentication logs to ensure that mechanisms such as enforcement of MFA are functioning as intended.

            Periodically review the hybrid identity solution in use for any discrepancies. For example, review all Pass Through Authentication (PTA) agents in the Azure Management Portal to identify any unwanted or unapproved ones. If ADFS is in use, review DLLs and executable files in the AD FS and Global Assembly Cache directories to ensure that they are signed by Microsoft. Note that in some cases binaries may be catalog-signed, which may cause the file to appear unsigned when viewing file properties.

            Periodically review for new and unknown network provider DLLs within the Registry (HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\<NetworkProviderName>\\NetworkProvider\\ProviderPath). Ensure only valid network provider DLLs are registered. The name of these can be found in the Registry key at HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order, and have corresponding service subkey pointing to a DLL at HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\<NetworkProviderName>\\NetworkProvider.`,
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description:
          "Integrating multi-factor authentication (MFA) as part of organizational policy can greatly reduce the risk of an adversary gaining control of valid credentials that may be used for additional tactics such as initial access, lateral movement, and collecting information. MFA can also be used to restrict access to cloud resources and APIs.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1028",
        name: "Operating System Configuration",
        description:
          `Ensure only valid password filters are registered. Filter DLLs must be present in Windows installation directory (C:\\Windows\\System32\\ by default) of a domain controller and/or local computer with a corresponding entry in HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Notification Packages.

        Starting in Windows 11 22H2, the EnableMPRNotifications policy can be disabled through Group Policy or through a configuration service provider to prevent Winlogon from sending credentials to network providers.`,
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "Operating System Configuration",
        description:
          `Audit domain and local accounts as well as their permission levels routinely to look for situations that could allow an adversary to gain wide access by obtaining credentials of a privileged account. These audits should also include if default accounts have been enabled, or if new local accounts are created that have not be authorized. Follow best practices for design and administration of an enterprise network to limit privileged account use across administrative tiers.

          Limit access to the root account and prevent users from modifying protected components through proper privilege separation (ex SELinux, grsecurity, AppArmor, etc.) and limiting Privilege Escalation opportunities.

          Limit on-premises accounts with access to the hybrid identity solution in place. For example, limit Azure AD Global Administrator accounts to only those required, and ensure that these are dedicated cloud-only accounts rather than hybrid ones.`,
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1025",
        name: "Privileged Process Integrity",
        description:
          "Enabled features, such as Protected Process Light (PPL), for LSA.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description:
          "Restrict write access to the /Library/Security/SecurityAgentPlugins directory.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1024",
        name: "Restrict Registry Permissions",
        description:
          "Restrict Registry permissions to disallow the modification of sensitive Registry keys such as HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description:
          "Ensure that proper policies are implemented to dictate the the secure enrollment and deactivation of authentication mechanisms, such as MFA, for user accounts.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1112",
    name: "Modify Registry",
    tactic: "Persistence",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "registry",
          "regedit",
          "registry-modification",
          "run-key",
        ])
      )
        s += 65;

      if (hasTagPartial(n, ["registry", "run-key", "regedit"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["registry", "run-key"])) {
        r.push("IOC associated with registry modification persistence");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1024",
        name: "Restrict Registry Permissions",
        description:
          "Ensure proper permissions are set for Registry hives to prevent users from modifying keys for system components that may lead to privilege escalation.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1137",
    name: "Office Application Startup",
    tactic: "Persistence",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "office-macro",
          "office-startup",
          "word-template",
          "excel-addin",
        ])
      )
        s += 65;

      if (hasTagPartial(n, ["macro", "office", "template"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["macro", "office"])) {
        r.push("IOC associated with Office startup persistence");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description:
          "On Windows 10, enable Attack Surface Reduction (ASR) rules to prevent Office applications from creating child processes and from writing potentially malicious executable content to disk.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description:
          `Follow Office macro security best practices suitable for your environment. Disable Office VBA macros from executing.

          Disable Office add-ins. If they are required, follow best practices for securing them by requiring them to be signed and disabling user notification for allowing add-ins. For some add-ins types (WLL, VBA) additional mitigation is likely required as disabling add-ins in the Office Trust Center does not disable WLL nor does it prevent VBA code from executing.`,
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1054",
        name: "Software Configuration",
        description:
          "For the Office Test method, create the Registry key used to execute it and set the permissions to 'Read Control' to prevent easy access to the key without administrator permissions or requiring Privilege Escalation.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1051",
        name: "Update Software",
        description:
          "For the Outlook methods, blocking macros may be ineffective as the Visual Basic engine used for these features is separate from the macro scripting engine. Microsoft has released patches to try to address each issue. Ensure KB3191938 which blocks Outlook Visual Basic and displays a malicious code warning, KB4011091 which disables custom forms by default, and KB4011162 which removes the legacy Home Page feature, are applied to systems.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1653",
    name: "Power Settings",
    tactic: "Persistence",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "powercfg",
          "sleep-modification",
          "hibernate-disable",
        ])
      )
        s += 60;

      if (hasTagPartial(n, ["powercfg", "hibernate", "sleep"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["powercfg", "hibernate"])) {
        r.push("IOC associated with malicious power setting modifications");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1047",
        name: "Audit",
        description:
          "Periodically inspect systems for abnormal and unexpected power settings that may indicate malicious activity.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1542",
    name: "Pre-OS Boot",
    tactic: "Persistence",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "bootkit",
          "uefi",
          "bios-malware",
          "mbr",
        ])
      )
        s += 75;

      if (hasTagPartial(n, ["bootkit", "uefi", "mbr"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["bootkit", "uefi"])) {
        r.push("IOC associated with pre-OS boot persistence");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1046",
        name: "Boot Integrity",
        description:
          "Use Trusted Platform Module technology and a secure or trusted boot process to prevent system integrity from being compromised. Check the integrity of the existing BIOS or EFI to determine if it is vulnerable to modification.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1047",
        name: "Audit",
        description:
          "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1035",
        name: "Limit Access to Resource Over Network",
        description:
          "Prevent access to file shares, remote access to systems, unnecessary services. Mechanisms to limit access may include use of network concentrators, RDP gateways, etc.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "Privileged Account Management",
        description:
          "Ensure proper permissions are in place to help prevent adversary access to privileged accounts necessary to perform these actions",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1051",
        name: "Update Software",
        description:
          "Patch the BIOS and EFI as necessary.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1176",
    name: "Software Extensions",
    tactic: "Persistence",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "browser-extension",
          "plugin",
          "extension",
          "add-on",
        ])
      )
        s += 65;

      if (hasTagPartial(n, ["extension", "plugin", "addon"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["browser-extension", "plugin"])) {
        r.push("IOC associated with malicious software extensions");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1047",
        name: "Audit",
        description:
          "Ensure extensions that are installed are the intended ones, as many malicious extensions may masquerade as legitimate ones.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1038",
        name: "Execution Prevention",
        description:
          "Set an extension allow or deny list as appropriate for your security policy.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1033",
        name: "Limit Software Installation",
        description:
          "Only install extensions from trusted sources that can be verified.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1051",
        name: "Update Software",
        description:
          "Ensure operating systems and software are using the most current version.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1017",
        name: "User Training",
        description:
          "Train users to minimize extension use, and to only install trusted extensions.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1205",
    name: "Traffic Signaling",
    tactic: "Persistence",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "beacon",
          "traffic-signal",
          "network-trigger",
          "magic-packet",
        ])
      )
        s += 65;

      if (hasTagPartial(n, ["beacon", "trigger", "signal"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["beacon", "traffic-signal"])) {
        r.push("IOC associated with traffic signaling persistence");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description:
          "Mitigation of some variants of this technique could be achieved through the use of stateful firewalls, depending upon how it is implemented.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description:
          "Disable Wake-on-LAN if it is not needed within an environment.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  // TA0004 — PRIVILEGE ESCALATION
  {
    technique: "T1068",
    name: "Exploitation for Privilege Escalation",
    tactic: "Privilege Escalation",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["exploit", "privesc", "privilege-escalation", "lpe", "eop"])) s += 65;
      if (n.type.includes("hash") && hasTagPartial(n, ["exploit", "privesc", "priv"])) s += 30;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["privesc", "privilege-esc", "lpe"])) r.push("IOC associated with local privilege escalation exploit");
      return r;
    },
    mitigations: [
      {
        id: "M1051",
        name: "Update Software",
        description: "Update software regularly by employing patch management for internal enterprise endpoints and servers.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1048",
        name: "Application Isolation and Sandboxing",
        description: "Make it difficult for adversaries to advance their operation through exploitation of undiscovered or unpatched vulnerabilities by using sandboxing. Other types of virtualization and application microsegmentation may also mitigate the impact of some types of exploitation. Risks of additional exploits and weaknesses in these systems may still exist.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1038",
        name: "Execution Prevention",
        description: "Consider blocking the execution of known vulnerable drivers that adversaries may exploit to execute code in kernel mode. Validate driver block rules in audit mode to ensure stability prior to production deployment.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1050",
        name: "Exploit Protection",
        description: "Security applications that look for behavior used during exploitation such as Windows Defender Exploit Guard (WDEG) and the Enhanced Mitigation Experience Toolkit (EMET) can be used to mitigate some exploitation behavior. Control flow integrity checking is another way to potentially identify and stop a software exploit from occurring. Many of these protections depend on the architecture and target application binary for compatibility and may not work for software components targeted for privilege escalation.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1019",
        name: "Threat Intelligence Program",
        description: "Develop a robust cyber threat intelligence capability to determine what types and levels of threat may use software exploits and 0-days against a particular organization.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1548",
    name: "Abuse Elevation Control Mechanism",
    tactic: "Privilege Escalation",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["uac-bypass", "sudo-abuse", "setuid", "elevation"])) s += 65;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["uac-bypass", "sudo", "elevation"])) r.push("IOC associated with UAC/sudo elevation control bypass");
      return r;
    },
    mitigations: [
      {
        id: "M1026",
        name: "Privileged Account Management",
        description: "Remove users from the local administrator group on systems. By requiring a password, even if an adversary can get terminal access, they must know the password to run anything in the sudoers file. Setting the timestamp_timeout to 0 will require the user to input their password every time sudo is executed.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1047",
        name: "Audit",
        description: "Check for common UAC bypass weaknesses on Windows systems to be aware of the risk posture and address issues where appropriate.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1038",
        name: "Execution Prevention",
        description: "System settings can prevent applications from running that haven't been downloaded from legitimate repositories which may help mitigate some of these issues. Not allowing unsigned applications from being run may also mitigate some risk.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1028",
        name: "Operating System Configuration",
        description: "Applications with known vulnerabilities or known shell escapes should not have the setuid or setgid bits set to reduce potential damage if an application is compromised. Additionally, the number of programs with setuid or setgid bits set should be minimized across a system. Ensuring that the sudo tty_tickets setting is enabled will prevent this leakage across tty sessions.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description: "The sudoers file should be strictly edited such that passwords are always required and that users can't spawn risky processes as users with higher privilege.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1051",
        name: "Update Software",
        description: "Perform regular software updates to mitigate exploitation risk.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1052",
        name: "User Account Control",
        description: "Although UAC bypass techniques exist, it is still prudent to use the highest enforcement level for UAC when possible and mitigate bypass opportunities that exist with techniques such as DLL.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description: "Limit the privileges of cloud accounts to assume, create, or impersonate additional roles, policies, and permissions to only those required. Where just-in-time access is enabled, consider requiring manual approval for temporary elevation of privileges.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1134",
    name: "Access Token Manipulation",
    tactic: "Privilege Escalation",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "token-manipulation",
          "token-theft",
          "token-impersonation",
          "se-debug",
        ])
      )
        s += 70;

      if (hasTagPartial(n, ["token", "impersonation", "privilege"])) s += 25;

      if (n.type.includes("hash")) s += 15;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["token", "impersonation"])) {
        r.push("IOC associated with access token manipulation or impersonation");
      }

      if (hasTagPartial(n, ["se-debug"])) {
        r.push("Tags indicate abuse of elevated token privileges");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1026",
        name: "Privileged Account Management",
        description:
          `Limit permissions so that users and user groups cannot create tokens. This setting should be defined for the local system account only. GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > User Rights Assignment: Create a token object. Also define who can create a process level token to only the local and network service through GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > User Rights Assignment: Replace a process level token.

          Administrators should log in as a standard user but run their tools with administrator privileges using the built-in access token manipulation command runas.`,
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description:
          "An adversary must already have administrator level access on the local system to make full use of this technique; be sure to restrict users and accounts to the least privileges they require.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1484",
    name: "Domain or Tenant Policy Modification",
    tactic: "Privilege Escalation",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "gpo-modification",
          "tenant-policy",
          "policy-change",
          "domain-policy",
        ])
      )
        s += 70;

      if (hasTagPartial(n, ["gpo", "policy", "tenant"])) s += 25;

      if (n.misp_confidence === "High") s += 10;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["gpo", "domain-policy"])) {
        r.push("IOC associated with unauthorized domain policy modification");
      }

      if (hasTagPartial(n, ["tenant-policy"])) {
        r.push("IOC linked to cloud tenant policy abuse");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1026",
        name: "Privileged Account Management",
        description:
          "Use least privilege and protect administrative access to the Domain Controller and Active Directory Federation Services (AD FS) server. Do not create service accounts with administrative privileges.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1047",
        name: "Audit",
        description:
          "Identify and correct GPO permissions abuse opportunities (ex: GPO modification privileges) using auditing tools such as BloodHound (version 1.5.1 and later).",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description:
          "Consider implementing WMI and security filtering to further tailor which users and computers a GPO will apply to.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1611",
    name: "Escape to Host",
    tactic: "Privilege Escalation",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "container-escape",
          "vm-escape",
          "escape-to-host",
          "namespace-breakout",
        ])
      )
        s += 75;

      if (hasTagPartial(n, ["escape", "container", "vm"])) s += 25;

      if (n.type.includes("hash")) s += 10;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["container-escape", "vm-escape"])) {
        r.push("IOC associated with container or virtual machine escape");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1048",
        name: "Application Isolation and Sandboxing",
        description:
          "Consider utilizing seccomp, seccomp-bpf, or a similar solution that restricts certain system calls such as mount. In Kubernetes environments, consider defining Pod Security Standards that limit container access to host process namespaces, the host network, and the host file system.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1051",
        name: "Update Software",
        description:
          "Ensure that hosts are kept up-to-date with security patches.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1042",
        name: "	Disable or Remove Feature or Program",
        description:
          "Remove unnecessary tools and software from containers.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1038",
        name: "Execution Prevention",
        description:
          "Use read-only containers, read-only file systems, and minimal images when possible to prevent the running of commands. Where possible, also consider using application control and software restriction tools (such as those provided by SELinux) to restrict access to files, processes, and system calls in containers.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "Privileged Account Management",
        description:
          "Ensure containers are not running as root by default and do not use unnecessary privileges or mounted components. In Kubernetes environments, consider defining Pod Security Standards that prevent pods from running privileged containers.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1055",
    name: "Process Injection",
    tactic: "Privilege Escalation",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "process-injection",
          "dll-injection",
          "reflective-loader",
          "shellcode",
          "remote-thread",
        ])
      )
        s += 75;

      if (
        hasTagPartial(n, [
          "inject",
          "dll",
          "shellcode",
          "reflective",
        ])
      )
        s += 25;

      if (n.type.includes("hash")) s += 15;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["dll-injection", "shellcode"])) {
        r.push("IOC associated with malicious process injection activity");
      }

      if (hasTagPartial(n, ["reflective-loader"])) {
        r.push("Tags indicate reflective code loading into another process");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description:
          "Some endpoint security solutions can be configured to block some types of process injection based on common sequences of behavior that occur during the injection process. For example, on Windows 10, Attack Surface Reduction (ASR) rules may prevent Office applications from code injection.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "Privileged Account Management",
        description:
          "Utilize Yama (ex: /proc/sys/kernel/yama/ptrace_scope) to mitigate ptrace based process injection by restricting the use of ptrace to privileged users only. Other mitigation controls involve the deployment of security kernel modules that provide advanced access control and process restrictions such as SELinux, grsecurity, and AppArmor.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  // TA0005 — STEALTH
  {
    technique: "T1612",
    name: "Build Image on Host",
    tactic: "Stealth",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["container-build", "docker-build", "image-build"])) s += 65;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["docker-build", "image-build"])) r.push("IOC associated with building malicious images on-host");
      return r;
    },
    mitigations: [
      {
        id: "M1047",
        name: "Audit",
        description: "Audit images deployed within the environment to ensure they do not contain any malicious components.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1035",
        name: "Limit Access to Resource Over Network",
        description: "Limit communications with the container service to local Unix sockets or remote access via SSH. Require secure port access to communicate with the APIs over TLS by disabling unauthenticated access to the Docker API on port 2375. Instead, communicate with the Docker API over TLS on port 2376.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1030",
        name: "Network Segmentation",
        description: "Deny direct remote access to internal systems through the use of network proxies, gateways, and firewalls.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "Privileged Account Management",
        description: "Ensure containers are not running as root by default. In Kubernetes environments, consider defining Pod Security Standards that prevent pods from running privileged containers.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  
  {
    technique: "T1678",
    name: "Delay Execution",
    tactic: "Stealth",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["sleep", "delayed-execution", "stalling"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["sleep", "delay"])) r.push("IOC associated with delayed execution for stealth");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1140",
    name: "Deobfuscate/Decode Files or Information",
    tactic: "Stealth",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["decode", "deobfuscate", "base64-decode"])) s += 65;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["decode", "deobfuscate"])) r.push("IOC associated with payload decoding/deobfuscation");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1006",
    name: "Direct Volume Access",
    tactic: "Stealth",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["raw-disk-access", "volume-access"])) s += 70;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["raw-disk", "volume"])) r.push("IOC associated with direct volume/raw disk access");
      return r;
    },
    mitigations: [
      {
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description: "Some endpoint security solutions can be configured to block some types of behaviors related to efforts by an adversary to create backups, such as command execution or preventing API calls to backup related services.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description: "Ensure only accounts required to configure and manage backups have the privileges to do so. Monitor these accounts for unauthorized backup activity.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1480",
    name: "Execution Guardrails",
    tactic: "Stealth",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["execution-guardrail", "geo-fencing", "domain-check"])) s += 65;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["guardrail", "geo-fencing"])) r.push("IOC associated with execution guardrails");
      return r;
    },
    mitigations: [
      {
        id: "M1055",
        name: "Do Not Mitigate",
        description: "Execution Guardrails likely should not be mitigated with preventative controls because it may protect unintended targets from being compromised. If targeted, efforts should be focused on preventing adversary tools from running earlier in the chain of activity and on identifying subsequent malicious behavior if compromised.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1211",
    name: "Exploitation for Stealth",
    tactic: "Stealth",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["stealth-exploit", "silent-exploit"])) s += 65;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["silent-exploit", "stealth-exploit"])) r.push("IOC associated with stealth-oriented exploitation");
      return r;
    },
    mitigations: [
      {
        id: "M1048",
        name: "Application Isolation and Sandboxing",
        description: "Make it difficult for adversaries to advance their operation through exploitation of undiscovered or unpatched vulnerabilities by using sandboxing. Other types of virtualization and application microsegmentation may also mitigate the impact of some types of exploitation. Risks of additional exploits and weaknesses in these systems may still exist.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1050",
        name: "Exploit Protection",
        description: "Security applications that look for behavior used during exploitation such as Windows Defender Exploit Guard (WDEG) and the Enhanced Mitigation Experience Toolkit (EMET) can be used to mitigate some exploitation behavior. Control flow integrity checking is another way to potentially identify and stop a software exploit from occurring. Many of these protections depend on the architecture and target application binary for compatibility and may not work for software targeted for defense evasion.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1019",
        name: "Threat Intelligence Program",
        description: "Develop a robust cyber threat intelligence capability to determine what types and levels of threat may use software exploits and 0-days against a particular organization.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1051",
        name: "Update Software",
        description: "Update software regularly by employing patch management for internal enterprise endpoints and servers.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1564",
    name: "Hide Artifacts",
    tactic: "Stealth",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["hidden-file", "hidden-process", "artifact-hiding"])) s += 70;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["hidden", "artifact"])) r.push("IOC associated with hiding files/processes/artifacts");
      return r;
    },
    mitigations: [
      {
        id: "M1049",
        name: "Antivirus/Antimalware",
        description: "Review and audit file/folder exclusions, and limit scope of exclusions to only what is required where possible.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1013",
        name: "Application Developer Guidance",
        description: "Application developers should consider limiting the requirements for custom or otherwise difficult to manage file/folder exclusions. Where possible, install applications to trusted system folder paths that are already protected by restricted file and directory permissions.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1047",
        name: "Audit",
        description: "Periodically audit virtual machines for abnormalities.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1033",
        name: "Limit Software Installation",
        description: "Restrict the installation of software that may be abused to create hidden desktops, such as hVNC, to user groups that require it.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1070",
    name: "Indicator Removal",
    tactic: "Stealth",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["log-clear", "artifact-delete", "history-clear"])) s += 75;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["log-clear", "history-clear"])) r.push("IOC linked to indicator/log removal");
      return r;
    },
    mitigations: [
      {
        id: "M1041",
        name: "Encrypt Sensitive Information",
        description: "Obfuscate/encrypt event files locally and in transit to avoid giving feedback to an adversary.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1029",
        name: "Remote Data Storage",
        description: "Automatically forward events to a log server or data repository to prevent conditions in which the adversary can locate and manipulate data on the local system. When possible, minimize time delay on event reporting to avoid prolonged storage on the local system.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description: "Protect generated event files that are stored locally with proper permissions and authentication and limit opportunities for adversaries to increase privileges by preventing Privilege Escalation opportunities.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1202",
    name: "Indirect Command Execution",
    tactic: "Stealth",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["indirect-execution", "forfiles", "pcalua"])) s += 65;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["indirect", "forfiles"])) r.push("IOC associated with indirect command execution");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1036",
    name: "Masquerading",
    tactic: "Stealth",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["masquerading", "fake-process", "renamed-binary"])) s += 70;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["masquerade", "renamed"])) r.push("IOC associated with process/file masquerading");
      return r;
    },
    mitigations: [
      {
        id: "M1049",
        name: "Antivirus/Antimalware",
        description: "Anti-virus can be used to automatically quarantine suspicious files.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1047",
        name: "Audit",
        description: "Audit user accounts to ensure that each one has a defined purpose.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description: "Implement security controls on the endpoint, such as a Host Intrusion Prevention System (HIPS), to identify and prevent execution of potentially malicious files (such as those with mismatching file signatures).",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1045",
        name: "Code Signing",
        description: "Require signed binaries.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1038",
        name: "Execution Prevention",
        description: "Use tools that restrict program execution via application control by attributes other than file name for common operating system utilities that are needed.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description: "Use file system access controls to protect folders such as C:\\Windows\\System32.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description: "Consider defining and enforcing a naming convention for user accounts to more easily spot generic account names that do not fit the typical schema.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1017",
        name: "User Training",
        description: "Train users not to open email attachments or click unknown links (URLs). Such training fosters more secure habits within your organization and will limit many of the risks.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1027",
    name: "Obfuscated Files or Information",
    tactic: "Stealth",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["packed", "obfuscated", "encrypted-payload"])) s += 75;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["packed", "obfuscated"])) r.push("IOC associated with obfuscated payloads");
      return r;
    },
    mitigations: [
      {
        id: "M1049",
        name: "Antivirus/Antimalware",
        description: "Anti-virus can be used to automatically detect and quarantine suspicious files. Consider utilizing the Antimalware Scan Interface (AMSI) on Windows 10+ to analyze commands after being processed/interpreted.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1047",
        name: "Audit",
        description: "Consider periodic review of common fileless storage locations (such as the Registry or WMI repository) to potentially identify abnormal and malicious data.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description: "On Windows 10+, enable Attack Surface Reduction (ASR) rules to prevent execution of potentially obfuscated payloads.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1017",
        name: "User Training",
        description: "Ensure that a finite amount of ingress points to a software deployment system exist with restricted access for those required to allow and enable newly deployed software.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  
  {
    technique: "T1620",
    name: "Reflective Code Loading",
    tactic: "Stealth",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["reflective-loader", "memory-loader"])) s += 75;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["reflective", "memory-loader"])) r.push("IOC associated with reflective in-memory loading");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1014",
    name: "Rootkit",
    tactic: "Stealth",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["rootkit", "kernel-hook", "dkom"])) s += 85;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["rootkit", "kernel"])) r.push("IOC associated with rootkit activity");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1679",
    name: "Selective Exclusion",
    tactic: "Stealth",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["av-exclusion", "defender-exclusion"])) s += 70;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["exclusion", "defender"])) r.push("IOC associated with selective security exclusions");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1684",
    name: "Social Engineering",
    tactic: "Stealth",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["social-engineering", "impersonation", "pretexting"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["pretext", "impersonation"])) r.push("IOC associated with social engineering activity");
      return r;
    },
    mitigations: [
      {
        id: "M1036",
        name: "Account Use Policies",
        description: "Adds verification for helpdesk resets, approvals, and app consents commonly targeted by impersonation.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1047",
        name: "Audit",
        description: "Enables correlation of email/identity/SaaS/endpoint activity that appears legitimate.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1017",
        name: "User Training",
        description: "Reduces success of phishing/vishing/impersonation and modern 'human interface' lures.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1218",
    name: "System Binary Proxy Execution",
    tactic: "Stealth",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["lolbin", "rundll32", "regsvr32", "mshta"])) s += 75;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["rundll32", "regsvr32", "lolbin"])) r.push("IOC associated with LOLBin proxy execution");
      return r;
    },
    mitigations: [
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description: "Many native binaries may not be necessary within a given environment.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1038",
        name: "Execution Prevention",
        description: "Consider using application control to prevent execution of binaries that are susceptible to abuse and not required for a given system or network.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1050",
        name: "Exploit Protection",
        description: "Microsoft's Enhanced Mitigation Experience Toolkit (EMET) Attack Surface Reduction (ASR) feature can be used to block methods of using using trusted binaries to bypass application control.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "Privileged Account Management",
        description: "Restrict execution of particularly vulnerable binaries to privileged accounts or groups that need to use it to lessen the opportunities for malicious usage.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1021",
        name: "Restrict Web-Based Content",
        description: "Restrict use of certain websites, block downloads/attachments, block Javascript, restrict browser extensions, etc.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1216",
    name: "System Script Proxy Execution",
    tactic: "Stealth",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["pubprn", "syncappvpublishingserver", "script-proxy"])) s += 65;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["script-proxy", "pubprn"])) r.push("IOC associated with system script proxy execution");
      return r;
    },
    mitigations: [
      {
        id: "M1038",
        name: "Execution Prevention",
        description: "Certain signed scripts that can be used to execute other programs may not be necessary within a given environment. Use application control configured to block execution of these scripts if they are not required for a given system or network to prevent potential misuse by adversaries.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1221",
    name: "Template Injection",
    tactic: "Stealth",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["template-injection", "ssti"])) s += 70;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["ssti", "template"])) r.push("IOC associated with template injection exploitation");
      return r;
    },
    mitigations: [
      {
        id: "M1049",
        name: "Antivirus/Antimalware",
        description: "Network/Host intrusion prevention systems, antivirus, and detonation chambers can be employed to prevent documents from fetching and/or executing malicious payloads.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description: "Consider disabling Microsoft Office macros/active content to prevent the execution of malicious payloads in documents, though this setting may not mitigate the Forced Authentication use for this technique.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Network/Host intrusion prevention systems, antivirus, and detonation chambers can be employed to prevent documents from fetching and/or executing malicious payloads.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1017",
        name: "User Training",
        description: "Train users to identify social engineering techniques and spearphishing emails that could be used to deliver malicious documents.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1535",
    name: "Unused/Unsupported Cloud Regions",
    tactic: "Stealth",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["unused-cloud-region", "shadow-region"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["shadow-region", "unused-region"])) r.push("IOC associated with cloud region evasion");
      return r;
    },
    mitigations: [
      {
        id: "M1054",
        name: "Software Configuration",
        description: "Cloud service providers may allow customers to deactivate unused regions.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1220",
    name: "XSL Script Processing",
    tactic: "Stealth",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["xsl-script", "wmic-xsl", "msxsl"])) s += 70;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["msxsl", "xsl"])) r.push("IOC associated with XSL script proxy execution");
      return r;
    },
    mitigations: [
      {
        id: "M1038",
        name: "Execution Prevention",
        description: "If msxsl.exe is unnecessary, then block its execution to prevent abuse by adversaries.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  // TA0112 — DEFENSE IMPAIRMENT
  {
    technique: "T1686",
    name: "Disable or Modify System Firewall",
    tactic: "Defense Impairment",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "firewall-disable",
          "firewall-bypass",
          "iptables-flush",
          "disable-firewall",
        ])
      )
        s += 75;

      if (hasTagPartial(n, ["firewall", "iptables", "defender"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["firewall", "iptables"])) {
        r.push("IOC associated with firewall disabling or modification");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1047",
        name: "Audit",
        description:
          "Routinely check account role permissions to ensure only expected users and roles have permission to modify system firewalls.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description:
          "Ensure proper process and file permissions are in place to prevent adversaries from disabling or modifying firewall settings.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1024",
        name: "Restrict Registry Permissions",
        description:
          "Ensure proper Registry permissions are in place to prevent adversaries from disabling or modifying firewall settings.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description:
          "Ensure proper user permissions are in place to prevent adversaries from disabling or modifying firewall settings.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1685",
    name: "Disable or Modify Tools",
    tactic: "Defense Impairment",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "disable-av",
          "tamper-defender",
          "edr-kill",
          "security-tool-disable",
        ])
      )
        s += 80;

      if (hasTagPartial(n, ["disable", "av", "edr", "defender"])) s += 20;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["disable-av", "edr-kill"])) {
        r.push("IOC linked to disabling endpoint security tools");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1047",
        name: "Audit",
        description:
          "Periodically verify that tools are functioning appropriately - for example, that all expected hosts with EDRs or monitoring agents are checking in to the central console. Check EDRs to ensure that no unexpected exclusion paths have been added. In Microsoft Defender for Endpoint, exclusions can be reviewed with the Get-MpPreference cmdlet.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description:
          "Consider removing previous versions of tools that are unnecessary to the environment when possible.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1038",
        name: "	Execution Prevention",
        description:
          "Use application control where appropriate, especially regarding the execution of tools outside of the organization's security policies (such as rootkit removal tools) that have been abused to impair system defenses. Ensure that only approved security applications are used and running on enterprise systems.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description:
          "Ensure proper process and file permissions are in place to prevent adversaries from disabling or interfering with security services.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1024",
        name: "Restrict Registry Permissions",
        description:
          "Ensure proper Registry permissions are in place to prevent adversaries from disabling or interfering with security services.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1054",
        name: "Software Configuration",
        description:
          "Consider automatically relaunching forwarding mechanisms at recurring intervals (ex: temporal, on-logon, etc.) as well as applying appropriate change management to firewall rules and other related system configurations.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description:
          "Ensure proper user permissions are in place to prevent adversaries from disabling or interfering with security services.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1689",
    name: "Downgrade Attack",
    tactic: "Defense Impairment",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "downgrade-attack",
          "protocol-downgrade",
          "tls-downgrade",
        ])
      )
        s += 75;

      if (hasTagPartial(n, ["downgrade", "legacy-protocol"])) s += 20;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["downgrade"])) {
        r.push("IOC associated with protocol or security downgrade attack");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description:
          "Consider removing previous versions of tools that are unnecessary to the environment when possible.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1054",
        name: "Software Configuration",
        description:
          "Consider implementing policies on internal web servers, such HTTP Strict Transport Security, that enforce the use of HTTPS/network traffic encryption to prevent insecure connections.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1687",
    name: "Exploitation for Defense Impairment",
    tactic: "Defense Impairment",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "security-bypass",
          "av-bypass",
          "edr-bypass",
          "defense-evasion",
        ])
      )
        s += 75;

      if (hasTagPartial(n, ["bypass", "evasion", "disable"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["edr-bypass", "security-bypass"])) {
        r.push("IOC associated with exploitation to impair defenses");
      }

      return r;
    },

    mitigations: [
      {
        id: "-",
        name: "-",
        description:
          "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1222",
    name: "File and Directory Permissions Modification",
    tactic: "Defense Impairment",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "chmod",
          "permission-modification",
          "acl-change",
          "takeown",
        ])
      )
        s += 65;

      if (hasTagPartial(n, ["permission", "acl", "chmod"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["permission", "acl"])) {
        r.push("IOC linked to malicious file permission modification");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1026",
        name: "Privileged Account Management",
        description:
          "Ensure critical system files as well as those known to be abused by adversaries have restrictive permissions and are owned by an appropriately privileged account, especially if access is not required by users nor will inhibit system functionality.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description:
          "Applying more restrictive permissions to files and directories could prevent adversaries from modifying their access control lists. Additionally, ensure that user settings regarding local and remote symbolic links are properly set or disabled where unneeded.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1578",
    name: "Modify Cloud Compute Infrastructure",
    tactic: "Defense Impairment",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "cloud-instance-modification",
          "security-group-change",
          "cloud-tampering",
        ])
      )
        s += 75;

      if (hasTagPartial(n, ["cloud", "security-group", "compute"])) s += 20;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["security-group", "cloud"])) {
        r.push("IOC associated with unauthorized cloud infrastructure modification");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1047",
        name: "Audit",
        description:
          "Routinely monitor user permissions to ensure only the expected users have the capability to modify cloud compute infrastructure components.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description:
          "Limit permissions for creating, deleting, and otherwise altering compute components in accordance with least privilege. Organizations should limit the number of users within the organization with an IAM role that has administrative privileges, strive to reduce all permanent privileged role assignments, and conduct periodic entitlement reviews on IAM users, roles and policies.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1666",
    name: "Modify Cloud Resource Hierarchy",
    tactic: "Defense Impairment",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "cloud-policy-modification",
          "tenant-hierarchy",
          "subscription-modification",
        ])
      )
        s += 75;

      if (hasTagPartial(n, ["tenant", "subscription", "policy"])) s += 20;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["tenant", "subscription"])) {
        r.push("IOC linked to cloud resource hierarchy manipulation");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1047",
        name: "	Audit",
        description:
          "Periodically audit resource groups in the cloud management console to ensure that only expected items exist, especially close to the top of the hierarchy (e.g., AWS accounts and Azure subscriptions). Typically, top-level accounts (such as the AWS management account) should not contain any workloads or resources.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1054",
        name: "Software Configuration",
        description:
          "In Azure environments, consider setting a policy to block subscription transfers. In AWS environments, consider using Service Control Policies to prevent the use of the LeaveOrganization API call",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description:
          "Limit permissions to add, delete, or modify resource groups to only those required.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1601",
    name: "Modify System Image",
    tactic: "Defense Impairment",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "firmware-modification",
          "system-image",
          "boot-image",
        ])
      )
        s += 80;

      if (hasTagPartial(n, ["firmware", "boot-image"])) s += 20;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["firmware", "system-image"])) {
        r.push("IOC associated with malicious modification of system images");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1046",
        name: "Boot Integrity",
        description:
          "Some vendors of embedded network devices provide cryptographic signing to ensure the integrity of operating system images at boot time. Implement where available, following vendor guidelines.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1045",
        name: "Code Signing",
        description:
          "Many vendors provide digitally signed operating system images to validate the integrity of the software used on their platform. Make use of this feature where possible in order to prevent and/or detect attempts by adversaries to compromise the system image.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1043",
        name: "Credential Access Protection",
        description:
          "Some embedded network devices are capable of storing passwords for local accounts in either plain-text or encrypted formats. Ensure that, where available, local passwords are always encrypted, per vendor recommendations.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description:
          "Use multi-factor authentication for user and privileged accounts. Most embedded network devices support TACACS+ and/or RADIUS. Follow vendor prescribed best practices for hardening access control.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1027",
        name: "Password Policies",
        description:
          "Refer to NIST guidelines when creating password policies.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "	Privileged Account Management",
        description:
          "Restrict administrator accounts to as few individuals as possible, following least privilege principles. Prevent credential overlap across systems of administrator and privileged accounts, particularly between network and non-network platforms, such as servers or endpoints.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1599",
    name: "Network Boundary Bridging",
    tactic: "Defense Impairment",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "boundary-bridging",
          "dual-homed",
          "network-bridge",
        ])
      )
        s += 70;

      if (hasTagPartial(n, ["bridge", "dual-homed"])) s += 20;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["network-bridge", "dual-homed"])) {
        r.push("IOC associated with network boundary bridging activity");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description:
          "Upon identifying a compromised network device being used to bridge a network boundary, block the malicious packets using an unaffected network device in path, such as a firewall or a router that has not been compromised. Continue to monitor for additional activity and to ensure that the blocks are indeed effective.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1043",
        name: "Credential Access Protection",
        description:
          "Some embedded network devices are capable of storing passwords for local accounts in either plain-text or encrypted formats. Ensure that, where available, local passwords are always encrypted, per vendor recommendations.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description:
          "Use multi-factor authentication for user and privileged accounts. Most embedded network devices support TACACS+ and/or RADIUS. Follow vendor prescribed best practices for hardening access control.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1027",
        name: "Password Policies",
        description:
          "Refer to NIST guidelines when creating password policies.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "Privileged Account Management",
        description:
          "Restrict administrator accounts to as few individuals as possible, following least privilege principles. Prevent credential overlap across systems of administrator and privileged accounts, particularly between network and non-network platforms, such as servers or endpoints.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1647",
    name: "Plist File Modification",
    tactic: "Defense Impairment",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "plist-modification",
          "launchagent",
          "launchdaemon",
        ])
      )
        s += 70;

      if (hasTagPartial(n, ["plist", "launchagent"])) s += 20;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["plist", "launchdaemon"])) {
        r.push("IOC associated with macOS plist persistence or defense impairment");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1013",
        name: "Application Developer Guidance",
        description:
          "Ensure applications are using Apple's developer guidance which enables hardened runtime.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1690",
    name: "Prevent Command History Logging",
    tactic: "Defense Impairment",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "history-disable",
          "clear-history",
          "logging-disable",
        ])
      )
        s += 75;

      if (hasTagPartial(n, ["history", "logging"])) s += 20;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["clear-history", "logging-disable"])) {
        r.push("IOC associated with disabling command history or logs");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1039",
        name: "Environment Variable Permissions",
        description:
          "Prevent users from changing the HISTCONTROL, HISTFILE, and HISTFILESIZE environment variables.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1028",
        name: "	Operating System Configuration",
        description:
          "Make sure that the HISTCONTROL environment variable is set to 'ignoredups' instead of 'ignoreboth' or 'ignorespace'.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1207",
    name: "Rogue Domain Controller",
    tactic: "Defense Impairment",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "rogue-dc",
          "fake-domain-controller",
          "dcsync",
        ])
      )
        s += 80;

      if (hasTagPartial(n, ["domain-controller", "dcsync"])) s += 20;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["rogue-dc", "dcsync"])) {
        r.push("IOC linked to rogue domain controller activity");
      }

      return r;
    },

    mitigations: [
      {
        id: "-",
        name: "-",
        description:
          "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1688",
    name: "Safe Mode Boot",
    tactic: "Defense Impairment",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "safe-mode",
          "bootconfig-modification",
          "minimal-boot",
        ])
      )
        s += 75;

      if (hasTagPartial(n, ["safe-mode", "boot"])) s += 20;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["safe-mode"])) {
        r.push("IOC associated with Safe Mode abuse to bypass defenses");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1026",
        name: "Privileged Account Management",
        description:
          "Restrict administrator accounts to as few individuals as possible, following least privilege principles, that may be abused to remotely boot a machine in safe mode.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1054",
        name: "Software Configuration",
        description:
          "Ensure that endpoint defenses run in safe mode.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1553",
    name: "Subvert Trust Controls",
    tactic: "Defense Impairment",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "code-signing-bypass",
          "trust-bypass",
          "signed-malware",
        ])
      )
        s += 80;

      if (hasTagPartial(n, ["signed", "trust", "certificate"])) s += 20;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["trust-bypass", "signed-malware"])) {
        r.push("IOC associated with subversion of trust mechanisms");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1038",
        name: "Execution Prevention",
        description:
          "System settings can prevent applications from running that haven't been downloaded through the Apple Store (or other legitimate repositories) which can help mitigate some of these issues. Also enable application control solutions such as AppLocker and/or Device Guard to block the loading of malicious content.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1028",
        name: "Operating System Configuration",
        description:
          "Windows Group Policy can be used to manage root certificates and the Flags value of HKLM\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Root\\ProtectedRoots can be set to 1 to prevent non-administrator users from making further root installations into their own HKCU certificate store",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "Privileged Account Management",
        description:
          "Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1024",
        name: "Restrict Registry Permissions",
        description:
          "Ensure proper permissions are set for Registry hives to prevent users from modifying keys related to SIP and trust provider components. Components may still be able to be hijacked to suitable functions already present on disk if malicious modifications to Registry keys are not prevented.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1054",
        name: "Software Configuration",
        description:
          "HTTP Public Key Pinning (HPKP) is one method to mitigate potential Adversary-in-the-Middle situations where and adversary uses a mis-issued or fraudulent certificate to intercept encrypted communications by enforcing use of an expected certificate.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1600",
    name: "Weaken Encryption",
    tactic: "Defense Impairment",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "weak-encryption",
          "tls-downgrade",
          "crypto-disable",
        ])
      )
        s += 75;

      if (hasTagPartial(n, ["encryption", "tls", "crypto"])) s += 20;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["weak-encryption", "tls-downgrade"])) {
        r.push("IOC linked to weakening or bypassing encryption controls");
      }

      return r;
    },

    mitigations: [
      {
        id: "-",
        name: "-",
        description:
          "-",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  // TA0006 — CREDENTIAL ACCESS
  {
    technique: "T1110",
    name: "Brute Force",
    tactic: "Credential Access",
    score: (n) => {
      let s = 0;
      if (n.type === "ip") s += 15;
      if (hasTag(n, ["brute-force", "password-spray", "credential-stuffing"])) s += 55;
      if (n.abuse_score >= 40) s += 20;
      if (hasTagPartial(n, ["brute", "spray", "stuff"])) s += 20;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["brute", "spray", "stuff"])) r.push("IOC tagged as brute-force/credential attack source");
      if (n.abuse_score >= 40) r.push("AbuseIPDB score consistent with brute-force activity");
      return r;
    },
    mitigations: [
      {
        id: "M1036",
        name: "Account Use Policies",
        description: "Set account lockout policies after a certain number of failed login attempts to prevent passwords from being guessed. Too strict a policy may create a denial of service condition and render environments un-usable, with all accounts used in the brute force being locked-out. Use conditional access policies to block logins from non-compliant devices or from outside defined organization IP ranges.[32] Consider blocking risky authentication requests, such as those originating from anonymizing services/proxies.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description: "Use multi-factor authentication. Where possible, also enable multi-factor authentication on externally facing services.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1027",
        name: "Password Policies",
        description: "Refer to NIST guidelines when creating password policies.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description: "Proactively reset accounts that are known to be part of breached credentials either immediately, or after detecting bruteforce attempts.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1555",
    name: "Credentials from Password Stores",
    tactic: "Credential Access",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["credential-dumping", "mimikatz", "lsass", "password-store", "keyvault"])) s += 65;
      if (n.type.includes("hash") && hasTagPartial(n, ["mimikatz", "lsass", "cred-dump"])) s += 30;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["mimikatz", "lsass", "cred-dump"])) r.push("IOC associated with credential dumping tool (Mimikatz/LSASS)");
      return r;
    },
    mitigations: [
      {
        id: "M1027",
        name: "Password Policies",
        description: "The password for the user's login keychain can be changed from the user's login password. This increases the complexity for an adversary because they need to know an additional password. Organizations may consider weighing the risk of storing credentials in password stores and web browsers. If system, software, or web browser credential disclosure is a significant concern, technical controls, policy, and user training may be used to prevent storage of credentials in improper locations.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "Privileged Account Management",
        description: "Limit the number of accounts and services with permission to query information from password stores to only those required. Ensure that accounts and services with permissions to query password stores only have access to the secrets they require.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1051",
        name: "Update Software",
        description: "Perform regular software updates to mitigate exploitation risk.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1539",
    name: "Steal Web Session Cookie",
    tactic: "Credential Access",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["cookie-theft", "session-hijacking", "infostealer"])) s += 65;
      if (isMalwareFamily(n, ["redline", "vidar", "raccoon", "azorult", "stealc"])) s += 30;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["infostealer", "cookie-theft"])) r.push("IOC linked to session cookie theft / infostealer malware");
      return r;
    },
    mitigations: [
      {
        id: "M1054",
        name: "Software Configuration",
        description: "Configure browsers or tasks to regularly delete persistent cookies. Additionally, minimize the length of time a web cookie is viable to potentially reduce the impact of stolen cookies while also increasing the needed frequency of cookie theft attempts - providing defenders with additional chances at detection. For example, use non-persistent cookies to limit the duration a session ID will remain on the web client cache where an attacker could obtain it",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1047",
        name: "Audit",
        description: "Implement auditing for authentication activities and user logins to detect the use of stolen session cookies. Monitor for impossible travel scenarios and anomalous behavior that could indicate the use of compromised session tokens or cookies.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description: 
          `Deploy hardware-based token (e.g., YubiKey or FIDO key), which incorporates the target login domain as part of the negotiation protocol, will prevent session cookie theft through proxy methods.

          Implement Conditional Access policies to only allow logins from trusted devices, such as those enrolled in Intune or joined via Hybrid/Entra. This mitigates the risk of session cookie replay attacks by ensuring that stolen tokens cannot be reused on unauthorized devices.`,
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1021",
        name: "Restrict Web-Based Content",
        description: "Restrict or block web-based content that could be used to extract session cookies or credentials stored in browsers. Use browser security settings, such as disabling third-party cookies and restricting browser extensions, to limit the attack surface.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1051",
        name: "Update Software",
        description: "Regularly update web browsers, password managers, and all related software to the latest versions. Keeping software up-to-date reduces the risk of vulnerabilities being exploited by attackers to extract stored credentials or session cookies.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1017",
        name: "User Training",
        description: "Train users to identify aspects of phishing attempts where they're asked to enter credentials into a site that has the incorrect domain for the application they are logging into. Additionally, train users not to run untrusted JavaScript in their browser, such as by copying and pasting code or dragging and dropping bookmarklets.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1558",
    name: "Steal or Forge Kerberos Tickets",
    tactic: "Credential Access",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["golden-ticket", "silver-ticket", "kerberoasting", "as-rep-roasting", "kerberos"])) s += 70;
      if (isMalwareFamily(n, ["mimikatz", "rubeus", "impacket"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["golden-ticket", "kerberoast", "silver-ticket"])) r.push("IOC associated with Kerberos ticket theft/forging attack");
      return r;
    },
    mitigations: [
      {
        id: "M1026",
        name: "Privileged Account Management",
        description: 
          `Limit domain admin account permissions to domain controllers and limited servers. Delegate other admin functions to separate accounts.

          Limit service accounts to minimal required privileges, including membership in privileged groups such as Domain Administrators.`,
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1015",
        name: "Active Directory Configuration",
        description: "For containing the impact of a previously generated golden ticket, reset the built-in KRBTGT account password twice, which will invalidate any existing golden tickets that have been created with the KRBTGT hash and other Kerberos tickets derived from it. For each domain, change the KRBTGT account password once, force replication, and then change the password a second time. Consider rotating the KRBTGT account password every 180 days.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1047",
        name: "Audit",
        description: "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1043",
        name: "Credential Access Protection",
        description: "On Linux systems, protect resources with Security Enhanced Linux (SELinux) by defining entry points, process types, and file labels.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1041",
        name: "Encrypt Sensitive Information",
        description: "Enable AES Kerberos encryption (or another stronger encryption algorithm), rather than RC4, where possible.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1027",
        name: "Password Policies",
        description: "Ensure strong password length (ideally 25+ characters) and complexity for service accounts and that these passwords periodically expire. Also consider using Group Managed Service Accounts or another third party product such as password vaulting.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1557",
    name: "Adversary-in-the-Middle",
    tactic: "Credential Access",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "mitm",
          "adversary-in-the-middle",
          "arp-spoofing",
          "sslstrip",
        ])
      )
        s += 75;

      if (hasTagPartial(n, ["mitm", "spoof", "relay"])) s += 25;

      if (n.type === "ip") s += 10;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["mitm", "sslstrip"])) {
        r.push("IOC associated with adversary-in-the-middle interception");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1041",
        name: "Encrypt Sensitive Information",
        description:
          "Ensure that all wired and/or wireless traffic is encrypted appropriately. Use best practices for authentication protocols, such as Kerberos, and ensure web traffic that may contain credentials is protected by SSL/TLS.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description:
          "Disable legacy network protocols that may be used to intercept network traffic if applicable, especially those that are not needed within an environment.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description:
          "Use network appliances and host-based security software to block network traffic that is not necessary within the environment, such as legacy protocols that may be leveraged for AiTM conditions.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1035",
        name: "Limit Access to Resource Over Network",
        description:
          "Limit access to network infrastructure and resources that can be used to reshape traffic or otherwise produce AiTM conditions.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1030",
        name: "Network Segmentation",
        description:
          "Network segmentation can be used to isolate infrastructure components that do not require broad network access. This may mitigate, or at least alleviate, the scope of AiTM activity.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description:
          "Network intrusion detection and prevention systems that can identify traffic patterns indicative of AiTM activity can be used to mitigate activity at the network level.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1017",
        name: "	User Training",
        description:
          "Train users to be suspicious about certificate errors. Adversaries may use their own certificates in an attempt to intercept HTTPS traffic. Certificate errors may arise when the application’s certificate does not match the one expected by the host.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1212",
    name: "Exploitation for Credential Access",
    tactic: "Credential Access",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "credential-exploit",
          "credential-theft",
          "lsass-exploit",
        ])
      )
        s += 75;

      if (hasTagPartial(n, ["credential", "exploit", "dump"])) s += 20;

      if (n.type.includes("hash")) s += 10;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["credential-exploit", "lsass"])) {
        r.push("IOC associated with exploitation for credential theft");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1013",
        name: "Application Developer Guidance",
        description:
          "Application developers should consider taking measures to validate authentication requests by enabling one-time passwords, providing timestamps or sequence numbers for messages sent, using digital signatures, and/or using random session keys.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1048",
        name: "Application Isolation and Sandboxing",
        description:
          "Make it difficult for adversaries to advance their operation through exploitation of undiscovered or unpatched vulnerabilities by using sandboxing. Other types of virtualization and application microsegmentation may also mitigate the impact of some types of exploitation. Risks of additional exploits and weaknesses in these systems may still exist",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1050",
        name: "Exploit Protection",
        description:
          "Security applications that look for behavior used during exploitation such as Windows Defender Exploit Guard (WDEG) and the Enhanced Mitigation Experience Toolkit (EMET) can be used to mitigate some exploitation behavior. Control flow integrity checking is another way to potentially identify and stop a software exploit from occurring. Many of these protections depend on the architecture and target application binary for compatibility and may not work for software targeted for defense evasion.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1019",
        name: "Threat Intelligence Program",
        description:
          "Develop a robust cyber threat intelligence capability to determine what types and levels of threat may use software exploits and 0-days against a particular organization.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1051",
        name: "Update Software",
        description:
          "Update software regularly by employing patch management for internal enterprise endpoints and servers.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1187",
    name: "Forced Authentication",
    tactic: "Credential Access",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "forced-authentication",
          "ntlm-relay",
          "printerbug",
          "petitpotam",
        ])
      )
        s += 80;

      if (hasTagPartial(n, ["ntlm", "relay", "forced-auth"])) s += 20;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["ntlm-relay", "petitpotam"])) {
        r.push("IOC associated with forced authentication abuse");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description:
          "Block SMB traffic from exiting an enterprise network with egress filtering or by blocking TCP ports 139, 445 and UDP port 137. Filter or block WebDAV protocol traffic from exiting the network. If access to external resources over SMB and WebDAV is necessary, then traffic should be tightly limited with allowlisting.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1027",
        name: "Password Policies",
        description:
          "Use strong passwords to increase the difficulty of credential hashes from being cracked if they are obtained.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1606",
    name: "Forge Web Credentials",
    tactic: "Credential Access",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "session-forgery",
          "jwt-forgery",
          "cookie-forgery",
        ])
      )
        s += 75;

      if (hasTagPartial(n, ["jwt", "session", "cookie"])) s += 20;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["jwt-forgery", "cookie-forgery"])) {
        r.push("IOC associated with forged web authentication tokens");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1054",
        name: "Software Configuration",
        description:
          "Configure browsers/applications to regularly delete persistent web credentials (such as cookies).",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1047",
        name: "Audit",
        description:
          `Administrators should perform an audit of all access lists and the permissions they have been granted to access web applications and services. This should be done extensively on all resources in order to establish a baseline, followed up on with periodic audits of new or updated resources. Suspicious accounts/credentials should be investigated and removed.

          Enable advanced auditing on ADFS. Check the success and failure audit options in the ADFS Management snap-in. Enable Audit Application Generated events on the AD FS farm via Group Policy Object.`,
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "Privileged Account Management",
        description:
          "Restrict permissions and access to the AD FS server to only originate from privileged access workstations.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description:
          "Ensure that user accounts with administrative rights follow best practices, including use of privileged access workstations, Just in Time/Just Enough Administration (JIT/JEA), and strong authentication. Reduce the number of users that are members of highly privileged Directory Roles. In AWS environments, prohibit users from calling the sts:GetFederationToken API unless explicitly required.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1111",
    name: "Multi-Factor Authentication Interception",
    tactic: "Credential Access",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "mfa-interception",
          "evilginx",
          "mfa-phishing",
        ])
      )
        s += 80;

      if (hasTagPartial(n, ["mfa", "evilginx", "phishing"])) s += 20;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["evilginx", "mfa-phishing"])) {
        r.push("IOC associated with MFA interception framework");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1017",
        name: "User Training",
        description:
          "Remove smart cards when not in use.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1621",
    name: "Multi-Factor Authentication Request Generation",
    tactic: "Credential Access",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "mfa-fatigue",
          "push-bombing",
          "mfa-spam",
        ])
      )
        s += 80;

      if (hasTagPartial(n, ["fatigue", "push", "mfa"])) s += 20;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["mfa-fatigue", "push-bombing"])) {
        r.push("IOC associated with MFA fatigue or push bombing attack");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description:
          "Implement more secure 2FA/MFA mechanisms in replacement of simple push or one-click 2FA/MFA options. For example, having users enter a one-time code provided by the login screen into the 2FA/MFA application or utilizing other out-of-band 2FA/MFA mechanisms (such as rotating code-based hardware tokens providing rotating codes that need an accompanying user pin) may be more secure. Furthermore, change default configurations and implement limits upon the maximum number of 2FA/MFA request prompts that can be sent to users in period of time.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1036",
        name: "Account Use Policies",
        description:
          "Enable account restrictions to prevent login attempts, and the subsequent 2FA/MFA service requests, from being initiated from suspicious locations or when the source of the login attempts do not match the location of the 2FA/MFA smart device. Use conditional access policies to block logins from non-compliant devices or from outside defined organization IP ranges.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1017",
        name: "User Training",
        description:
          "Train users to only accept 2FA/MFA requests from login attempts they initiated, to review source location of the login attempt prompting the 2FA/MFA requests, and to report suspicious/unsolicited prompts.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1040",
    name: "Network Sniffing",
    tactic: "Credential Access",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "packet-sniffing",
          "wireshark",
          "tcpdump",
          "sniffer",
        ])
      )
        s += 70;

      if (hasTagPartial(n, ["sniff", "packet", "capture"])) s += 20;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["sniffer", "tcpdump"])) {
        r.push("IOC associated with credential interception via network sniffing");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1041",
        name: "Encrypt Sensitive Information",
        description:
          "Ensure that all wired and/or wireless traffic is encrypted appropriately. Use best practices for authentication protocols, such as Kerberos, and ensure web traffic that may contain credentials is protected by SSL/TLS.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description:
          "Use multi-factor authentication wherever possible.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1030",
        name: "Network Segmentation",
        description:
          "Deny direct access of broadcasts and multicast sniffing, and prevent attacks such as Name Resolution Poisoning and SMB Relay",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description:
          "In cloud environments, ensure that users are not granted permissions to create or modify traffic mirrors unless this is explicitly required.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1003",
    name: "OS Credential Dumping",
    tactic: "Credential Access",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "mimikatz",
          "lsass-dump",
          "sam-dump",
          "credential-dumping",
        ])
      )
        s += 80;

      if (hasTagPartial(n, ["lsass", "mimikatz", "sam"])) s += 20;

      if (n.type.includes("hash")) s += 10;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["mimikatz", "lsass"])) {
        r.push("IOC associated with operating system credential dumping");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1043",
        name: "Credential Access Protection",
        description:
          "With Windows 10, Microsoft implemented new protections called Credential Guard to protect the LSA secrets that can be used to obtain credentials through forms of credential dumping. It is not configured by default and has hardware and firmware system requirements. It also does not protect against all forms of credential dumping.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1015",
        name: "Active Directory Configuration",
        description:
          "Manage the access control list for 'Replicating Directory Changes All' and other permissions associated with domain controller replication. Consider adding users to the 'Protected Users' Active Directory security group. This can help limit the caching of users' plaintext credentials.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description:
          "On Windows 10, enable Attack Surface Reduction (ASR) rules to secure LSASS and prevent credential stealing.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1041",
        name: "Encrypt Sensitive Information",
        description:
          "Ensure Domain Controller backups are properly secured.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1028",
        name: "Operating System Configuration",
        description:
          "Consider disabling or restricting NTLM. Consider disabling WDigest authentication.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1027",
        name: "Password Policies",
        description:
          "Ensure that local administrator accounts have complex, unique passwords across all systems on the network.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "Privileged Account Management",
        description:
          `Windows:
          Do not put user or admin domain accounts in the local administrator groups across systems unless they are tightly controlled, as this is often equivalent to having a local administrator account with the same password on all systems. Follow best practices for design and administration of an enterprise network to limit privileged account use across administrative tiers.[33]

          Linux:
          Scraping the passwords from memory requires root privileges. Follow best practices in restricting access to privileged accounts to avoid hostile programs from accessing such sensitive regions of memory.`,
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1025",
        name: "Privileged Process Integrity",
        description:
          "On Windows 8.1 and Windows Server 2012 R2, enable Protected Process Light for LSA.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1017",
        name: "User Training",
        description:
          "Limit credential overlap across accounts and systems by training users and administrators not to use the same password for multiple accounts.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1528",
    name: "Steal Application Access Token",
    tactic: "Credential Access",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "oauth-token-theft",
          "token-stealing",
          "api-token",
        ])
      )
        s += 75;

      if (hasTagPartial(n, ["oauth", "token", "api-key"])) s += 20;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["oauth-token", "token-stealing"])) {
        r.push("IOC associated with application access token theft");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1047",
        name: "Audit",
        description:
          "Administrators should audit all cloud and container accounts to ensure that they are necessary and that the permissions granted to them are appropriate. Additionally, administrators should perform an audit of all OAuth applications and the permissions they have been granted to access organizational data. This should be done extensively on all applications in order to establish a baseline, followed up on with periodic audits of new or updated applications. Suspicious applications should be investigated and removed.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1021",
        name: "Restrict Web-Based Content",
        description:
          `Administrators can block end-user consent to OAuth applications, disabling users from authorizing third-party apps through OAuth 2.0 and forcing administrative consent for all requests. They can also block end-user registration of applications by their users, to reduce risk. A Cloud Access Security Broker can also be used to ban applications.

          Azure offers a couple of enterprise policy settings in the Azure Management Portal that may help:

          "Users -> User settings -> App registrations: Users can register applications" can be set to "no" to prevent users from registering new applications.
          "Enterprise applications -> User settings -> Enterprise applications: Users can consent to apps accessing company data on their behalf" can be set to "no" to prevent users from consenting to allow third-party multi-tenant applications`,
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description:
          "Enforce role-based access control to limit accounts to the least privileges they require. A Cloud Access Security Broker (CASB) can be used to set usage policies and manage user permissions on cloud applications to prevent access to application access tokens. In Kubernetes applications, set 'automountServiceAccountToken: false' in the YAML specification of pods that do not require access to service account tokens.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1017",
        name: "User Training",
        description:
          "Users need to be trained to not authorize third-party applications they don't recognize. The user should pay particular attention to the redirect URL: if the URL is a misspelled or convoluted sequence of words related to an expected service or SaaS application, the website is likely trying to spoof a legitimate service. Users should also be cautious about the permissions they are granting to apps. For example, offline access and access to read emails should excite higher suspicions because adversaries can utilize SaaS APIs to discover credentials and other sensitive communications.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1649",
    name: "Steal or Forge Authentication Certificates",
    tactic: "Credential Access",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "certificate-theft",
          "golden-cert",
          "adcs-abuse",
        ])
      )
        s += 80;

      if (hasTagPartial(n, ["certificate", "adcs", "forge"])) s += 20;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["golden-cert", "adcs"])) {
        r.push("IOC associated with authentication certificate abuse");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1015",
        name: "Active Directory Configuration",
        description:
          `Ensure certificate authorities (CA) are properly secured, including treating CA servers (and other resources hosting CA certificates) as tier 0 assets. Harden abusable CA settings and attributes.

          For example, consider disabling the usage of AD CS certificate SANs within relevant authentication protocol settings to enforce strict user mappings and prevent certificates from authenticating as other identifies.[4] Also consider enforcing CA Certificate Manager approval for the templates that include SAN as an issuance requirement.`,
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1047",
        name: "Audit",
        description:
          "Check and remediate unneeded existing authentication certificates as well as common abusable misconfigurations of CA settings and permissions, such as AD CS certificate enrollment permissions and published overly permissive certificate templates (which define available settings for created certificates). For example, available AD CS certificate templates can be checked via the Certificate Authority MMC snap-in (certsrv.msc). certutil.exe can also be used to examine various information within an AD CS CA database.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description:
          "Consider disabling old/dangerous authentication protocols (e.g. NTLM), as well as unnecessary certificate features, such as potentially vulnerable AD CS web and other enrollment server roles",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1041",
        name: "	Encrypt Sensitive Information",
        description:
          "Ensure certificates as well as associated private keys are appropriately secured. Consider utilizing additional hardware credential protections such as trusted platform modules (TPM) or hardware security modules (HSM). Enforce HTTPS and enable Extended Protection for Authentication.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1552",
    name: "Unsecured Credentials",
    tactic: "Credential Access",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "hardcoded-password",
          "plaintext-password",
          "credential-file",
        ])
      )
        s += 70;

      if (hasTagPartial(n, ["plaintext", "credential", "password"])) s += 20;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["plaintext-password", "credential-file"])) {
        r.push("IOC associated with exposed or unsecured credentials");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1047",
        name: "Audit",
        description:
          "Preemptively search for files containing passwords or other credentials and take actions to reduce the exposure risk when found.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1015",
        name: "Active Directory Configuration",
        description:
          "Remove vulnerable Group Policy Preferences.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1041",
        name: "Encrypt Sensitive Information",
        description:
          "When possible, store keys on separate cryptographic hardware instead of on the local system.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description:
          "Limit access to the Instance Metadata API. A properly configured Web Application Firewall (WAF) may help prevent external adversaries from exploiting Server-side Request Forgery (SSRF) attacks that allow access to the Cloud Instance Metadata API.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1035",
        name: "Limit Access to Resource Over Network",
        description:
          "Limit network access to sensitive services, such as the Instance Metadata API.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1028",
        name: "Operating System Configuration",
        description:
          `There are multiple methods of preventing a user's command history from being flushed to their .bash_history file, including use of the following commands:
          set +o history and set -o history to start logging again;
          unset HISTFILE being added to a user's .bash_rc file; and
          ln -s /dev/null ~/.bash_history to write commands to /dev/nullinstead.`,
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1027",
        name: "Password Policies",
        description:
          "Use strong passphrases for private keys to make cracking difficult. Do not store credentials within the Registry. Establish an organizational policy that prohibits password storage in files.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "Privileged Account Management",
        description:
          "If it is necessary that software must store credentials in the Registry, then ensure the associated accounts have limited permissions so they cannot be abused if obtained by an adversary.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description:
          "Restrict file shares to specific directories with access only to necessary users.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1051",
        name: "Update Software",
        description:
          "Apply patch KB2962486 which prevents credentials from being stored in GPPs.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1017",
        name: "User Training",
        description:
          "Ensure that developers and system administrators are aware of the risk associated with having plaintext passwords in software configuration files that may be left on endpoint systems or servers.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  
  // TA0007 — DISCOVERY
  {
    technique: "T1046",
    name: "Network Service Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["port-scan", "network-scan", "service-discovery"])) s += 60;
      if (n.type === "ip" && n.abuse_score >= 30) s += 20;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["port-scan", "network-scan"])) r.push("IOC associated with network service/port scanning");
      return r;
    },
    mitigations: [
      {
        id: "M1030",
        name: "Network Segmentation",
        description: "Ensure proper network segmentation is followed to protect critical servers and devices.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Use network intrusion detection/prevention systems to detect and prevent remote service scans.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description: "Ensure that unnecessary ports and services are closed to prevent risk of discovery and potential exploitation.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1083",
    name: "File and Directory Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["file-discovery", "directory-traversal", "path-traversal"])) s += 60;
      if (n.type === "url" && hasTagPartial(n, ["traversal", "../", "dirlist"])) s += 35;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["traversal", "path-trav"])) r.push("IOC associated with directory/path traversal reconnaissance");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK + OWASP A01 + NIST SP 800-53r5 AC-3",
      },
    ],
  },
  {
    technique: "T1087",
    name: "Account Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["account-discovery", "user-enum", "net-user"])) s += 60;
      if (hasTagPartial(n, ["user", "account", "enum"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["user-enum", "account"])) r.push("IOC associated with account enumeration activity");
      return r;
    },
    mitigations: [
      {
        id: "M1028",
        name: "Operating System Configuration",
        description: "Prevent administrator accounts from being enumerated when an application is elevating through UAC since it can lead to the disclosure of account names. The Registry key is located HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI\\EnumerateAdministrators. It can be disabled through GPO: Computer Configuration > [Policies] > Administrative Templates > Windows Components > Credential User Interface: Enumerate administrator accounts on elevation.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description: "Manage the creation, modification, use, and permissions associated to user accounts.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1010",
    name: "Application Window Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["window-discovery", "gui-enum"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["window", "gui"])) r.push("IOC linked to application window enumeration");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1217",
    name: "Browser Information Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["browser-info", "browser-discovery", "chrome-enum"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["browser", "chrome", "firefox"])) r.push("IOC associated with browser information discovery");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1580",
    name: "Cloud Infrastructure Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["aws-enum", "azure-enum", "gcp-enum", "cloud-discovery"])) s += 65;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["aws", "azure", "gcp"])) r.push("IOC linked to cloud infrastructure enumeration");
      return r;
    },
    mitigations: [
      {
        id: "M1018",
        name: "User Account Management",
        description: "Limit permissions to discover cloud infrastructure in accordance with least privilege. Organizations should limit the number of users within the organization with an IAM role that has administrative privileges, strive to reduce all permanent privileged role assignments, and conduct periodic entitlement reviews on IAM users, roles and policies.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1538",
    name: "Cloud Service Dashboard",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["cloud-dashboard", "aws-console", "azure-portal"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["console", "portal"])) r.push("IOC associated with cloud dashboard enumeration");
      return r;
    },
    mitigations: [
      {
        id: "M1018",
        name: "User Account Management",
        description: "Enforce the principle of least-privilege by limiting dashboard visibility to only the resources required. This may limit the discovery value of the dashboard in the event of a compromised account.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1526",
    name: "Cloud Service Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["cloud-service-discovery", "aws-cli", "azure-cli"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["cloud-service", "aws-cli"])) r.push("IOC linked to cloud service enumeration");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1619",
    name: "Cloud Storage Object Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["s3-enum", "bucket-enum", "blob-enum"])) s += 65;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["bucket", "blob", "s3"])) r.push("IOC associated with cloud storage enumeration");
      return r;
    },
    mitigations: [
      {
        id: "M1018",
        name: "User Account Management",
        description: "Restrict granting of permissions related to listing objects in cloud storage to necessary accounts.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1613",
    name: "Container and Resource Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["docker-enum", "k8s-enum", "container-discovery"])) s += 65;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["docker", "k8s", "container"])) r.push("IOC linked to container resource discovery");
      return r;
    },
    mitigations: [
      {
        id: "M1035",
        name: "Limit Access to Resource Over Network",
        description: "Limit communications with the container service to managed and secured channels, such as local Unix sockets or remote access via SSH. Require secure port access to communicate with the APIs over TLS by disabling unauthenticated access to the Docker API and Kubernetes API Server. In Kubernetes clusters deployed in cloud environments, use native cloud platform features to restrict the IP ranges that are permitted to access to API server. Where possible, consider enabling just-in-time (JIT) access to the Kubernetes API to place additional restrictions on access.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1030",
        name: "Network Segmentation",
        description: "Deny direct remote access to internal systems through the use of network proxies, gateways, and firewalls.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description: "Enforce the principle of least privilege by limiting dashboard visibility to only the required users. When using Kubernetes, avoid giving users wildcard permissions or adding users to the system:masters group, and use RoleBindings rather than ClusterRoleBindings to limit user privileges to specific namespaces.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1622",
    name: "Debugger Evasion",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["anti-debug", "debugger-evasion"])) s += 70;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["anti-debug", "debugger"])) r.push("IOC associated with debugger evasion");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1652",
    name: "Device Driver Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["driver-discovery", "kernel-driver"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["driver", "kernel"])) r.push("IOC associated with device driver enumeration");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1482",
    name: "Domain Trust Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["domain-trust", "trust-enum", "ad-trust"])) s += 65;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["trust", "domain"])) r.push("IOC linked to Active Directory trust discovery");
      return r;
    },
    mitigations: [
      {
        id: "M1047",
        name: "Audit",
        description: "Map the trusts within existing domains/forests and keep trust relationships to a minimum.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1030",
        name: "Network Segmentation",
        description: "Employ network segmentation for sensitive domains.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1615",
    name: "Group Policy Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["gpo-discovery", "group-policy"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["gpo", "group-policy"])) r.push("IOC associated with Group Policy enumeration");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1005",
    name: "Local Storage Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["disk-enum", "storage-discovery"])) s += 55;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["disk", "storage"])) r.push("IOC linked to local storage discovery");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1654",
    name: "Log Enumeration",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["log-enum", "eventlog-query"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["log", "eventlog"])) r.push("IOC associated with log enumeration");
      return r;
    },
    mitigations: [
      {
        id: "M1018",
        name: "User Account Management",
        description: "Limit the ability to access and export sensitive logs to privileged accounts where possible.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1135",
    name: "Network Share Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["share-enum", "smb-enum", "network-share"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["smb", "share"])) r.push("IOC associated with network share discovery");
      return r;
    },
    mitigations: [
      {
        id: "M1028",
        name: "Operating System Configuration",
        description: "Enable Windows Group Policy 'Do Not Allow Anonymous Enumeration of SAM Accounts and Shares' security setting to limit users who can enumerate network shares",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1201",
    name: "Password Policy Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["password-policy", "policy-enum"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["password-policy", "policy"])) r.push("IOC associated with password policy discovery");
      return r;
    },
    mitigations: [
      {
        id: "M1027",
        name: "Password Policies",
        description: 
          "Ensure only valid password filters are registered. Filter DLLs must be present in Windows installation directory (C:\\Windows\\System32\\ by default) of a domain controller and/or local computer with a corresponding entry in HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Notification Packages.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1120",
    name: "Peripheral Device Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["usb-enum", "device-discovery"])) s += 55;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["usb", "device"])) r.push("IOC associated with peripheral device discovery");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1069",
    name: "Permission Groups Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["group-discovery", "admin-group-enum"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["group", "admin"])) r.push("IOC associated with permission group enumeration");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1057",
    name: "Process Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["process-enum", "tasklist", "ps-enum"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["process", "tasklist"])) r.push("IOC linked to process discovery activity");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1012",
    name: "Query Registry",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["registry-query", "reg-enum"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["registry", "reg-query"])) r.push("IOC associated with Windows registry queries");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1018",
    name: "Remote System Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["remote-enum", "host-discovery"])) s += 60;
      if (n.abuse_score >= 30) s += 15;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["host-discovery", "remote"])) r.push("IOC associated with remote system discovery");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1518",
    name: "Software Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["software-discovery", "installed-apps"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["software", "installed"])) r.push("IOC associated with installed software discovery");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1082",
    name: "System Information Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["systeminfo", "host-info", "os-discovery"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["systeminfo", "os"])) r.push("IOC associated with system information gathering");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1614",
    name: "System Location Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["geo-discovery", "locale-discovery"])) s += 55;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["geo", "locale"])) r.push("IOC associated with system location discovery");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1016",
    name: "System Network Configuration Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["ipconfig", "ifconfig", "network-config"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["ipconfig", "ifconfig"])) r.push("IOC associated with network configuration discovery");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1049",
    name: "System Network Connections Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["netstat", "connection-enum"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["netstat", "connection"])) r.push("IOC associated with network connection enumeration");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1033",
    name: "System Owner/User Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["whoami", "user-discovery"])) s += 55;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["whoami", "user"])) r.push("IOC associated with user/session discovery");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1007",
    name: "System Service Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["service-enum", "service-discovery"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["service", "enum"])) r.push("IOC associated with system service discovery");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1124",
    name: "System Time Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["time-discovery", "ntp-query"])) s += 50;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["time", "ntp"])) r.push("IOC associated with system time discovery");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1497",
    name: "Virtualization/Sandbox Evasion",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["sandbox-evasion", "vm-detect", "anti-vm"])) s += 70;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["sandbox", "anti-vm"])) r.push("IOC associated with sandbox or virtualization evasion");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1673",
    name: "Virtual Machine Discovery",
    tactic: "Discovery",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["vm-discovery", "virtualbox", "vmware", "hyperv"])) s += 65;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["vmware", "virtualbox", "hyperv"])) r.push("IOC associated with virtual machine discovery");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  // TA0008 — LATERAL MOVEMENT
  {
    technique: "T1021",
    name: "Remote Services",
    tactic: "Lateral Movement",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["rdp", "ssh", "smb", "winrm", "lateral-movement"])) s += 60;
      if (n.type === "ip" && hasTagPartial(n, ["rdp", "ssh", "smb", "lateral"])) s += 30;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["rdp", "smb", "lateral"])) r.push("IOC associated with remote service lateral movement");
      return r;
    },
    mitigations: [
      {
        id: "M1035",
        name: "Limit Access to Resource Over Network",
        description: "Prevent unnecessary remote access to file shares, hypervisors, sensitive systems, etc. Mechanisms to limit access may include use of network concentrators, RDP gateways, etc.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1047",
        name: "	Audit",
        description: "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description: "If remote services, such as the ability to make direct connections to cloud virtual machines, are not required, disable these connection types where feasible. On ESXi servers, consider enabling lockdown mode, which disables direct access to an ESXi host and requires that the host be managed remotely using vCenter",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description: "Use multi-factor authentication on remote service logons where possible.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1027",
        name: "Password Policies",
        description: "Do not reuse local administrator account passwords across systems. Ensure password complexity and uniqueness such that the passwords cannot be cracked or guessed.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description: "Limit the accounts that may use remote services. Limit the permissions for accounts that are at higher risk of compromise; for example, configure SSH so users can only run specific programs.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1550",
    name: "Use Alternate Authentication Material",
    tactic: "Lateral Movement",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["pass-the-hash", "pass-the-ticket", "golden-ticket", "silver-ticket", "overpass-the-hash"])) s += 70;
      if (isMalwareFamily(n, ["mimikatz", "impacket"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["pass-the-hash", "pass-the-ticket", "golden-ticket"])) r.push("IOC linked to stolen authentication token/hash abuse for lateral movement");
      return r;
    },
    mitigations: [
      {
        id: "M1026",
        name: "Privileged Account Management",
        description: "Limit credential overlap across systems to prevent the damage of credential compromise and reduce the adversary's ability to perform Lateral Movement between systems.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description: "Enforce the principle of least-privilege. Do not allow a domain user to be in the local administrator group on multiple systems.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1027",
        name: "Password Policies",
        description: "Set and enforce secure password policies for accounts.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1047",
        name: "Audit",
        description: "Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1013",
        name: "Application Developer Guidance",
        description: "Consider implementing token binding strategies, such as Azure AD token protection or OAuth Proof of Possession, that cryptographically bind a token to a secret. This may prevent the token from being used without knowledge of the secret or possession of the device the token is tied to.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1015",
        name: "Active Directory Configuration",
        description: "Configure Active Directory to prevent use of certain techniques; use SID Filtering, etc.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1036",
        name: "Account Use Policies",
        description: "Where possible, consider restricting the use of authentication material outside of expected contexts.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1534",
    name: "Internal Spearphishing",
    tactic: "Lateral Movement",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["internal-phishing", "lateral-phishing"])) s += 65;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["internal-phish", "lateral-phish"])) r.push("IOC linked to internal spearphishing for lateral movement");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1210",
    name: "Exploitation of Remote Services",
    tactic: "Lateral Movement",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["remote-exploit", "smb-exploit", "rdp-exploit", "eternalblue", "remote-service-exploit"])) s += 70;
      if (n.type === "ip" && n.abuse_score >= 40) s += 20;
      if (hasTagPartial(n, ["exploit", "remote", "lateral"])) s += 20;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["eternalblue", "remote-exploit"])) r.push("IOC associated with exploitation of remote services for lateral movement");
      if (n.abuse_score >= 40) r.push("AbuseIPDB score indicates suspicious remote exploitation attempts");
      return r;
    },
    mitigations: [
      {
        id: "M1051",
        name: "Update Software",
        description: "Update software regularly by employing patch management for internal enterprise endpoints and servers.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1030",
        name: "Network Segmentation",
        description: "Segment networks and systems appropriately to reduce access to critical systems and services to controlled methods.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1048",
        name: "Application Isolation and Sandboxing",
        description: "Make it difficult for adversaries to advance their operation through exploitation of undiscovered or unpatched vulnerabilities by using sandboxing. Other types of virtualization and application microsegmentation may also mitigate the impact of some types of exploitation. Risks of additional exploits and weaknesses in these systems may still exist.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description: "Minimize available services to only those that are necessary.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1050",
        name: "Exploit Protection",
        description: "Security applications that look for behavior used during exploitation such as Windows Defender Exploit Guard (WDEG) and the Enhanced Mitigation Experience Toolkit (EMET) can be used to mitigate some exploitation behavior. Control flow integrity checking is another way to potentially identify and stop a software exploit from occurring. Many of these protections depend on the architecture and target application binary for compatibility and may not work for all software or services targeted.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "Privileged Account Management",
        description: "Minimize permissions and access for service accounts to limit impact of exploitation.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1019",
        name: "Threat Intelligence Program",
        description: "Develop a robust cyber threat intelligence capability to determine what types and levels of threat may use software exploits and 0-days against a particular organization.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1016",
        name: "Vulnerability Scanning",
        description: "Regularly scan the internal network for available services to identify new and potentially vulnerable services.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1570",
    name: "Lateral Tool Transfer",
    tactic: "Lateral Movement",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["psexec", "impacket", "tool-transfer", "admin-share", "copy-tool"])) s += 65;
      if (n.type.includes("hash") && hasTagPartial(n, ["tool", "transfer", "payload"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["psexec", "tool-transfer", "admin-share"])) r.push("IOC associated with transferring tools across internal systems");
      return r;
    },
    mitigations: [
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Consider using the host firewall to restrict file sharing communications such as SMB.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware or unusual data transfer over known tools and protocols like FTP can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1563",
    name: "Remote Service Session Hijacking",
    tactic: "Lateral Movement",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["session-hijack", "rdp-hijack", "ssh-hijack", "tscon"])) s += 70;
      if (hasTagPartial(n, ["session", "hijack"])) s += 20;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["rdp-hijack", "session-hijack", "tscon"])) r.push("IOC associated with hijacking active remote sessions");
      return r;
    },
    mitigations: [
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description: "Disable the remote service (ex: SSH, RDP, etc.) if it is unnecessary.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "Privileged Account Management",
        description: "Do not allow remote access to services as a privileged account unless necessary.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1030",
        name: "Network Segmentation",
        description: "Enable firewall rules to block unnecessary traffic between network security zones within a network.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1027",
        name: "Password Policies",
        description: "Set and enforce secure password policies for accounts.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description: "Limit remote user permissions if remote access is necessary.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1080",
    name: "Taint Shared Content",
    tactic: "Lateral Movement",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["shared-folder", "network-share-malware", "tainted-share"])) s += 65;
      if (n.type.includes("hash") && hasTagPartial(n, ["shared", "malware", "payload"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["shared-folder", "tainted-share"])) r.push("IOC associated with malicious content placed on shared resources");
      return r;
    },
    mitigations: [
      {
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description: "Protect shared folders by minimizing users who have write access.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1049",
        name: "Antivirus/Antimalware",
        description: "Anti-virus can be used to automatically quarantine suspicious files.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1038",
        name: "Execution Prevention",
        description: "Identify potentially malicious software that may be used to taint content or may result from it and audit and/or block the unknown programs by using application control tools, like AppLocker, or Software Restriction Policies where appropriate.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1050",
        name: "Exploit Protection",
        description: "Use utilities that detect or mitigate common features used in exploitation, such as the Microsoft Enhanced Mitigation Experience Toolkit (EMET).",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  // TA0009 — COLLECTION
  {
    technique: "T1560",
    name: "Archive Collected Data",
    tactic: "Collection",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["data-collection", "archive", "exfil-prep", "staging"])) s += 55;
      if (n.type.includes("hash") && hasTagPartial(n, ["rar", "zip", "7z", "archive"])) s += 35;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["archive", "exfil", "staging"])) r.push("IOC associated with data archiving/staging before exfiltration");
      return r;
    },
    mitigations: [
      {
        id: "M1047",
        name: "Audit",
        description: "System scans can be performed to identify unauthorized archival utilities.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1113",
    name: "Screen Capture",
    tactic: "Collection",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["screenshot", "screen-capture", "spyware"])) s += 60;
      if (isMalwareFamily(n, ["darkcomet", "njrat", "remcos", "asyncrat"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["screenshot", "screen-capture", "spyware"])) r.push("IOC linked to spyware/screen capture capability");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1056",
    name: "Input Capture",
    tactic: "Collection",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["keylogger", "keylogging", "input-capture"])) s += 65;
      if (isMalwareFamily(n, ["agent-tesla", "lokibot", "hawkeye"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["keylog", "input-capture"])) r.push("IOC linked to keylogger/input capture malware");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1123",
    name: "Audio Capture",
    tactic: "Collection",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["audio-capture", "microphone", "voice-recording", "spyware"])) s += 65;
      if (isMalwareFamily(n, ["remcos", "darkcomet", "quasar", "njrat"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["microphone", "audio-capture", "voice"])) r.push("IOC linked to malware capable of microphone/audio recording");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1119",
    name: "Automated Collection",
    tactic: "Collection",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["automated-collection", "data-harvesting", "scheduled-collection"])) s += 60;
      if (n.type.includes("hash") && hasTagPartial(n, ["collector", "harvest"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["automated", "harvest"])) r.push("IOC associated with automated data collection capability");
      return r;
    },
    mitigations: [
      {
        id: "M1041",
        name: "Encrypt Sensitive Information",
        description: "Encryption and off-system storage of sensitive information may be one way to mitigate collection of files, but may not stop an adversary from acquiring the information if an intrusion persists over a long period of time and the adversary is able to discover and access the data through other means. Strong passwords should be used on certain encrypted documents that use them to prevent offline cracking through Brute Force techniques.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1029",
        name: "Remote Data Storage",
        description: "Encryption and off-system storage of sensitive information may be one way to mitigate collection of files, but may not stop an adversary from acquiring the information if an intrusion persists over a long period of time and the adversary is able to discover and access the data through other means.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1185",
    name: "Browser Session Hijacking",
    tactic: "Collection",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["session-hijacking", "cookie-theft", "browser-theft"])) s += 70;
      if (isMalwareFamily(n, ["redline", "vidar", "raccoon", "stealc"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["cookie", "session-hijack"])) r.push("IOC linked to browser session hijacking activity");
      return r;
    },
    mitigations: [
      {
        id: "M1018",
        name: "User Account Management",
        description: "Since browser pivoting requires a high integrity process to launch from, restricting user permissions and addressing Privilege Escalation and Bypass User Account Control opportunities can limit the exposure to this technique.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1017",
        name: "User Training",
        description: "Close all browser sessions regularly and when they are no longer needed.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1115",
    name: "Clipboard Data",
    tactic: "Collection",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["clipboard", "clipboard-monitoring", "clipboard-theft"])) s += 60;
      if (isMalwareFamily(n, ["agent-tesla", "lokibot", "remcos"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["clipboard"])) r.push("IOC associated with clipboard monitoring or theft");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1530",
    name: "Data from Cloud Storage",
    tactic: "Collection",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["cloud-storage", "onedrive", "google-drive", "s3", "dropbox"])) s += 65;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["cloud-storage", "s3", "onedrive"])) r.push("IOC associated with cloud storage data collection");
      return r;
    },
    mitigations: [
      {
        id: "M1047",
        name: "Audit",
        description: "Frequently check permissions on cloud storage to ensure proper permissions are set to deny open or unprivileged access to resources.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1041",
        name: "Audit",
        description: "Encrypt data stored at rest in cloud storage. Managed encryption keys can be rotated by most providers. At a minimum, ensure an incident response plan to storage breach includes rotating the keys and test for impact on client applications.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Cloud service providers support IP-based restrictions when accessing cloud resources. Consider using IP allowlisting along with user account management to ensure that data access is restricted not only to valid users but only from expected IP ranges to mitigate the use of stolen credentials to access data.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description: "Consider using multi-factor authentication to restrict access to resources and cloud storage APIs.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description: "Use access control lists on storage systems and objects.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "Restrict File and Directory Permissions",
        description: "Configure user permissions groups and roles for access to cloud storage. Implement strict Identity and Access Management (IAM) controls to prevent access to storage solutions except for the applications, users, and services that require access. Ensure that temporary access tokens are issued rather than permanent credentials, especially when access is being granted to entities outside of the internal security boundary.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1602",
    name: "Data from Configuration Repository",
    tactic: "Collection",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["git", "github", "gitlab", "config-repo", "jenkins"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["git", "config-repo"])) r.push("IOC linked to configuration repository access/collection");
      return r;
    },
    mitigations: [
      {
        id: "M1041",
        name: "Encrypt Sensitive Information",
        description: "Configure SNMPv3 to use the highest level of security (authPriv) available.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Apply extended ACLs to block unauthorized protocols outside the trusted network.[",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Configure intrusion prevention devices to detect SNMP queries and commands from unauthorized sources.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1030",
        name: "Network Segmentation",
        description: "Segregate SNMP traffic on a separate management network.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1054",
        name: "Software Configuration",
        description: "Allowlist MIB objects and implement SNMP views.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1051",
        name: "Update Software",
        description: "Keep system images and software updated and migrate to SNMPv3.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1213",
    name: "Data from Information Repositories",
    tactic: "Collection",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["sharepoint", "confluence", "wiki", "document-repository"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["sharepoint", "confluence", "repository"])) r.push("IOC associated with enterprise information repository access");
      return r;
    },
    mitigations: [
      {
        id: "M1047",
        name: "Audit",
        description: "Consider periodic review of accounts and privileges for critical and sensitive repositories. Ensure that repositories such as cloud-hosted databases are not unintentionally exposed to the public, and that security groups assigned to them permit only necessary and authorized hosts.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1041",
        name: "Encrypt Sensitive Information",
        description: "Encrypt data stored at rest in databases.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description: "Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1060",
        name: "Out-of-Band Communications Channel",
        description: "Create plans for leveraging a secure out-of-band communications channel, rather than existing in-network chat applications, in case of a security incident.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description: "Enforce the principle of least-privilege. Consider implementing access control mechanisms that include both authentication and authorization.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1054",
        name: "Software Configuration",
        description: "Consider implementing data retention policies to automate periodically archiving and/or deleting data that is no longer needed.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1017",
        name: "User Training",
        description: "Develop and publish policies that define acceptable information to be stored in repositories.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1005",
    name: "Data from Local System",
    tactic: "Collection",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["data-theft", "local-data", "collection"])) s += 55;
      if (n.type.includes("hash") && hasTagPartial(n, ["stealer", "collector"])) s += 30;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["local-data", "collector"])) r.push("IOC linked to local system data collection");
      return r;
    },
    mitigations: [
      {
        id: "M1057",
        name: "Data Loss Prevention",
        description: "Data loss prevention can restrict access to sensitive data and detect sensitive data that is unencrypted.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1039",
    name: "Data from Network Shared Drive",
    tactic: "Collection",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["network-share", "smb-share", "shared-drive"])) s += 60;
      if (n.type === "ip" && hasTagPartial(n, ["smb", "share"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["network-share", "shared-drive"])) r.push("IOC associated with collection from shared network drives");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1025",
    name: "Data from Removable Media",
    tactic: "Collection",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["usb", "removable-media", "external-drive"])) s += 65;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["usb", "removable"])) r.push("IOC linked to removable media data collection");
      return r;
    },
    mitigations: [
      {
        id: "M1057",
        name: "Data Loss Prevention",
        description: "Data loss prevention can restrict access to sensitive data and detect sensitive data that is unencrypted.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1074",
    name: "Data Staged",
    tactic: "Collection",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["staging", "data-staged", "archive"])) s += 60;
      if (n.type.includes("hash") && hasTagPartial(n, ["staging", "rar", "zip"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["staging", "archive"])) r.push("IOC associated with staged data preparation before exfiltration");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1114",
    name: "Email Collection",
    tactic: "Collection",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["email-collection", "mailbox-access", "exchange-dump"])) s += 65;
      if (hasTagPartial(n, ["imap", "exchange", "mailbox"])) s += 20;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["mailbox", "email-collection"])) r.push("IOC associated with unauthorized email collection activity");
      return r;
    },
    mitigations: [
      {
        id: "M1047",
        name: "Audit",
        description: 
          `Enterprise email solutions have monitoring mechanisms that may include the ability to audit auto-forwarding rules on a regular basis.

          In an Exchange environment, Administrators can use Get-InboxRule to discover and remove potentially malicious auto-forwarding rules.`,
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1041",
        name: "Encrypt Sensitive Information",
        description: "Use of encryption provides an added layer of security to sensitive information sent over email. Encryption using public key cryptography requires the adversary to obtain the private certificate along with an encryption key to decrypt messages.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description: "Use of multi-factor authentication for public-facing webmail servers is a recommended best practice to minimize the usefulness of usernames and passwords to adversaries.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1060",
        name: "Multi-factor Authentication",
        description: "Use secure out-of-band authentication methods to verify the authenticity of critical actions initiated via email, such as password resets, financial transactions, or access requests. For highly sensitive information, utilize out-of-band communication channels instead of relying solely on email to prevent adversaries from collecting data through compromised email accounts.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1125",
    name: "Video Capture",
    tactic: "Collection",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["video-capture", "webcam", "camera-access"])) s += 65;
      if (isMalwareFamily(n, ["darkcomet", "njrat", "quasar"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["webcam", "camera"])) r.push("IOC linked to webcam/video capture capability");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  // TA0010 — EXFILTRATION
  {
    technique: "T1041",
    name: "Exfiltration Over C2 Channel",
    tactic: "Exfiltration",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["exfiltration", "data-theft", "c2-exfil"])) s += 65;
      if (n.type === "ip" && n.abuse_score >= 50) s += 20;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["exfil", "data-theft"])) r.push("IOC associated with data exfiltration via C2 channel");
      return r;
    },
    mitigations: [
      {
        id: "M1057",
        name: "Data Loss Prevention",
        description: "Data loss prevention can detect and block sensitive data being sent over unencrypted protocols.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool command and control signatures over time or construct protocols in such a way to avoid detection by common defensive tools.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1048",
    name: "Exfiltration Over Alternative Protocol",
    tactic: "Exfiltration",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["dns-exfil", "icmp-tunnel", "ftp-exfil", "smtp-exfil"])) s += 65;
      if (n.type === "domain" && hasTagPartial(n, ["dns-tunnel", "dns-exfil"])) s += 40;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["dns-exfil", "dns-tunnel", "icmp-tunnel"])) r.push("IOC linked to DNS tunneling or ICMP exfiltration");
      return r;
    },
    mitigations: [
      {
        id: "M1057",
        name: "Data Loss Prevention",
        description: "Data loss prevention can detect and block sensitive data being uploaded via web browsers.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Enforce proxies and use dedicated servers for services such as DNS and only allow those systems to communicate over respective ports/protocols, instead of all systems within a network. Cloud service providers support IP-based restrictions when accessing cloud resources. Consider using IP allowlisting along with user account management to ensure that data access is restricted not only to valid users but only from expected IP ranges to mitigate the use of stolen credentials to access data.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary command and control infrastructure and malware can be used to mitigate activity at the network level.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1030",
        name: "Network Segmentation",
        description: "Follow best practices for network firewall configurations to allow only necessary ports and traffic to enter and exit the network.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description: "Use access control lists on cloud storage systems and objects.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description: "Configure user permissions groups and roles for access to cloud storage. Implement strict Identity and Access Management (IAM) controls to prevent access to storage solutions except for the applications, users, and services that require access. Ensure that temporary access tokens are issued rather than permanent credentials, especially when access is being granted to entities outside of the internal security boundary.",
        framework: "MITRE ATT&CK",
      },
      
    ],
  },
  {
    technique: "T1567",
    name: "Exfiltration Over Web Service",
    tactic: "Exfiltration",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["cloud-exfil", "github-exfil", "dropbox-exfil", "pastebin-exfil", "discord-exfil"])) s += 65;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["cloud-exfil", "pastebin", "discord-exfil"])) r.push("IOC linked to data exfiltration via cloud/web service");
      return r;
    },
    mitigations: [
      {
        id: "M1057",
        name: "Data Loss Prevention",
        description: "Data loss prevention can be detect and block sensitive data being uploaded to web services via web browsers.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1021",
        name: "Restrict Web-Based Content",
        description: "Web proxies can be used to enforce an external network communication policy that prevents use of unauthorized external services.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1020",
    name: "Automated Exfiltration",
    tactic: "Exfiltration",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["automated-exfil", "scheduled-exfil", "bulk-transfer"])) s += 65;
      if (n.type.includes("hash") && hasTagPartial(n, ["exfil", "uploader", "transfer"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["automated-exfil", "bulk-transfer"])) r.push("IOC associated with automated exfiltration activity");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1030",
    name: "Data Transfer Size Limits",
    tactic: "Exfiltration",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["chunked-exfil", "low-and-slow", "fragmented-transfer"])) s += 65;
      if (n.type === "domain" && hasTagPartial(n, ["chunk", "split"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["chunked", "low-and-slow"])) r.push("IOC linked to staged/chunked exfiltration to evade detection");
      return r;
    },
    mitigations: [
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary command and control infrastructure and malware can be used to mitigate activity at the network level.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1011",
    name: "Exfiltration Over Other Network Medium",
    tactic: "Exfiltration",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["bluetooth-exfil", "wifi-exfil", "rf-exfil", "covert-channel"])) s += 70;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["bluetooth", "rf-exfil", "covert-channel"])) r.push("IOC associated with exfiltration over alternate network medium");
      return r;
    },
    mitigations: [
      {
        id: "M1028",
        name: "Operating System Configuration",
        description: "Prevent the creation of new network adapters where possible.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description: "Disable WiFi connection, modem, cellular data connection, Bluetooth, or another radio frequency (RF) channel in local computer security settings or by group policy if it is not needed within an environment.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1052",
    name: "Exfiltration Over Physical Medium",
    tactic: "Exfiltration",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["usb-exfil", "removable-media", "physical-exfil"])) s += 70;
      if (n.type.includes("hash") && hasTagPartial(n, ["usb", "removable"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["usb-exfil", "physical-exfil"])) r.push("IOC linked to exfiltration through removable/physical media");
      return r;
    },
    mitigations: [
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description: "Disable Autorun if it is unnecessary. Disallow or restrict removable media at an organizational policy level if they are not required for business operations.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1057",
        name: "Data Loss Prevention",
        description: "Data loss prevention can detect and block sensitive data being copied to physical mediums.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1034",
        name: "Limit Hardware Installation",
        description: "Limit the use of USB devices and removable media within a network.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1029",
    name: "Scheduled Transfer",
    tactic: "Exfiltration",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["scheduled-transfer", "cron-exfil", "timed-exfil"])) s += 65;
      if (hasTagPartial(n, ["cron", "task-scheduler", "scheduled"])) s += 20;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["scheduled-transfer", "cron-exfil"])) r.push("IOC associated with scheduled exfiltration activity");
      return r;
    },
    mitigations: [
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary command and control infrastructure and malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool command and control signatures over time or construct protocols in such a way to avoid detection by common defensive tools.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1537",
    name: "Transfer Data to Cloud Account",
    tactic: "Exfiltration",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["cloud-exfil", "onedrive-exfil", "google-drive-exfil", "dropbox-exfil"])) s += 70;
      if (n.type === "domain" && hasTagPartial(n, ["dropbox", "drive", "onedrive"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["cloud-exfil", "dropbox", "onedrive"])) r.push("IOC linked to exfiltration into attacker-controlled cloud account");
      return r;
    },
    mitigations: [
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Implement network-based filtering restrictions to prohibit data transfers to untrusted VPCs.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1057",
        name: "Data Loss Prevention",
        description: "Data loss prevention can prevent and block sensitive data from being shared with individuals outside an organization.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1054",
        name: "Software Configuration",
        description: "Configure appropriate data sharing restrictions in cloud services. For example, external sharing in Microsoft SharePoint and Google Drive can be turned off altogether, blocked for certain domains, or restricted to certain users.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description: "Limit user account and IAM policies to the least privileges required.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  // TA0011 — COMMAND & CONTROL
  {
    technique: "T1071",
    name: "Application Layer Protocol",
    tactic: "Command and Control",
    score: (n) => {
      let s = 0;
      if (n.type === "domain") s += 20;
      if (n.type === "ip") s += 20;
      if (hasTag(n, ["c2", "command-and-control", "trojan", "botnet", "rat"])) s += 50;
      if (n.abuse_score >= 50) s += 15;
      if (n.vt_score >= 10) s += 10;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["c2", "botnet", "rat"])) r.push("Tags indicate C2/botnet communication channel");
      if (n.abuse_score >= 50) r.push("High AbuseIPDB score confirms malicious reputation");
      return r;
    },
    mitigations: [
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1573",
    name: "Encrypted Channel",
    tactic: "Command and Control",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["encrypted-c2", "tls-c2", "ssl-c2", "custom-crypto"])) s += 65;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["encrypted-c2", "tls-c2"])) r.push("IOC associated with encrypted C2 channel using custom/non-standard TLS");
      return r;
    },
    mitigations: [
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1020",
        name: "SSL/TLS Inspection",
        description: "SSL/TLS inspection can be used to see the contents of encrypted sessions to look for network-based indicators of malware communication protocols.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1092",
    name: "Communication Through Removable Media",
    tactic: "Command and Control",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["usb-c2", "removable-media", "offline-c2", "airgap-transfer"])) s += 65;
      if (n.type.includes("hash") && hasTagPartial(n, ["usb", "removable", "airgap"])) s += 30;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["usb", "removable", "airgap"])) r.push("IOC associated with command/control through removable media");
      return r;
    },
    mitigations: [
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description: "Disable Autoruns if it is unnecessary.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1028",
        name: "Operating System Configuration",
        description: "Disallow or restrict removable media at an organizational policy level if they are not required for business operations.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1132",
    name: "Data Encoding",
    tactic: "Command and Control",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["base64", "xor-encoding", "encoded-payload", "obfuscated-c2"])) s += 60;
      if (n.type.includes("hash") && hasTagPartial(n, ["base64", "encoded"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["base64", "encoded", "xor"])) r.push("IOC associated with encoded C2 payloads");
      return r;
    },
    mitigations: [
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool C2 signatures over time or construct protocols in such a way as to avoid detection by common defensive tools.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1001",
    name: "Data Obfuscation",
    tactic: "Command and Control",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["obfuscation", "steganography", "junk-data", "traffic-padding"])) s += 65;
      if (hasTagPartial(n, ["obfus", "stego"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["obfuscation", "stego"])) r.push("IOC associated with obfuscated C2 traffic");
      return r;
    },
    mitigations: [
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate some obfuscation activity at the network level.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1568",
    name: "Dynamic Resolution",
    tactic: "Command and Control",
    score: (n) => {
      let s = 0;
      if (n.type === "domain") s += 15;
      if (hasTag(n, ["dga", "fast-flux", "dynamic-dns", "domain-generation"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["dga", "dynamic-dns", "fast-flux"])) r.push("IOC linked to dynamically resolved C2 infrastructure");
      return r;
    },
    mitigations: [
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level. Malware researchers can reverse engineer malware variants that use dynamic resolution and determine future C2 infrastructure that the malware will attempt to contact, but this is a time and resource intensive effort",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1021",
        name: "Restrict Web-Based Content",
        description: "In some cases a local DNS sinkhole may be used to help prevent behaviors associated with dynamic resolution.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1008",
    name: "Fallback Channels",
    tactic: "Command and Control",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["fallback-c2", "backup-c2", "redundant-channel"])) s += 65;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["fallback", "backup-c2"])) r.push("IOC associated with redundant/fallback command channels");
      return r;
    },
    mitigations: [
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific protocol used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool C2 signatures over time or construct protocols in such a way as to avoid detection by common defensive tools.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1665",
    name: "Hide Infrastructure",
    tactic: "Command and Control",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["bulletproof-hosting", "cdn-abuse", "reverse-proxy", "hidden-infra"])) s += 65;
      if (n.type === "ip" && hasTagPartial(n, ["proxy", "cdn"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["bulletproof", "reverse-proxy", "cdn"])) r.push("IOC associated with hidden or masked C2 infrastructure");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1105",
    name: "Ingress Tool Transfer",
    tactic: "Command and Control",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["tool-transfer", "payload-download", "stage-download", "wget", "curl"])) s += 65;
      if (n.type === "url") s += 20;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["payload-download", "tool-transfer"])) r.push("IOC associated with inbound malicious tool transfer");
      return r;
    },
    mitigations: [
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Use network filtering to block outbound traffic from compromised systems to unapproved external destinations. Restricting access to known, trusted IP addresses and protocols can prevent attackers from downloading malicious tools or payloads onto compromised servers after gaining initial access.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware or unusual data transfer over known protocols like FTP can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool C2 signatures over time or construct protocols in such a way as to avoid detection by common defensive tools",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1104",
    name: "Multi-Stage Channels",
    tactic: "Command and Control",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["multi-stage-c2", "staged-payload", "multi-hop-c2"])) s += 65;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["multi-stage", "staged"])) r.push("IOC linked to staged or multi-hop C2 communications");
      return r;
    },
    mitigations: [
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1095",
    name: "Non-Application Layer Protocol",
    tactic: "Command and Control",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["icmp-c2", "raw-socket", "custom-protocol", "udp-c2"])) s += 70;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["icmp", "raw-socket", "udp-c2"])) r.push("IOC associated with non-application layer C2 protocol");
      return r;
    },
    mitigations: [
      {
        id: "M1047",
        name: "Audit",
        description: "Periodically investigate ESXi hosts for open VMCI ports. Running the lsof -A command and inspecting results with a type of SOCKET_VMCI will reveal processes that have open VMCI ports.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Filter network traffic to prevent use of protocols across the network boundary that are unnecessary. If VMCI is not required in ESXi environments, consider restricting guest virtual machines from accessing VMCI services.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1030",
        name: "Network Segmentation",
        description: "Properly configure firewalls and proxies to limit outgoing traffic to only necessary ports and through proper network gateway systems. Also ensure hosts are only provisioned to communicate over authorized interfaces.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1571",
    name: "Non-Standard Port",
    tactic: "Command and Control",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["non-standard-port", "high-port-c2", "port-evasion"])) s += 60;
      if (n.type === "ip") s += 20;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["non-standard-port", "port-evasion"])) r.push("IOC associated with C2 over unusual ports");
      return r;
    },
    mitigations: [
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1030",
        name: "Network Segmentation",
        description: "Properly configure firewalls and proxies to limit outgoing traffic to only necessary ports for that particular network segment.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1572",
    name: "Protocol Tunneling",
    tactic: "Command and Control",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["dns-tunnel", "http-tunnel", "ssh-tunnel", "icmp-tunnel"])) s += 70;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["tunnel", "dns-tunnel", "ssh-tunnel"])) r.push("IOC linked to tunneled command and control traffic");
      return r;
    },
    mitigations: [
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Consider filtering network traffic to untrusted or known bad domains and resources.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1090",
    name: "Proxy",
    tactic: "Command and Control",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["proxy", "tor", "vpn-abuse", "socks5"])) s += 65;
      if (n.type === "ip") s += 20;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["proxy", "tor", "vpn"])) r.push("IOC associated with proxy/anonymization infrastructure");
      return r;
    },
    mitigations: [
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Traffic to known anonymity networks and C2 infrastructure can be blocked through the use of network allow and block lists. It should be noted that this kind of blocking may be circumvented by other techniques like Domain Fronting.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific C2 protocol used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool C2 signatures over time or construct protocols in such a way as to avoid detection by common defensive tools.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1020",
        name: "SSL/TLS Inspection",
        description: "If it is possible to inspect HTTPS traffic, the captures can be analyzed for connections that appear to be domain fronting.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1219",
    name: "Remote Access Tools",
    tactic: "Command and Control",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["teamviewer", "anydesk", "screenconnect", "ammyy", "remote-access-tool"])) s += 65;
      if (isMalwareFamily(n, ["asyncrat", "njrat", "remcos"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["teamviewer", "anydesk", "screenconnect"])) r.push("IOC linked to remote access tool abuse");
      return r;
    },
    mitigations: [
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description: "Consider disabling unnecessary remote connection functionality, including both unapproved software installations and specific features built into supported applications.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1038",
        name: "Execution Prevention",
        description: "Use application control to mitigate installation and use of unapproved software that can be used for remote access.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Properly configure firewalls, application firewalls, and proxies to limit outgoing traffic to sites and services used by remote access software.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1034",
        name: "Limit Hardware Installation",
        description: "Block the use of IP-based KVM devices within the network if they are not required.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Network intrusion detection and prevention systems that use network signatures may be able to prevent traffic to remote access services.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1102",
    name: "Web Service",
    tactic: "Command and Control",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["github-c2", "discord-c2", "telegram-c2", "pastebin-c2", "web-service-c2"])) s += 65;
      if (n.type === "domain") s += 20;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["github-c2", "telegram-c2", "discord-c2"])) r.push("IOC associated with web-service-based C2");
      return r;
    },
    mitigations: [
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1021",
        name: "Restrict Web-Based Content",
        description: "Web proxies can be used to enforce external network communication policy that prevents use of unauthorized external services.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  // TA0040 — IMPACT
  {
    technique: "T1486",
    name: "Data Encrypted for Impact (Ransomware)",
    tactic: "Impact",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["ransomware", "locker", "encryptor", "crypto-malware", "wiper-ransom"])) s += 75;
      if (isMalwareFamily(n, ["lockbit", "conti", "ryuk", "revil", "blackcat", "hive", "blackbasta", "play", "cl0p", "akira"])) s += 30;
      if (n.type.includes("hash") && hasTagPartial(n, ["ransom"])) s += 20;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["ransomware"])) r.push("IOC confirmed as ransomware");
      if (n.malware_family) r.push(`Ransomware family identified: ${n.malware_family}`);
      return r;
    },
    mitigations: [
      {
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description: "On Windows 10, enable cloud-delivered protection and Attack Surface Reduction (ASR) rules to block the execution of files that resemble ransomware.[170] In AWS environments, create an IAM policy to restrict or block the use of SSE-C on S3 buckets.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1053",
        name: "Data Backup",
        description: "Consider implementing IT disaster recovery plans that contain procedures for regularly taking and testing data backups that can be used to restore organizational data. Ensure backups are stored off system and is protected from common methods adversaries may use to gain access and destroy the backups to prevent recovery. Consider enabling versioning in cloud environments to maintain backup copies of storage objects.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1485",
    name: "Data Destruction",
    tactic: "Impact",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["wiper", "data-destruction", "destructive-malware"])) s += 70;
      if (isMalwareFamily(n, ["notpetya", "shamoon", "whiterabbit", "caddywiper", "industroyer"])) s += 30;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["wiper", "destruct"])) r.push("IOC linked to destructive wiper malware");
      return r;
    },
    mitigations: [
      {
        id: "M1053",
        name: "Data Backup",
        description: "Consider implementing IT disaster recovery plans that contain procedures for taking regular data backups that can be used to restore organizational data. Ensure backups are stored off system and protected from common methods adversaries may use to gain access and destroy the backups to prevent recovery.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description: "Implement multi-factor authentication (MFA) delete for cloud storage resources, such as AWS S3 buckets, to prevent unauthorized deletion of critical data and infrastructure. MFA delete requires additional authentication steps, making it significantly more difficult for adversaries to destroy data without proper credentials. This additional security layer helps protect against the impact of data destruction in cloud environments by ensuring that only authenticated actions can irreversibly delete storage or machine images.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description: "In cloud environments, limit permissions to modify cloud bucket lifecycle policies (e.g., PutLifecycleConfiguration in AWS) to only those accounts that require it. In AWS environments, consider using Service Control policies to limit the use of the PutBucketLifecycle API call.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1498",
    name: "Network Denial of Service",
    tactic: "Impact",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["ddos", "dos", "flood", "amplification", "reflection", "botnet-ddos"])) s += 70;
      if (n.abuse_score >= 70) s += 20;
      if (n.type === "ip" && hasTagPartial(n, ["ddos", "flood"])) s += 20;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["ddos", "flood", "amplification"])) r.push("IOC tagged as DDoS attack source or amplification node");
      if (n.abuse_score >= 70) r.push("AbuseIPDB score strongly confirms attack traffic");
      return r;
    },
    mitigations: [
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description: 
          `When flood volumes exceed the capacity of the network connection being targeted, it is typically necessary to intercept the incoming traffic upstream to filter out the attack traffic from the legitimate traffic. Such defenses can be provided by the hosting Internet Service Provider (ISP) or by a 3rd party such as a Content Delivery Network (CDN) or providers specializing in DoS mitigations.

          Depending on flood volume, on-premises filtering may be possible by blocking source addresses sourcing the attack, blocking ports that are being targeted, or blocking protocols being used for transport.

          As immediate response may require rapid engagement of 3rd parties, analyze the risk associated to critical resources being affected by Network DoS attacks and create a disaster recovery plan/business continuity plan to respond to incidents.`,
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1489",
    name: "Service Stop",
    tactic: "Impact",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["service-stop", "kill-process", "sabotage", "ics-attack"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["service-stop", "kill", "sabotage"])) r.push("IOC linked to service disruption/sabotage capability");
      return r;
    },
    mitigations: [
      {
        id: "M1030",
        name: "Network Segmentation",
        description: "Operate intrusion detection, analysis, and response systems on a separate network from the production environment to lessen the chances that an adversary can see and interfere with critical response functions.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1060",
        name: "	Out-of-Band Communications Channel",
        description: "Develop and enforce security policies that include the use of out-of-band communication channels for critical communications during a security incident.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description: "Ensure proper process and file permissions are in place to inhibit adversaries from disabling or interfering with critical services.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1024",
        name: "Restrict Registry Permissions",
        description: "Ensure proper registry permissions are in place to inhibit adversaries from disabling or interfering with critical services.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description: "Limit privileges of user accounts and groups so that only authorized administrators can interact with service changes and service configurations.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1496",
    name: "Resource Hijacking",
    tactic: "Impact",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["cryptominer", "xmrig", "monero", "cryptojacking", "miner"])) s += 70;
      if (isMalwareFamily(n, ["xmrig", "lemon-duck", "kinsing", "watchbog"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["cryptomin", "xmrig", "miner"])) r.push("IOC linked to cryptomining/resource hijacking malware");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1531",
    name: "Account Access Removal",
    tactic: "Impact",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["account-lockout", "account-deletion", "disable-account", "access-removal"])) s += 65;
      if (hasTagPartial(n, ["lockout", "disable-account"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["account-lockout", "disable-account"])) r.push("IOC associated with unauthorized account access removal");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1565",
    name: "Data Manipulation",
    tactic: "Impact",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["data-tampering", "record-modification", "integrity-attack", "manipulation"])) s += 70;
      if (n.type.includes("hash") && hasTagPartial(n, ["tamper", "modify"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["tamper", "manipulation", "integrity"])) r.push("IOC linked to unauthorized data manipulation");
      return r;
    },
    mitigations: [
      {
        id: "M1041",
        name: "Encrypt Sensitive Information",
        description: "Consider encrypting important information to reduce an adversary’s ability to perform tailored data modifications.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1030",
        name: "Network Segmentation",
        description: "Identify critical business and system processes that may be targeted by adversaries and work to isolate and secure those systems against unauthorized access and tampering.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1029",
        name: "Remote Data Storage",
        description: "Consider implementing IT disaster recovery plans that contain procedures for taking regular data backups that can be used to restore organizational data. Ensure backups are stored off system and is protected from common methods adversaries may use to gain access and manipulate backups.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description: "Ensure least privilege principles are applied to important information resources to reduce exposure to data manipulation risk.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1491",
    name: "Defacement",
    tactic: "Impact",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["website-defacement", "web-deface", "ui-tampering"])) s += 70;
      if (n.type === "url" && hasTagPartial(n, ["deface", "hacked-by"])) s += 35;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["deface", "hacked-by"])) r.push("IOC associated with website/application defacement");
      return r;
    },
    mitigations: [
      {
        id: "M1053",
        name: "Data Backup",
        description: "Consider implementing IT disaster recovery plans that contain procedures for taking regular data backups that can be used to restore organizational data. Ensure backups are stored off system and is protected from common methods adversaries may use to gain access and destroy the backups to prevent recovery.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1561",
    name: "Disk Wipe",
    tactic: "Impact",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["disk-wipe", "mbR-wipe", "partition-delete", "wipe-malware"])) s += 75;
      if (isMalwareFamily(n, ["notpetya", "shamoon", "caddywiper"])) s += 30;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["disk-wipe", "partition-delete"])) r.push("IOC linked to destructive disk wiping activity");
      return r;
    },
    mitigations: [
      {
        id: "M1053",
        name: "Data Backup",
        description: "Consider implementing IT disaster recovery plans that contain procedures for taking regular data backups that can be used to restore organizational data. Ensure backups are stored off system and is protected from common methods adversaries may use to gain access and destroy the backups to prevent recovery.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1667",
    name: "Email Bombing",
    tactic: "Impact",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["email-bombing", "mail-flood", "spam-flood"])) s += 65;
      if (n.type === "domain" && hasTagPartial(n, ["spam", "mail-flood"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["email-bomb", "mail-flood"])) r.push("IOC associated with email flooding attacks");
      return r;
    },
    mitigations: [
      {
        id: "M1054",
        name: "Software Configuration",
        description: "Use anti-spoofing and email authentication mechanisms to filter messages based on validity checks of the sender domain (using SPF) and integrity of messages (using DKIM). Enabling these mechanisms within an organization (through policies such as DMARC) may enable recipients (intra-org and cross domain) to perform similar message filtering and validation. Note that additional filtering may be necessary if emails are coming from legitimate sources.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1017",
        name: "User Training",
        description: "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful social engineering via e-mail bombing.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1499",
    name: "Endpoint Denial of Service",
    tactic: "Impact",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["endpoint-dos", "application-crash", "resource-exhaustion"])) s += 70;
      if (n.abuse_score >= 60) s += 15;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["resource-exhaustion", "application-crash"])) r.push("IOC associated with endpoint/service resource exhaustion");
      return r;
    },
    mitigations: [
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Leverage services provided by Content Delivery Networks (CDN) or providers specializing in DoS mitigations to filter traffic upstream from services. Filter boundary traffic by blocking source addresses sourcing the attack, blocking ports that are being targeted, or blocking protocols being used for transport. To defend against SYN floods, enable SYN Cookies.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1657",
    name: "Financial Theft",
    tactic: "Impact",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["banking-malware", "financial-fraud", "wire-fraud", "payment-theft"])) s += 75;
      if (isMalwareFamily(n, ["dridex", "trickbot", "gozi", "zeus"])) s += 30;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["financial", "banking-malware", "payment"])) r.push("IOC linked to financial theft activity");
      return r;
    },
    mitigations: [
      {
        id: "M1018",
        name: "User Account Management",
        description: "Limit access/authority to execute sensitive transactions, and switch to systems and procedures designed to authenticate/approve payments and purchase requests outside of insecure communication lines such as email.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1017",
        name: "User Training",
        description: "Train and encourage users to identify social engineering techniques used to enable financial theft. Also consider training users on procedures to prevent and respond to swatting and doxing, acts increasingly deployed by financially motivated groups to further coerce victims into satisfying ransom/extortion demands.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1495",
    name: "Firmware Corruption",
    tactic: "Impact",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["firmware-corruption", "uefi-malware", "bios-modification"])) s += 80;
      if (n.type.includes("hash") && hasTagPartial(n, ["firmware", "uefi", "bios"])) s += 30;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["uefi", "bios", "firmware"])) r.push("IOC associated with firmware-level corruption or persistence");
      return r;
    },
    mitigations: [
      {
        id: "M1046",
        name: "Boot Integrity",
        description: "Check the integrity of the existing BIOS and device firmware to determine if it is vulnerable to modification.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1026",
        name: "	Privileged Account Management",
        description: "Prevent adversary access to privileged accounts or access necessary to replace system firmware.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1051",
        name: "Update Software",
        description: "Patch the BIOS and other firmware as necessary to prevent successful use of known vulnerabilities.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1490",
    name: "Inhibit System Recovery",
    tactic: "Impact",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["shadow-copy-delete", "backup-delete", "recovery-disable"])) s += 75;
      if (hasTagPartial(n, ["vssadmin", "shadow-copy"])) s += 30;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["shadow-copy", "backup-delete", "recovery-disable"])) r.push("IOC associated with disabling recovery mechanisms");
      return r;
    },
    mitigations: [
      {
        id: "M1053",
        name: "Data Backup",
        description: "Consider implementing IT disaster recovery plans that contain procedures for taking regular data backups that can be used to restore organizational data. Ensure backups are stored off system and is protected from common methods adversaries may use to gain access and destroy the backups to prevent recovery. In cloud environments, enable versioning on storage objects where possible, and copy backups to other accounts or regions to isolate them from the original copies. On ESXi servers, ensure that disk images and snapshots of virtual machines are regularly taken, with copies stored off system.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1038",
        name: "Execution Prevention",
        description: "Consider using application control configured to block execution of utilities such as diskshadow.exe that may not be required for a given system or network to prevent potential misuse by adversaries.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1028",
        name: "Operating System Configuration",
        description: "Consider technical controls to prevent the disabling of services or deletion of files involved in system recovery. Additionally, ensure that WinRE is enabled using the following command: reagentc /enable.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description: "Limit the user accounts that have access to backups to only those required. In AWS environments, consider using Service Control Policies to restrict API calls to delete backups, snapshots, and images.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1529",
    name: "System Shutdown/Reboot",
    tactic: "Impact",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["forced-reboot", "shutdown", "system-crash", "restart-loop"])) s += 65;
      if (hasTagPartial(n, ["shutdown", "reboot"])) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["shutdown", "restart-loop"])) r.push("IOC linked to forced system shutdown or reboot activity");
      return r;
    },
    mitigations: [
      {
        id: "-",
        name: "-",
        description: "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
];

// ================================================================
// Baseline — NIST SP 800-61r2 IR lifecycle (always included)
// ================================================================

const BASELINE_MITIGATIONS: MitigationAction[] = [
  {
    id: "NIST-IR-1",
    name: "Document & Escalate Finding",
    description: "Record all findings with timestamps in your incident tracking system. Escalate to SOC Tier 2 if threat level is HIGH or CRITICAL. Aligns with NIST SP 800-61r2 Section 3.2 (Detection & Analysis).",
    framework: "NIST SP 800-61r2",
  },
  {
    id: "NIST-IR-2",
    name: "Update Threat Intelligence Feeds",
    description: "Export this IOC to SIEM and TIP. Create correlation detection rules. Share with relevant ISACs. Aligns with NIST CSF DE.AE-2 and MITRE ATT&CK D3FEND.",
    framework: "NIST CSF + MITRE D3FEND",
  },
  {
    id: "NIST-IR-3",
    name: "Post-Incident Review",
    description: "Conduct a lessons-learned review after containment. Update detection playbooks and IR runbooks. Aligns with NIST SP 800-61r2 Section 3.4 (Post-Incident Activity).",
    framework: "NIST SP 800-61r2",
  },
];

// ================================================================
// Confidence Scoring
// ================================================================

export function calculateConfidence(
  normalized: NormalizedIndicator,
): "High" | "Medium" | "Low" {
  const vtRatio =
    normalized.vt_total > 0
      ? (normalized.vt_score / normalized.vt_total) * 100
      : 0;

  let score = 0;
  score += vtRatio * 0.4;
  score += normalized.abuse_score * 0.3;
  if (normalized.misp_confidence === "High") score += 25;
  else if (normalized.misp_confidence === "Medium") score += 15;
  if (normalized.tags.length > 0) score += 10;

  if (score >= 70) return "High";
  if (score >= 40) return "Medium";
  return "Low";
}

// ================================================================
// Main Analysis Engine
// ================================================================

export async function analyzeThreatToMitigation(
  normalized: NormalizedIndicator,
): Promise<ThreatIntelResult> {
  const matchedTechniques: TechniqueMatch[] = [];
  const mitigations: MitigationAction[] = [];
  const seenMitigations = new Set<string>();

  for (const entry of TECHNIQUE_MAP) {
    const confidence = entry.score(normalized);
    if (confidence >= 30) {
      matchedTechniques.push({
        technique: entry.technique,
        techniqueName: entry.name,
        tactic: entry.tactic,
        confidence,
        reasons: entry.reasons(normalized),
      });

      for (const m of entry.mitigations) {
        if (!seenMitigations.has(m.id)) {
          seenMitigations.add(m.id);
          mitigations.push(m);
        }
      }
    }
  }

  matchedTechniques.sort((a, b) => b.confidence - a.confidence);

  for (const m of BASELINE_MITIGATIONS) {
    if (!seenMitigations.has(m.id)) {
      mitigations.push(m);
    }
  }

  return {
    primaryTechnique: matchedTechniques[0]?.technique ?? null,
    primaryTechniqueName: matchedTechniques[0]?.techniqueName ?? null,
    techniques: matchedTechniques,
    mitigations,
    cve: null,
    cwe: null,
  };
}

// ================================================================
// Utility
// ================================================================

const TECHNIQUE_NAMES: Record<string, string> = Object.fromEntries(
  TECHNIQUE_MAP.map((t) => [t.technique, t.name]),
);

export async function getTechniqueByCode(
  code: string,
): Promise<{ code: string; name: string } | null> {
  if (!code) return null;
  const name = TECHNIQUE_NAMES[code];
  return name ? { code, name } : null;
}