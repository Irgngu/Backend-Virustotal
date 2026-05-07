// mitigation.ts
// ================================================================
// Advanced CTI Mitigation Engine — MITRE ATT&CK v14 Full Coverage
//
// Frameworks referenced:
//   MITRE ATT&CK v14  — https://attack.mitre.org
//   NIST SP 800-61r2  — Incident Response
//   NIST SP 800-53r5  — Security Controls
//   OWASP Top 10 2021 — https://owasp.org/Top10
//   NIST CSF 2.0      — Cybersecurity Framework
//
// Tactics covered (15):
//   TA0001 Initial Access       TA0002 Execution
//   TA0003 Persistence          TA0004 Privilege Escalation
//   TA0005 Defense Evasion      TA0006 Credential Access
//   TA0007 Discovery            TA0008 Lateral Movement
//   TA0009 Collection           TA0010 Exfiltration
//   TA0011 Command & Control    TA0040 Impact
//   TA0042 Resource Development TA0043 Reconnaissance
//   TA0101 Stealth (new v16+)   TA0102 Defense Impairment (new v16+)
// ================================================================

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
// MITRE ATT&CK v14 — Full Technique Map
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
        description: "Minimize internet-facing attack surface. Disable unnecessary services/ports. Conduct regular external attack surface management (EASM). Aligns with NIST SP 800-115.",
        framework: "MITRE ATT&CK + NIST SP 800-115",
      },
    ],
  },
  {
    technique: "T1595.001",
    name: "Active Scanning: Scanning IP Blocks",
    tactic: "Reconnaissance",
    score: (n) => {
      let s = 0;
      if (n.type === "subnet") s += 40;
      if (n.type === "ip" && hasTag(n, ["scanner"])) s += 30;
      if (n.abuse_score >= 40) s += 20;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (n.type === "subnet") r.push("Indicator is an IP block/subnet targeted in scanning");
      if (n.abuse_score >= 40) r.push("AbuseIPDB score indicates systematic IP block scanning");
      return r;
    },
    mitigations: [
      {
        id: "M1056",
        name: "Pre-compromise Mitigation",
        description: "Implement network access controls and segment critical infrastructure. Block subnets associated with known scanning infrastructure.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 SC-7",
      },
    ],
  },
  {
    technique: "T1595.002",
    name: "Active Scanning: Vulnerability Scanning",
    tactic: "Reconnaissance",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["vuln-scan", "vulnerability", "nessus", "openvas"])) s += 60;
      if (n.type === "ip" && n.abuse_score >= 30) s += 20;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["vuln", "nessus", "openvas"])) r.push("Tags suggest vulnerability scanning activity");
      return r;
    },
    mitigations: [
      {
        id: "M1016",
        name: "Vulnerability Scanning",
        description: "Conduct proactive internal vulnerability scanning. Patch internet-facing systems regularly per NIST SP 800-40r4 before adversaries identify weaknesses.",
        framework: "MITRE ATT&CK + NIST SP 800-40r4",
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
        description: "Reduce sensitive technical exposure in public databases. Request removal from Shodan/Censys. Monitor your attack surface with EASM tools. Aligns with NIST CSF PR.AC.",
        framework: "MITRE ATT&CK + NIST CSF",
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
        description: "Train users to recognize spear-phishing attempts targeting credential/info harvesting. Simulate phishing campaigns regularly. Aligns with NIST SP 800-50.",
        framework: "MITRE ATT&CK + NIST SP 800-50",
      },
      {
        id: "M1054",
        name: "Software Configuration",
        description: "Configure email security gateways with anti-phishing policies. Enforce DMARC/DKIM/SPF. Aligns with NIST SP 800-177.",
        framework: "MITRE ATT&CK + NIST SP 800-177",
      },
    ],
  },
  // TA0043 — RECONNAISSANCE

{
  technique: "T1590",
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
        "Reduce public exposure of host metadata and services. Disable unnecessary DNS records and minimize information leakage from internet-facing systems.",
      framework: "MITRE ATT&CK + NIST SP 800-53r5",
    },
    {
      id: "M1037",
      name: "Filter Network Traffic",
      description:
        "Restrict unauthorized reconnaissance traffic and monitor DNS enumeration attempts using IDS/IPS.",
      framework: "MITRE ATT&CK + NIST SP 800-41",
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
      id: "M1017",
      name: "User Training",
      description:
        "Educate employees regarding social engineering and identity harvesting attempts through phishing or OSINT collection.",
      framework: "MITRE ATT&CK + NIST SP 800-50",
    },
    {
      id: "M1027",
      name: "Password Policies",
      description:
        "Enforce strong password policies and MFA to reduce risks from harvested identity information.",
      framework: "MITRE ATT&CK + NIST SP 800-63B",
    },
  ],
},

{
  technique: "T1590.001",
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
      id: "M1030",
      name: "Network Segmentation",
      description:
        "Segment internal networks and minimize exposure of sensitive routing and topology information.",
      framework: "MITRE ATT&CK + NIST SP 800-125B",
    },
    {
      id: "M1037",
      name: "Filter Network Traffic",
      description:
        "Monitor and restrict unauthorized network mapping and enumeration activities.",
      framework: "MITRE ATT&CK + NIST SP 800-41",
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
      id: "M1017",
      name: "User Training",
      description:
        "Educate employees regarding oversharing organizational information on public platforms.",
      framework: "MITRE ATT&CK + NIST SP 800-50",
    },
    {
      id: "M1056",
      name: "Pre-compromise Mitigation",
      description:
        "Limit publicly accessible organizational data and monitor external exposure through OSINT platforms.",
      framework: "MITRE ATT&CK + NIST CSF",
    },
  ],
},

{
  technique: "T1597",
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
      id: "M1017",
      name: "User Training",
      description:
        "Educate users about risks of exposing sensitive information to public AI services.",
      framework: "MITRE ATT&CK + NIST AI RMF",
    },
    {
      id: "M1054",
      name: "Software Configuration",
      description:
        "Restrict usage of unauthorized public AI services and enforce DLP policies for sensitive data.",
      framework: "MITRE ATT&CK + NIST AI RMF",
    },
  ],
},

{
  technique: "T1596.001",
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
        "Monitor dark web exposure and leaked organizational data through threat intelligence services.",
      framework: "MITRE ATT&CK + NIST CSF",
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
      id: "M1056",
      name: "Pre-compromise Mitigation",
      description:
        "Reduce publicly exposed metadata and sensitive information on websites/domains.",
      framework: "MITRE ATT&CK + NIST CSF",
    },
  ],
},

{
  technique: "T1596.002",
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
        "Continuously monitor threat intelligence platforms for exposed infrastructure and malicious indicators.",
      framework: "MITRE ATT&CK + NIST CSF",
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
        "Harden public-facing websites and remove unnecessary exposed resources or directories.",
      framework: "MITRE ATT&CK + NIST SP 800-53r5",
    },
    {
      id: "M1037",
      name: "Filter Network Traffic",
      description:
        "Use WAF and rate limiting to detect reconnaissance and directory brute-force activity.",
      framework: "MITRE ATT&CK + NIST SP 800-41",
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
        description: "Monitor newly registered domains similar to your brand. Subscribe to domain monitoring and threat intel feeds to detect attacker infrastructure early.",
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
        description: "Implement supply chain security controls. Verify integrity of third-party infrastructure. Audit external dependencies. Aligns with NIST SP 800-161.",
        framework: "MITRE ATT&CK + NIST SP 800-161",
      },
    ],
  },
  {
    technique: "T1587",
    name: "Develop Capabilities (Custom Malware)",
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
        id: "M1049",
        name: "Antivirus/Antimalware",
        description: "Deploy behavioral-based EDR to detect novel/custom malware not covered by static signatures. Aligns with NIST SP 800-83.",
        framework: "MITRE ATT&CK + NIST SP 800-83",
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
        id: "M1032",
        name: "Multi-factor Authentication",
        description:
          "Enforce MFA on VPN, RDP, cloud, and privileged accounts to reduce risks from purchased or stolen access.",
        framework: "MITRE ATT&CK + NIST SP 800-63B",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description:
          "Monitor for unauthorized remote access sessions and disable dormant accounts.",
        framework: "MITRE ATT&CK + NIST SP 800-53",
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
        id: "M1032",
        name: "Multi-factor Authentication",
        description:
          "Require MFA for all sensitive and privileged accounts.",
        framework: "MITRE ATT&CK + NIST SP 800-63B",
      },
      {
        id: "M1027",
        name: "Password Policies",
        description:
          "Enforce strong password policies and monitor credential reuse.",
        framework: "MITRE ATT&CK + NIST SP 800-63B",
      },
      {
        id: "M1018",
        name: "User Account Management",
        description:
          "Monitor suspicious logins and disable compromised accounts immediately.",
        framework: "MITRE ATT&CK + NIST SP 800-53",
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
        id: "M1018",
        name: "User Account Management",
        description:
          "Monitor newly created accounts and implement identity verification controls.",
        framework: "MITRE ATT&CK + NIST SP 800-53",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description:
          "Require MFA during account onboarding and privileged access activation.",
        framework: "MITRE ATT&CK + NIST SP 800-63B",
      },
    ],
  },

  {
    technique: "T1588.001",
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
        id: "M1017",
        name: "User Training",
        description:
          "Train users to recognize spoofed documents, phishing templates, and malicious attachments.",
        framework: "MITRE ATT&CK + NIST SP 800-50",
      },
      {
        id: "M1054",
        name: "Software Configuration",
        description:
          "Block malicious document macros and restrict untrusted attachments.",
        framework: "MITRE ATT&CK + NIST SP 800-177",
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
        id: "M1049",
        name: "Antivirus/Antimalware",
        description:
          "Deploy EDR/AV capable of detecting exploit frameworks and malware toolkits.",
        framework: "MITRE ATT&CK + NIST SP 800-83",
      },
      {
        id: "M1050",
        name: "Exploit Protection",
        description:
          "Enable exploit mitigation technologies and application hardening.",
        framework: "MITRE ATT&CK + NIST SP 800-53",
      },
    ],
  },

  {
    technique: "T1588.002",
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
        id: "M1037",
        name: "Filter Network Traffic",
        description:
          "Block known malware staging domains and monitor outbound payload retrieval activity.",
        framework: "MITRE ATT&CK + NIST SP 800-41",
      },
      {
        id: "M1049",
        name: "Antivirus/Antimalware",
        description:
          "Detect and quarantine droppers, loaders, and staged payloads using EDR solutions.",
        framework: "MITRE ATT&CK + NIST SP 800-83",
      },
    ],
  },

  // TA0001 — INITIAL ACCESS
  {
    technique: "T1190",
    name: "Exploit Public-Facing Application",
    tactic: "Initial Access",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["exploit", "webshell", "sqli", "rce", "lfi", "rfi", "ssrf"])) s += 60;
      if (n.type === "url" && hasTagPartial(n, ["exploit", "injection", "shell"])) s += 30;
      if (n.vt_score >= 5) s += 10;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["exploit", "rce", "sqli", "ssrf"])) r.push("Tags indicate web application exploitation");
      if (n.type === "url") r.push("URL-type IOC consistent with exploit delivery or webshell");
      return r;
    },
    mitigations: [
      {
        id: "M1048",
        name: "Application Isolation & Sandboxing",
        description: "Run public-facing apps in isolated environments. Deploy WAF to detect and block OWASP Top 10 exploits. Aligns with OWASP A03:2021 (Injection).",
        framework: "MITRE ATT&CK + OWASP A03",
      },
      {
        id: "M1030",
        name: "Network Segmentation",
        description: "Isolate public-facing servers from internal networks using DMZ architecture. Aligns with NIST SP 800-53r5 SC-7.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 SC-7",
      },
      {
        id: "M1016",
        name: "Vulnerability Scanning",
        description: "Conduct regular vulnerability assessments on public-facing applications. Prioritize patching by CVSS score. Aligns with NIST SP 800-40r4.",
        framework: "MITRE ATT&CK + NIST SP 800-40r4",
      },
    ],
  },
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
        description: "Restrict RDP/SSH/VPN to approved source IPs only. Place behind VPN/jump host. Aligns with NIST SP 800-46r2.",
        framework: "MITRE ATT&CK + NIST SP 800-46r2",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description: "Enforce MFA on all external remote access services. Use phishing-resistant MFA (FIDO2) per NIST SP 800-63B AAL2+.",
        framework: "MITRE ATT&CK + NIST SP 800-63B",
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
        description: "Ensure endpoint AV signatures are updated. Scan all attachments in sandboxed environment. Aligns with NIST SP 800-83.",
        framework: "MITRE ATT&CK + NIST SP 800-83",
      },
      {
        id: "M1054",
        name: "Software Configuration",
        description: "Configure SPF, DKIM, DMARC. Enable attachment sandboxing and URL link-scanning. Aligns with NIST SP 800-177 and OWASP.",
        framework: "MITRE ATT&CK + NIST SP 800-177 + OWASP",
      },
      {
        id: "M1017",
        name: "User Training",
        description: "Conduct regular anti-phishing training and simulations. Track phishing click rate as a security KPI. Aligns with NIST SP 800-50.",
        framework: "MITRE ATT&CK + NIST SP 800-50",
      },
      {
        id: "M1047",
        name: "Audit",
        description: "Determine if certain websites or attachment types (ex: .scr, .exe, .pif, .cpl, etc.) that can be used for phishing are necessary for business operations and consider blocking access if activity cannot be monitored well or if it poses a significant risk.",
        framework: "MITRE ATT&CK + NIST SP 800-50",
      },
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Network intrusion prevention systems and systems designed to scan and remove malicious email attachments or links can be used to block activity.",
        framework: "MITRE ATT&CK + NIST SP 800-50",
      },
      {
        id: "M1021",
        name: "Restrict Web-Based Content",
        description: "Determine if certain websites or attachment types (ex: .scr, .exe, .pif, .cpl, etc.) that can be used for phishing are necessary for business operations and consider blocking access if activity cannot be monitored well or if it poses a significant risk.",
        framework: "MITRE ATT&CK + NIST SP 800-50",
      },
    ],
  },
  {
    technique: "T1566.001",
    name: "Phishing: Spearphishing Attachment",
    tactic: "Initial Access",
    score: (n) => {
      let s = 0;
      if (n.type.includes("hash") && hasTagPartial(n, ["phish", "doc", "office", "macro"])) s += 60;
      if (hasTag(n, ["spearphishing-attachment", "malicious-doc"])) s += 50;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["macro", "malicious-doc"])) r.push("Hash associated with malicious macro-enabled document");
      return r;
    },
    mitigations: [
      {
        id: "M1049",
        name: "Antivirus/Antimalware",
        description: "Block execution of malicious macros in Office documents. Disable macros from untrusted sources by default. Aligns with NIST SP 800-83.",
        framework: "MITRE ATT&CK + NIST SP 800-83",
      },
      {
        id: "M1021",
        name: "Restrict Web-Based Content",
        description: "Use email attachment sandboxing to analyze suspicious files before delivery. OWASP A08:2021 (Software Integrity).",
        framework: "MITRE ATT&CK + OWASP A08",
      },
    ],
  },
  {
    technique: "T1566.002",
    name: "Phishing: Spearphishing Link",
    tactic: "Initial Access",
    score: (n) => {
      let s = 0;
      if (n.type === "url" && hasTag(n, ["phishing", "spearphishing"])) s += 65;
      if (n.type === "domain" && hasTagPartial(n, ["phish"])) s += 40;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (n.type === "url" && hasTagPartial(n, ["phish"])) r.push("URL confirmed as a spearphishing link");
      return r;
    },
    mitigations: [
      {
        id: "M1021",
        name: "Restrict Web-Based Content",
        description: "Block malicious URL at web proxy and email link-scanner layer. Enable URL sandbox detonation before delivery.",
        framework: "MITRE ATT&CK + OWASP",
      },
    ],
  },
  {
    technique: "T1566.003",
    name: "Phishing: Spearphishing via Service",
    tactic: "Initial Access",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["social-media-phishing", "linkedin-phish", "teams-phish", "slack-phish"])) s += 65;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["social-media", "linkedin", "teams-phish"])) r.push("IOC linked to phishing via social/business messaging service");
      return r;
    },
    mitigations: [
      {
        id: "M1017",
        name: "User Training",
        description: "Train users to be suspicious of unsolicited contact via social platforms requesting credentials or downloads. Aligns with NIST SP 800-50.",
        framework: "MITRE ATT&CK + NIST SP 800-50",
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
        description: "Enable ASLR, DEP, and browser-level exploit mitigations. Keep browsers and plugins fully patched. Aligns with NIST SP 800-40r4.",
        framework: "MITRE ATT&CK + NIST SP 800-40r4",
      },
      {
        id: "M1021",
        name: "Restrict Web-Based Content",
        description: "Block malicious URL at DNS/proxy layer. Use browser isolation for high-risk users. Aligns with OWASP A03:2021.",
        framework: "MITRE ATT&CK + OWASP A03",
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
        description: "Implement software composition analysis (SCA). Verify package integrity via checksums and SBOM. Aligns with NIST SP 800-161 and OWASP A06:2021.",
        framework: "MITRE ATT&CK + NIST SP 800-161 + OWASP A06",
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
        description: "Audit and rotate compromised credentials immediately. Enforce PAM solutions. Aligns with NIST SP 800-53r5 AC-2.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 AC-2",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description: "Enforce MFA on all accounts, especially privileged and remote access. NIST SP 800-63B AAL2+.",
        framework: "MITRE ATT&CK + NIST SP 800-63B",
      },
      {
        id: "M1019",
        name: "Threat Intelligence Program",
        description: "Ingest this MISP IOC into SIEM. Create detection rules for known-bad credentials. Share with ISACs where applicable. Aligns with NIST CSF DE.AE-2.",
        framework: "MITRE ATT&CK + NIST CSF DE.AE-2",
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
        name: "Software Configuration",
        description:
          "Implement CSP, input sanitization, and secure HTTP headers to prevent malicious content injection.",
        framework: "MITRE ATT&CK + OWASP A03:2021",
      },
      {
        id: "M1048",
        name: "Application Isolation & Sandboxing",
        description:
          "Use browser isolation and WAF protections to detect injected malicious scripts.",
        framework: "MITRE ATT&CK + OWASP",
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
        name: "Application Isolation & Sandboxing",
        description:
          "Run public-facing apps in isolated environments and deploy WAF protections against OWASP Top 10 attacks.",
        framework: "MITRE ATT&CK + OWASP A03",
      },
      {
        id: "M1016",
        name: "Vulnerability Scanning",
        description:
          "Conduct regular vulnerability scanning and prioritize patching based on CVSS severity.",
        framework: "MITRE ATT&CK + NIST SP 800-40r4",
      },
      {
        id: "M1030",
        name: "Network Segmentation",
        description:
          "Place internet-facing applications in DMZ architecture separated from internal systems.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5",
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
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description:
          "Disable autorun/autoplay and restrict unauthorized USB device usage.",
        framework: "MITRE ATT&CK + NIST SP 800-53",
      },
      {
        id: "M1034",
        name: "Limit Hardware Installation",
        description:
          "Enforce endpoint device control policies and restrict unauthorized peripherals.",
        framework: "MITRE ATT&CK + NIST SP 800-171",
      },
      {
        id: "M1017",
        name: "User Training",
        description:
          "Educate users against connecting unknown removable devices to corporate systems.",
        framework: "MITRE ATT&CK + NIST SP 800-50",
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
          "Disable autorun/autoplay for removable media across enterprise endpoints.",
        framework: "MITRE ATT&CK + NIST SP 800-53",
      },
      {
        id: "M1049",
        name: "Antivirus/Antimalware",
        description:
          "Scan removable devices automatically before allowing file execution.",
        framework: "MITRE ATT&CK + NIST SP 800-83",
      },
      {
        id: "M1034",
        name: "Limit Hardware Installation",
        description:
          "Restrict unauthorized USB storage devices using endpoint control solutions.",
        framework: "MITRE ATT&CK + NIST SP 800-171",
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
          "Restrict and continuously audit third-party/vendor account permissions.",
        framework: "MITRE ATT&CK + NIST SP 800-53",
      },
      {
        id: "M1030",
        name: "Network Segmentation",
        description:
          "Isolate partner/vendor access from critical internal environments.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description:
          "Require MFA for all partner and third-party remote access connections.",
        framework: "MITRE ATT&CK + NIST SP 800-63B",
      },
    ],
  },

  {
    technique: "T1090.003",
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
        id: "M1035",
        name: "Limit Access to Resource Over Network",
        description:
          "Restrict wireless access using NAC and approved device policies.",
        framework: "MITRE ATT&CK + NIST SP 800-153",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description:
          "Require MFA for wireless network authentication and remote services.",
        framework: "MITRE ATT&CK + NIST SP 800-63B",
      },
      {
        id: "M1041",
        name: "Encrypt Sensitive Information",
        description:
          "Enforce WPA3 and strong wireless encryption standards for enterprise Wi-Fi.",
        framework: "MITRE ATT&CK + NIST SP 800-153",
      },
    ],
  },

  // TA0002 — EXECUTION
  {
    technique: "T1059",
    name: "Command and Scripting Interpreter",
    tactic: "Execution",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["powershell", "cmd", "bash", "python", "wscript", "cscript", "vbs"])) s += 55;
      if (n.type.includes("hash") && hasTagPartial(n, ["script", "shell", "interpreter"])) s += 30;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["powershell", "script", "bash"])) r.push("IOC associated with scripting interpreter abuse");
      return r;
    },
    mitigations: [
      {
        id: "M1026",
        name: "Privileged Account Management",
        description: "Limit who can execute scripting engines. Use PowerShell Constrained Language Mode. Aligns with NIST SP 800-53r5 AC-6.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 AC-6",
      },
      {
        id: "M1038",
        name: "Execution Prevention",
        description: "Block unauthorized script execution via AppLocker/WDAC policies. Log all script execution in SIEM. Aligns with NIST SP 800-167.",
        framework: "MITRE ATT&CK + NIST SP 800-167",
      },
    ],
  },
  {
    technique: "T1059.001",
    name: "Command and Scripting Interpreter: PowerShell",
    tactic: "Execution",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["powershell", "ps1"])) s += 70;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["powershell", "ps1"])) r.push("IOC linked to malicious PowerShell execution");
      return r;
    },
    mitigations: [
      {
        id: "M1045",
        name: "Code Signing",
        description: "Require signed PowerShell scripts. Enable script block logging and transcription. Use Constrained Language Mode in production.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1059.003",
    name: "Command and Scripting Interpreter: Windows Command Shell",
    tactic: "Execution",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["cmd", "bat", "command-shell"])) s += 60;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["cmd", "batch"])) r.push("IOC linked to malicious Windows Command Shell usage");
      return r;
    },
    mitigations: [
      {
        id: "M1038",
        name: "Execution Prevention",
        description: "Restrict cmd.exe execution to authorized users. Audit command-line activity via EDR telemetry.",
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
        description: "Block malicious file hashes via EDR and application allowlisting. Add to SIEM blocklist immediately. Aligns with NIST SP 800-167.",
        framework: "MITRE ATT&CK + NIST SP 800-167",
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
        description: "Restrict access to software deployment tools. Require MFA and full audit trail for all deployment actions. Aligns with NIST SP 800-53r5 CM-7.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 CM-7",
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
        id: "M1038",
        name: "Execution Prevention",
        description:
          "Restrict unauthorized BITS job creation and monitor bitsadmin usage through EDR telemetry.",
        framework: "MITRE ATT&CK + NIST SP 800-167",
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
          "Restrict cloud administrative privileges and enforce least privilege access.",
        framework: "MITRE ATT&CK + NIST SP 800-53",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description:
          "Require MFA for all cloud administrative accounts and CLI access.",
        framework: "MITRE ATT&CK + NIST SP 800-63B",
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
          "Restrict unauthorized script execution using AppLocker or WDAC policies.",
        framework: "MITRE ATT&CK + NIST SP 800-167",
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
        id: "M1048",
        name: "Application Isolation & Sandboxing",
        description:
          "Restrict container administration access and isolate workloads securely.",
        framework: "MITRE ATT&CK + NIST SP 800-190",
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
        id: "M1048",
        name: "Application Isolation & Sandboxing",
        description:
          "Restrict container image execution to trusted registries and signed images.",
        framework: "MITRE ATT&CK + NIST SP 800-190",
      },
    ],
  },

  {
    technique: "T1059.012",
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
        id: "M1032",
        name: "Multi-factor Authentication",
        description:
          "Require MFA for VMware ESXi and vCenter administration access.",
        framework: "MITRE ATT&CK + NIST SP 800-63B",
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
          "Enable browser exploit protection and keep client software fully patched.",
        framework: "MITRE ATT&CK + NIST SP 800-40",
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
        id: "M1045",
        name: "Code Signing",
        description:
          "Enforce signed binaries and monitor DLL search-order hijacking attempts.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1056",
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
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description:
          "Monitor suspicious process interaction and synthetic input behavior.",
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
          "Monitor suspicious IPC mechanisms and abnormal process interactions.",
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
          "Detect suspicious native API usage and direct syscall behavior.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1608",
    name: "Stage Capabilities",
    tactic: "Execution",
    score: (n) => {
      let s = 0;

      if (
        hasTag(n, [
          "payload-stage",
          "stager",
          "loader",
          "dropper",
        ])
      )
        s += 65;

      if (hasTagPartial(n, ["stager", "loader", "dropper"])) s += 25;

      return s;
    },

    reasons: (n) => {
      const r: string[] = [];

      if (hasTagPartial(n, ["loader", "dropper"])) {
        r.push("IOC associated with staged execution payloads");
      }

      return r;
    },

    mitigations: [
      {
        id: "M1049",
        name: "Antivirus/Antimalware",
        description:
          "Detect staged malware payloads and execution loaders using EDR.",
        framework: "MITRE ATT&CK + NIST SP 800-83",
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
          "Restrict scheduled task creation permissions and audit scheduled jobs.",
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
        id: "M1026",
        name: "Privileged Account Management",
        description:
          "Restrict serverless deployment privileges and monitor cloud execution logs.",
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
        id: "M1045",
        name: "Code Signing",
        description:
          "Restrict execution to trusted signed shared libraries and modules.",
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
          "Monitor service creation events and detect suspicious service execution.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1211",
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
          "Restrict execution of LOLBins and trusted developer utilities where unnecessary.",
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
          "Monitor WMI event subscriptions and suspicious remote WMI execution.",
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
        description: "Audit account changes regularly. Alert on new privileged account creation. Aligns with NIST SP 800-53r5 AC-2.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 AC-2",
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
        description: "Restrict write access to service registry keys and systemd directories. Alert on new service creation. Aligns with NIST SP 800-53r5 AC-3.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 AC-3",
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
        id: "M1038",
        name: "Execution Prevention",
        description: "Monitor and restrict modifications to autostart registry keys (HKCU/HKLM Run) and startup folders. Deploy EDR for autorun monitoring.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 CM-7",
      },
    ],
  },
  {
    technique: "T1505",
    name: "Server Software Component (Webshell)",
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
        description: "Remove unnecessary server-side scripting capabilities. Monitor web directories for new/modified files. Aligns with OWASP A05:2021.",
        framework: "MITRE ATT&CK + OWASP A05",
      },
      {
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description: "Set web root to read-only for the web server process. Alert on file system changes in web-accessible directories.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 AC-3",
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
        description: "Monitor for new account creation events. Alert on accounts added to privileged groups. Use PAM solution. Aligns with NIST SP 800-53r5 AC-2.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 AC-2",
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
        id: "M1038",
        name: "Execution Prevention",
        description:
          "Restrict unauthorized startup and logon script execution. Monitor Group Policy and startup folder modifications.",
        framework: "MITRE ATT&CK + NIST SP 800-53",
      },
    ],
  },

  {
    technique: "T1136.001",
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
        id: "M1018",
        name: "User Account Management",
        description:
          "Restrict third-party OAuth application consent and review cloud app integrations regularly.",
        framework: "MITRE ATT&CK + NIST SP 800-63",
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
          "Enforce integrity validation and code signing verification for system binaries.",
        framework: "MITRE ATT&CK + OWASP A08",
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
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description:
          "Monitor suspicious WMI subscriptions and event-triggered task execution.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1539",
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
        id: "M1018",
        name: "User Account Management",
        description:
          "Review access control policies and monitor for unauthorized ownership or lockout modifications.",
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
          "Verify integrity and cryptographic signatures of VM/container images before deployment.",
        framework: "MITRE ATT&CK + NIST SP 800-190",
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
          "Monitor authentication module changes and enforce integrity protection for authentication components.",
        framework: "MITRE ATT&CK + NIST SP 800-63",
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
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description:
          "Restrict write access to sensitive registry keys and monitor registry changes continuously.",
        framework: "MITRE ATT&CK + NIST SP 800-53",
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
        id: "M1049",
        name: "Antivirus/Antimalware",
        description:
          "Disable untrusted Office macros and monitor Office startup templates/add-ins.",
        framework: "MITRE ATT&CK + NIST SP 800-83",
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
        id: "M1028",
        name: "Operating System Configuration",
        description:
          "Restrict modification of system power policies and audit power configuration changes.",
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
          "Enable Secure Boot and TPM-based boot integrity validation to detect bootkits.",
        framework: "MITRE ATT&CK + NIST SP 800-147",
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
        id: "M1045",
        name: "Code Signing",
        description:
          "Allow only trusted signed browser extensions and plugins from approved sources.",
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
          "Detect and block suspicious beaconing or trigger-based network communications.",
        framework: "MITRE ATT&CK + NIST SP 800-41",
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
        description: "Apply OS and kernel patches promptly. Enforce least-privilege across all accounts. Aligns with NIST SP 800-40r4.",
        framework: "MITRE ATT&CK + NIST SP 800-40r4",
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
        description: "Enforce UAC prompts at the highest level. Audit sudo rules. Remove unnecessary SUID binaries on Linux. Aligns with NIST SP 800-53r5 AC-6.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 AC-6",
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
          "Restrict SeDebugPrivilege and monitor token impersonation activity through EDR telemetry. Enforce least privilege for service accounts.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 AC-6",
      },
      {
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description:
          "Detect suspicious token duplication and impersonation attempts using endpoint behavioral analytics.",
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
          "Restrict administrative access to Group Policy Objects and tenant-wide cloud policies. Require MFA for all administrative changes.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 AC-6",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description:
          "Enforce MFA for Active Directory and cloud tenant administrative accounts.",
        framework: "MITRE ATT&CK + NIST SP 800-63B",
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
        name: "Application Isolation & Sandboxing",
        description:
          "Harden container and virtualization environments. Restrict privileged containers and enable namespace isolation.",
        framework: "MITRE ATT&CK + NIST SP 800-190",
      },
      {
        id: "M1051",
        name: "Update Software",
        description:
          "Apply security updates for container runtimes, hypervisors, and orchestration platforms promptly.",
        framework: "MITRE ATT&CK + NIST SP 800-40r4",
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
          "Use EDR solutions to detect remote thread creation, memory injection, and suspicious process access behavior.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1038",
        name: "Execution Prevention",
        description:
          "Restrict unsigned DLL execution and monitor abnormal process spawning chains.",
        framework: "MITRE ATT&CK + NIST SP 800-167",
      },
    ],
  },

  // TA0005 — DEFENSE IMPAIRMENT
  {
    technique: "T1562.004",
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
        id: "M1037",
        name: "Filter Network Traffic",
        description:
          "Restrict unauthorized firewall rule changes. Monitor firewall configuration modifications centrally.",
        framework: "MITRE ATT&CK + NIST SP 800-41",
      },
    ],
  },

  {
    technique: "T1562.001",
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
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description:
          "Enable tamper protection on AV/EDR products and alert on security agent termination attempts.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1562.010",
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
        id: "M1041",
        name: "Encrypt Sensitive Information",
        description:
          "Disable legacy protocols and enforce modern TLS configurations across all systems.",
        framework: "MITRE ATT&CK + NIST SP 800-52r2",
      },
    ],
  },

  {
    technique: "T1211",
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
        id: "M1050",
        name: "Exploit Protection",
        description:
          "Enable exploit mitigation technologies such as ASLR, DEP, CFG, and EDR anti-tampering features.",
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
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description:
          "Enforce least privilege on critical system directories and monitor unauthorized ACL changes.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 AC-3",
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
        id: "M1035",
        name: "Limit Access to Resource Over Network",
        description:
          "Restrict cloud administrative access and continuously audit cloud infrastructure changes.",
        framework: "MITRE ATT&CK + CIS Cloud Benchmarks",
      },
    ],
  },

  {
    technique: "T1485",
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
        id: "M1026",
        name: "Privileged Account Management",
        description:
          "Restrict permissions for cloud tenant and subscription modifications. Require MFA and approval workflows.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 AC-6",
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
        id: "M1045",
        name: "Code Signing",
        description:
          "Require signed firmware and verified boot mechanisms to prevent unauthorized image modification.",
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
        id: "M1030",
        name: "Network Segmentation",
        description:
          "Prevent unauthorized bridging between segmented networks and monitor dual-homed systems.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 SC-7",
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
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description:
          "Restrict write access to LaunchAgents and LaunchDaemons directories on macOS systems.",
        framework: "MITRE ATT&CK",
      },
    ],
  },

  {
    technique: "T1562.003",
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
        id: "M1047",
        name: "Audit",
        description:
          "Forward logs to centralized SIEM and restrict local users from disabling shell history or logging.",
        framework: "MITRE ATT&CK + NIST SP 800-92",
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
        id: "M1026",
        name: "Privileged Account Management",
        description:
          "Restrict domain replication privileges and continuously monitor Active Directory replication behavior.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 AC-6",
      },
    ],
  },

  {
    technique: "T1562.009",
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
        id: "M1045",
        name: "Code Signing",
        description:
          "Enable Secure Boot and monitor unauthorized boot configuration changes.",
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
        id: "M1045",
        name: "Code Signing",
        description:
          "Validate digital signatures and revoke compromised certificates immediately.",
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
        id: "M1041",
        name: "Encrypt Sensitive Information",
        description:
          "Enforce strong cryptographic standards and disable insecure ciphers/protocols across all systems.",
        framework: "MITRE ATT&CK + NIST SP 800-52r2",
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
        description: "Enforce account lockout after failed attempts. Implement CAPTCHA on login. Aligns with OWASP A07:2021 and NIST SP 800-63B.",
        framework: "MITRE ATT&CK + OWASP A07 + NIST SP 800-63B",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description: "Require MFA on all accounts. Phishing-resistant MFA (FIDO2/WebAuthn) preferred per NIST SP 800-63B AAL2+.",
        framework: "MITRE ATT&CK + NIST SP 800-63B",
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
    technique: "T1110.001",
    name: "Brute Force: Password Guessing",
    tactic: "Credential Access",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["password-guessing", "dictionary-attack"])) s += 65;
      if (n.type === "ip" && n.abuse_score >= 50) s += 25;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["dictionary", "password-guess"])) r.push("IOC associated with dictionary/password guessing attacks");
      return r;
    },
    mitigations: [
      {
        id: "M1036",
        name: "Account Use Policies",
        description: "Enforce password complexity and lockout. Log and alert on multiple failed login attempts in SIEM. Aligns with OWASP A07.",
        framework: "MITRE ATT&CK + OWASP A07",
      },
    ],
  },
  {
    technique: "T1110.003",
    name: "Brute Force: Password Spraying",
    tactic: "Credential Access",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["password-spray", "spray"])) s += 70;
      if (n.abuse_score >= 50) s += 20;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["spray"])) r.push("IOC associated with password spraying campaign");
      return r;
    },
    mitigations: [
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description: "MFA prevents authentication success even when spraying yields a valid password. Deploy immediately on all externally accessible services. Aligns with NIST SP 800-63B.",
        framework: "MITRE ATT&CK + NIST SP 800-63B",
      },
    ],
  },
  {
    technique: "T1110.004",
    name: "Brute Force: Credential Stuffing",
    tactic: "Credential Access",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["credential-stuffing", "cred-stuffing"])) s += 70;
      if (n.abuse_score >= 40) s += 20;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["stuffing"])) r.push("IOC associated with credential stuffing using leaked databases");
      return r;
    },
    mitigations: [
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description: "MFA defeats credential stuffing even with valid username/password. Monitor for impossible-travel login patterns in SIEM.",
        framework: "MITRE ATT&CK + NIST SP 800-63B",
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
        id: "M1043",
        name: "Credential Access Protection",
        description: "Enable Windows Credential Guard. Restrict LSASS access. Monitor for LSASS memory reads via EDR. Aligns with NIST SP 800-53r5 IA-5.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 IA-5",
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
        description: "Set Secure and HttpOnly flags on session cookies. Implement short session timeouts and token rotation. Aligns with OWASP A07:2021.",
        framework: "MITRE ATT&CK + OWASP A07",
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
        description: "Use Managed Service Accounts (gMSA). Enforce AES-256 Kerberos encryption. Monitor for anomalous Kerberos ticket requests. Aligns with NIST SP 800-53r5 IA-5.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 IA-5",
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
          "Enforce TLS everywhere and disable insecure protocols susceptible to interception attacks.",
        framework: "MITRE ATT&CK + NIST SP 800-52r2",
      },
      {
        id: "M1032",
        name: "Multi-factor Authentication",
        description:
          "Use phishing-resistant MFA (FIDO2/WebAuthn) to reduce credential theft impact.",
        framework: "MITRE ATT&CK + NIST SP 800-63B",
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
        id: "M1043",
        name: "Credential Access Protection",
        description:
          "Enable Credential Guard and restrict access to authentication subsystems such as LSASS.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 IA-5",
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
          "Disable NTLM where possible and block outbound SMB traffic to untrusted hosts.",
        framework: "MITRE ATT&CK + Microsoft Security Baselines",
      },
    ],
  },

  {
    technique: "T1111",
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
          "Use strong token signing keys and rotate session tokens regularly. Enforce secure cookie settings.",
        framework: "MITRE ATT&CK + OWASP A07",
      },
    ],
  },

  {
    technique: "T1111.001",
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
        id: "M1032",
        name: "Multi-factor Authentication",
        description:
          "Deploy phishing-resistant MFA such as FIDO2/WebAuthn instead of OTP-based MFA.",
        framework: "MITRE ATT&CK + NIST SP 800-63B",
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
          "Enable number matching and geographic context in MFA prompts to prevent MFA fatigue attacks.",
        framework: "MITRE ATT&CK + Microsoft Security Guidance",
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
          "Use encrypted protocols such as HTTPS, SSH, and SMB signing to prevent credential interception.",
        framework: "MITRE ATT&CK + NIST SP 800-52r2",
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
          "Enable Credential Guard and monitor for unauthorized LSASS memory access.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 IA-5",
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
        id: "M1054",
        name: "Software Configuration",
        description:
          "Rotate API and OAuth tokens regularly. Limit token scope and expiration time.",
        framework: "MITRE ATT&CK + OWASP API Security",
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
        id: "M1026",
        name: "Privileged Account Management",
        description:
          "Restrict access to certificate authorities and monitor certificate issuance events.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 IA-5",
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
          "Continuously scan repositories and systems for exposed credentials and rotate compromised secrets immediately.",
        framework: "MITRE ATT&CK + OWASP Secrets Management",
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
        description: "Segment internal networks to limit lateral discovery. Use host-based firewalls to restrict unnecessary port access. Aligns with NIST SP 800-53r5 SC-7.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 SC-7",
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
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description: "Enforce least-privilege file permissions. Disable directory listing on web servers. Aligns with OWASP A01:2021 and NIST SP 800-53r5 AC-3.",
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
        id: "M1027",
        name: "Password Policies",
        description: "Restrict anonymous account enumeration and audit account discovery attempts. Aligns with NIST SP 800-53r5 AC-7.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 AC-7",
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
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description: "Monitor suspicious GUI/window enumeration behavior via EDR telemetry.",
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
        id: "M1054",
        name: "Software Configuration",
        description: "Restrict browser data access and monitor browser profile enumeration attempts.",
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
        id: "M1032",
        name: "Multi-factor Authentication",
        description: "Protect cloud administration accounts with MFA and monitor enumeration activity in cloud audit logs.",
        framework: "MITRE ATT&CK + NIST SP 800-63B",
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
        id: "M1026",
        name: "Privileged Account Management",
        description: "Restrict cloud dashboard access to approved admins and monitor abnormal login patterns.",
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
        id: "M1035",
        name: "Limit Access to Resource Over Network",
        description: "Restrict access to cloud APIs and monitor discovery commands in cloud logs.",
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
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description: "Restrict public cloud bucket access and audit storage enumeration activity.",
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
        id: "M1047",
        name: "Audit",
        description: "Enable Kubernetes and container audit logging. Restrict container runtime enumeration.",
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
        id: "M1049",
        name: "Antivirus/Antimalware",
        description: "Use behavioral EDR capable of detecting anti-debugging and evasion behavior.",
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
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description: "Monitor driver enumeration attempts and unauthorized kernel interactions.",
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
        id: "M1026",
        name: "Privileged Account Management",
        description: "Restrict AD enumeration privileges and monitor trust relationship queries.",
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
        id: "M1047",
        name: "Audit",
        description: "Monitor access to Group Policy Objects and restrict unauthorized AD queries.",
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
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description: "Restrict access to sensitive drives and monitor abnormal storage enumeration.",
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
        id: "M1047",
        name: "Audit",
        description: "Monitor suspicious access to security and event logs through SIEM correlation.",
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
        id: "M1030",
        name: "Network Segmentation",
        description: "Restrict SMB access and disable unnecessary file sharing across segments.",
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
        id: "M1036",
        name: "Account Use Policies",
        description: "Limit exposure of password policy information and monitor policy enumeration activity.",
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
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description: "Restrict unauthorized USB enumeration and monitor peripheral device interactions.",
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
        id: "M1026",
        name: "Privileged Account Management",
        description: "Restrict group enumeration permissions and monitor privileged group queries.",
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
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description: "Detect abnormal process enumeration activity through EDR telemetry.",
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
        id: "M1024",
        name: "Restrict Registry Permissions",
        description: "Restrict registry access and monitor suspicious registry enumeration.",
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
        id: "M1030",
        name: "Network Segmentation",
        description: "Restrict internal host enumeration through firewall segmentation and ACLs.",
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
        id: "M1047",
        name: "Audit",
        description: "Monitor inventory enumeration and software reconnaissance activity.",
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
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description: "Monitor suspicious system information enumeration commands.",
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
        id: "M1047",
        name: "Audit",
        description: "Monitor suspicious locale and geographic enumeration attempts.",
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
        id: "M1030",
        name: "Network Segmentation",
        description: "Limit visibility into internal network architecture and monitor configuration discovery activity.",
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
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description: "Monitor processes enumerating active network connections.",
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
        id: "M1026",
        name: "Privileged Account Management",
        description: "Restrict unnecessary account visibility and monitor user discovery commands.",
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
        id: "M1047",
        name: "Audit",
        description: "Monitor unauthorized service enumeration and service configuration access.",
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
        id: "M1047",
        name: "Audit",
        description: "Monitor suspicious system time queries and NTP enumeration behavior.",
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
        id: "M1049",
        name: "Antivirus/Antimalware",
        description: "Deploy advanced sandboxing and behavioral detection capable of identifying anti-VM techniques.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1497.001",
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
        id: "M1049",
        name: "Antivirus/Antimalware",
        description: "Monitor for virtualization detection behavior commonly used by malware to evade analysis.",
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
        description: "Restrict lateral movement protocols (RDP/SMB/WinRM) between workstations. Use PAM jump hosts. Aligns with NIST SP 800-53r5 AC-17.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 AC-17",
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
        description: "Use unique local admin passwords (LAPS). Implement Protected Users group. Aligns with NIST SP 800-53r5 IA-5.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 IA-5",
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
        id: "M1049",
        name: "Antivirus/Antimalware",
        description: "Scan internal email traffic. Alert on unusual internal email patterns (bulk send, attachment from non-standard senders).",
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
        description: "Patch SMB, RDP, VPN, and remote management services promptly. Prioritize critical CVEs affecting exposed services. Aligns with NIST SP 800-40r4.",
        framework: "MITRE ATT&CK + NIST SP 800-40r4",
      },
      {
        id: "M1030",
        name: "Network Segmentation",
        description: "Restrict east-west traffic between systems to limit lateral exploitation opportunities. Use internal firewalls and ACLs.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 SC-7",
      },
      {
        id: "M1035",
        name: "Limit Access to Resource Over Network",
        description: "Restrict administrative protocols (SMB/RDP/WinRM) to approved hosts only and require MFA for remote administration.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 AC-17",
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
        id: "M1038",
        name: "Execution Prevention",
        description: "Block unauthorized administrative tools such as PsExec and Impacket binaries via application allowlisting.",
        framework: "MITRE ATT&CK + NIST SP 800-167",
      },
      {
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description: "Restrict write access to administrative shares and monitor suspicious file copy activity between systems.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 AC-3",
      },
      {
        id: "M1047",
        name: "Audit",
        description: "Log SMB file transfers and remote execution events in SIEM to detect unauthorized tool propagation.",
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
        id: "M1032",
        name: "Multi-factor Authentication",
        description: "Require MFA re-authentication for privileged remote sessions and administrative access.",
        framework: "MITRE ATT&CK + NIST SP 800-63B",
      },
      {
        id: "M1026",
        name: "Privileged Account Management",
        description: "Restrict concurrent administrative sessions and enforce session timeout policies.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 AC-6",
      },
      {
        id: "M1047",
        name: "Audit",
        description: "Monitor abnormal session switching, tscon.exe usage, and remote session takeover events.",
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
        description: "Limit write permissions on shared drives and monitor unauthorized modifications to shared content.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 AC-3",
      },
      {
        id: "M1049",
        name: "Antivirus/Antimalware",
        description: "Continuously scan shared folders and network drives for malicious files and suspicious payloads.",
        framework: "MITRE ATT&CK + NIST SP 800-83",
      },
      {
        id: "M1038",
        name: "Execution Prevention",
        description: "Prevent execution of binaries and scripts directly from shared/network locations through application control policies.",
        framework: "MITRE ATT&CK + NIST SP 800-167",
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
        id: "M1057",
        name: "Data Loss Prevention",
        description: "Deploy DLP to detect unauthorized data archival and staging. Monitor for large compressed file creation. Aligns with NIST SP 800-53r5 SI-12.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 SI-12",
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
        id: "M1038",
        name: "Execution Prevention",
        description: "Block unauthorized remote access tools and spyware via EDR behavioral rules. Aligns with NIST SP 800-83.",
        framework: "MITRE ATT&CK + NIST SP 800-83",
      },
    ],
  },
  {
    technique: "T1056",
    name: "Input Capture (Keylogger)",
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
        id: "M1038",
        name: "Execution Prevention",
        description: "Block known keylogger hashes via EDR. Use behavioral monitoring for input hook APIs. Aligns with NIST SP 800-83.",
        framework: "MITRE ATT&CK + NIST SP 800-83",
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
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description: "Disable microphone access for non-essential applications. Monitor unauthorized microphone usage via EDR telemetry.",
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
        id: "M1057",
        name: "Data Loss Prevention",
        description: "Deploy DLP and UEBA to detect large-scale automated collection activity. Monitor abnormal file access patterns.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 SI-4",
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
        id: "M1054",
        name: "Software Configuration",
        description: "Enforce secure session handling, short-lived tokens, and browser isolation for privileged users. Monitor abnormal session reuse.",
        framework: "MITRE ATT&CK + OWASP A07",
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
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description: "Monitor processes accessing clipboard APIs abnormally. Block clipboard scraping malware through EDR behavioral rules.",
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
        id: "M1035",
        name: "Limit Access to Resource Over Network",
        description: "Restrict cloud storage access using least privilege IAM policies. Monitor abnormal bulk downloads from cloud repositories.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 AC-6",
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
        id: "M1026",
        name: "Privileged Account Management",
        description: "Restrict access to source code and configuration repositories. Require MFA and monitor repository cloning activity.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 AC-6",
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
        id: "M1057",
        name: "Data Loss Prevention",
        description: "Monitor sensitive document access and bulk export activities from enterprise repositories. Apply DLP controls.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 SI-12",
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
        description: "Monitor sensitive local file access and unauthorized collection behavior through EDR and DLP policies.",
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
        id: "M1030",
        name: "Network Segmentation",
        description: "Restrict SMB share access using least privilege. Audit access to sensitive network shares regularly.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 SC-7",
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
        id: "M1051",
        name: "Update Software",
        description: "Disable unauthorized USB storage devices. Monitor removable media access and file copy activities through endpoint controls.",
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
        id: "M1057",
        name: "Data Loss Prevention",
        description: "Detect temporary staging directories and large archive creation events. Alert on abnormal compression behavior.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 SI-12",
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
        id: "M1032",
        name: "Multi-factor Authentication",
        description: "Require MFA for all email access. Monitor mailbox export and forwarding rule creation activity.",
        framework: "MITRE ATT&CK + NIST SP 800-63B",
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
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description: "Disable webcam access for unauthorized applications. Monitor camera API usage using EDR telemetry.",
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
        description: "Implement DLP on egress points. Alert on large outbound data transfers. Aligns with NIST SP 800-53r5 SI-12.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 SI-12",
      },
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Block unauthorized outbound destinations. Use SSL/TLS inspection to detect encrypted exfiltration. Aligns with NIST SP 800-41.",
        framework: "MITRE ATT&CK + NIST SP 800-41",
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
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Detect DNS tunneling via payload analysis and query anomaly detection. Block high-entropy DNS subdomain queries. Aligns with NIST SP 800-81r2.",
        framework: "MITRE ATT&CK + NIST SP 800-81r2",
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
        id: "M1021",
        name: "Restrict Web-Based Content",
        description: "Block unapproved cloud storage services at proxy. Monitor for unusual uploads to GitHub/Pastebin/Discord. CASB solution recommended.",
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
        id: "M1057",
        name: "Data Loss Prevention",
        description: "Deploy DLP and UEBA solutions to detect recurring or automated outbound data transfers. Alert on repetitive bulk uploads.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 SI-12",
      },
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Restrict outbound traffic to approved destinations only. Monitor automated transfer tools and suspicious scheduled uploads.",
        framework: "MITRE ATT&CK + NIST SP 800-41",
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
        description: "Detect anomalous repeated small outbound transfers using NDR/IDS solutions. Correlate fragmented traffic patterns over time.",
        framework: "MITRE ATT&CK + NIST SP 800-94",
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
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Disable unused wireless interfaces such as Bluetooth and unauthorized Wi-Fi adapters. Monitor RF/network anomalies.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1042",
        name: "Disable or Remove Feature or Program",
        description: "Restrict removable wireless communication hardware on sensitive systems.",
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
        id: "M1051",
        name: "Update Software",
        description: "Disable unauthorized USB storage access using endpoint device control policies. Log and monitor removable media usage.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1057",
        name: "Data Loss Prevention",
        description: "Apply DLP rules to block copying sensitive data to removable media devices.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 SI-12",
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
        id: "M1018",
        name: "User Account Management",
        description: "Audit scheduled tasks and cron jobs regularly. Alert on unauthorized scheduled outbound transfer scripts.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 AU-6",
      },
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Monitor recurring outbound connections occurring at fixed intervals indicative of automated exfiltration.",
        framework: "MITRE ATT&CK + NIST SP 800-41",
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
        id: "M1021",
        name: "Restrict Web-Based Content",
        description: "Block unauthorized cloud storage platforms via proxy or CASB. Monitor uploads to external cloud accounts.",
        framework: "MITRE ATT&CK",
      },
      {
        id: "M1057",
        name: "Data Loss Prevention",
        description: "Use DLP/CASB solutions to inspect and prevent sensitive data uploads to external cloud services.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 SI-12",
      },
    ],
  },

  // TA0011 — COMMAND & CONTROL
  {
    technique: "T1071",
    name: "Application Layer Protocol (C2)",
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
        description: "Deploy IDS/IPS signatures for C2 communication patterns. Inspect HTTP/S, DNS, and other app-layer traffic. Aligns with NIST SP 800-94.",
        framework: "MITRE ATT&CK + NIST SP 800-94",
      },
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Block confirmed C2 IPs/domains at perimeter. Maintain dynamic blocklist from threat intel feeds. Aligns with NIST SP 800-41.",
        framework: "MITRE ATT&CK + NIST SP 800-41",
      },
    ],
  },
  {
    technique: "T1071.001",
    name: "Application Layer Protocol: Web Protocols (HTTP/S C2)",
    tactic: "Command and Control",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["http-c2", "https-c2", "web-c2", "cobalt-strike", "beacon"])) s += 65;
      if (n.type === "url" && hasTagPartial(n, ["c2", "beacon"])) s += 40;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["http-c2", "beacon", "cobalt-strike"])) r.push("IOC associated with HTTP/S-based C2 beaconing (e.g. Cobalt Strike)");
      return r;
    },
    mitigations: [
      {
        id: "M1021",
        name: "Restrict Web-Based Content",
        description: "Enforce web proxy with SSL inspection. Detect C2 beacon patterns via JA3/JA3S TLS fingerprinting and anomalous heartbeat intervals.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
  {
    technique: "T1071.004",
    name: "Application Layer Protocol: DNS (DNS C2)",
    tactic: "Command and Control",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["dns-c2", "dns-beacon", "dns-tunnel", "iodine", "dnscat"])) s += 65;
      if (n.type === "domain" && hasTagPartial(n, ["dns-c2", "tunnel"])) s += 40;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["dns-c2", "dns-tunnel", "dnscat"])) r.push("IOC linked to DNS-based C2 communication");
      return r;
    },
    mitigations: [
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Analyze DNS traffic for high-entropy subdomains. Block domains used for DNS C2. Deploy DNS RPZ. Aligns with NIST SP 800-81r2.",
        framework: "MITRE ATT&CK + NIST SP 800-81r2",
      },
    ],
  },
  {
    technique: "T1090",
    name: "Proxy",
    tactic: "Command and Control",
    score: (n) => {
      let s = 0;
      if (hasTag(n, ["proxy", "tor", "vpn-abuse", "bulletproof-proxy", "socks5"])) s += 60;
      if (n.type === "ip" && hasTagPartial(n, ["proxy", "tor", "vpn", "socks"])) s += 30;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["proxy", "tor", "socks"])) r.push("IOC is a known anonymizing proxy, Tor exit node, or SOCKS relay");
      return r;
    },
    mitigations: [
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Block known Tor exit nodes, anonymizing proxies, and residential proxy networks. Maintain up-to-date intelligence blocklists. Aligns with NIST SP 800-41.",
        framework: "MITRE ATT&CK + NIST SP 800-41",
      },
    ],
  },
  {
    technique: "T1568",
    name: "Dynamic Resolution (DGA / Fast-Flux)",
    tactic: "Command and Control",
    score: (n) => {
      let s = 0;
      if (n.type === "domain") s += 15;
      if (hasTag(n, ["dga", "fast-flux", "dynamic-dns", "domain-generation"])) s += 55;
      if (n.vt_score >= 3) s += 15;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (hasTagPartial(n, ["dga", "fast-flux", "domain-generation"])) r.push("IOC associated with DGA/fast-flux C2 evasion technique");
      if (n.type === "domain" && n.vt_score >= 3) r.push("Malicious domain with VT detections, consistent with C2 infrastructure");
      return r;
    },
    mitigations: [
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description: "Block domain at DNS resolver. Deploy DNS RPZ. Use ML-based DGA detection in DNS analytics. Aligns with NIST SP 800-81r2.",
        framework: "MITRE ATT&CK + NIST SP 800-81r2",
      },
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Null-route resolved IPs. Investigate all hosts that queried this domain. Aligns with NIST SP 800-61r2 Containment phase.",
        framework: "MITRE ATT&CK + NIST SP 800-61r2",
      },
    ],
  },
  {
    technique: "T1573",
    name: "Encrypted Channel (Encrypted C2)",
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
        description: "Deploy SSL/TLS inspection for outbound connections. Use JA3 fingerprinting to detect anomalous TLS handshakes used by C2 frameworks.",
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
        id: "M1034",
        name: "Limit Hardware Installation",
        description: "Restrict USB/removable media usage via endpoint policy. Monitor unauthorized removable device insertion events.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 MP-7",
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
        description: "Inspect outbound traffic for suspicious encoded payloads and anomalous Base64/XOR patterns in HTTP/DNS traffic.",
        framework: "MITRE ATT&CK + NIST SP 800-94",
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
        description: "Deploy deep packet inspection and anomaly detection to identify obfuscated or steganographic C2 traffic.",
        framework: "MITRE ATT&CK + NIST SP 800-94",
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
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Block DGA and fast-flux domains using DNS sinkholing and RPZ policies.",
        framework: "MITRE ATT&CK + NIST SP 800-81r2",
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
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Block all identified primary and secondary C2 endpoints. Correlate beaconing across multiple protocols.",
        framework: "MITRE ATT&CK + NIST SP 800-41",
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
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Monitor and restrict outbound traffic to suspicious CDN/reverse proxy infrastructure and anonymized hosting providers.",
        framework: "MITRE ATT&CK + NIST SP 800-41",
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
        id: "M1021",
        name: "Restrict Web-Based Content",
        description: "Restrict unauthorized downloads from external sources. Monitor PowerShell/curl/wget download activity.",
        framework: "MITRE ATT&CK + OWASP",
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
        description: "Correlate staged outbound traffic patterns and detect chained communication channels.",
        framework: "MITRE ATT&CK + NIST SP 800-94",
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
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Restrict ICMP and unauthorized raw socket traffic. Alert on anomalous non-standard protocol usage.",
        framework: "MITRE ATT&CK + NIST SP 800-41",
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
        id: "M1037",
        name: "Filter Network Traffic",
        description: "Restrict outbound traffic to approved ports only. Monitor uncommon outbound port activity.",
        framework: "MITRE ATT&CK + NIST SP 800-41",
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
        description: "Inspect traffic for tunneling signatures and block unauthorized encapsulated protocols.",
        framework: "MITRE ATT&CK + NIST SP 800-94",
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
        description: "Block known proxy/Tor/VPN infrastructure and monitor anonymized outbound traffic.",
        framework: "MITRE ATT&CK + NIST SP 800-41",
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
        description: "Restrict unauthorized remote access tools. Allow only approved RAT software through application control.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 CM-7",
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
        id: "M1021",
        name: "Restrict Web-Based Content",
        description: "Restrict access to unapproved web services and monitor outbound traffic to collaboration/chat platforms.",
        framework: "MITRE ATT&CK + OWASP",
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
        id: "M1053",
        name: "Data Backup",
        description: "Maintain offline immutable backups (3-2-1 strategy). Test restoration quarterly. Aligns with NIST SP 800-53r5 CP-9.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 CP-9",
      },
      {
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description: "On Windows 10, enable cloud-delivered protection and Attack Surface Reduction (ASR) rules to block the execution of files that resemble ransomware. In AWS environments, create an IAM policy to restrict or block the use of SSE-C on S3 buckets.",
        framework: "MITRE ATT&CK + NIST SP 800-83",
      },
      {
        id: "M1038",
        name: "Execution Prevention",
        description: "Block ransomware hash via EDR. Deploy canary files and shadow copy protection for behavioral ransomware detection. Aligns with NIST SP 800-83.",
        framework: "MITRE ATT&CK + NIST SP 800-83",
      },
      {
        id: "M1027",
        name: "Password Policies",
        description: "Ransomware operators often exploit weak credentials for initial access. Enforce strong password + MFA across all accounts. NIST SP 800-63B.",
        framework: "MITRE ATT&CK + NIST SP 800-63B",
      },
    ],
  },
  {
    technique: "T1485",
    name: "Data Destruction (Wiper)",
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
        description: "Maintain offline immutable backups. Implement network segmentation to limit wiper propagation. Aligns with NIST SP 800-53r5 CP-9.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 CP-9",
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
        description: "Block offending IP/range at perimeter immediately. Engage upstream ISP for traffic scrubbing during volumetric attacks. Aligns with NIST SP 800-61r2.",
        framework: "MITRE ATT&CK + NIST SP 800-61r2",
      },
      {
        id: "M1035",
        name: "Limit Access to Resource Over Network",
        description: "Rate-limit inbound connections. Use cloud DDoS scrubbing (Cloudflare Magic Transit, AWS Shield Advanced). Aligns with NIST SP 800-61r2.",
        framework: "MITRE ATT&CK + NIST SP 800-61r2",
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
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description: "Protect critical service binaries/configurations from modification. Monitor service status changes via SIEM. Aligns with NIST SP 800-53r5 CM-7.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 CM-7",
      },
    ],
  },
  {
    technique: "T1496",
    name: "Resource Hijacking (Cryptomining)",
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
        id: "M1038",
        name: "Execution Prevention",
        description: "Block known cryptominer hashes. Monitor for high CPU utilization anomalies. Aligns with NIST SP 800-83.",
        framework: "MITRE ATT&CK + NIST SP 800-83",
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
        id: "M1026",
        name: "Privileged Account Management",
        description: "Monitor privileged account modifications and unauthorized account disablement events. Implement rapid account recovery procedures.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 AC-2",
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
        description: "Use integrity monitoring, database auditing, and cryptographic validation to detect unauthorized data changes.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 SI-7",
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
        id: "M1022",
        name: "Restrict File and Directory Permissions",
        description: "Restrict write access to web content directories and monitor website file integrity for unauthorized modifications.",
        framework: "MITRE ATT&CK + OWASP A05",
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
        description: "Maintain offline backups and implement rapid restoration procedures for critical systems and boot records.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 CP-9",
      },
    ],
  },
  {
    technique: "T1580",
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
        description: "Enable anti-spam protections, mail throttling, and rate-limiting controls on email gateways.",
        framework: "MITRE ATT&CK + NIST SP 800-45",
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
        description: "Rate-limit requests and monitor for resource exhaustion patterns targeting endpoints or services.",
        framework: "MITRE ATT&CK + NIST SP 800-61r2",
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
        id: "M1032",
        name: "Multi-factor Authentication",
        description: "Enforce MFA and transaction verification for financial systems and payment workflows.",
        framework: "MITRE ATT&CK + NIST SP 800-63B",
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
        id: "M1051",
        name: "Update Software",
        description: "Enable Secure Boot, TPM validation, and firmware integrity verification. Keep firmware updated from trusted vendors.",
        framework: "MITRE ATT&CK + NIST SP 800-147",
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
        description: "Use offline immutable backups and monitor for deletion of backup snapshots or shadow copies.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 CP-9",
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
        id: "M1040",
        name: "Behavior Prevention on Endpoint",
        description: "Monitor and restrict unauthorized shutdown/reboot commands through EDR and privileged access controls.",
        framework: "MITRE ATT&CK + NIST SP 800-83",
      },
    ],
  },

  // GENERIC HIGH-DETECTION FALLBACK
  {
    technique: "T1203",
    name: "Exploitation for Client Execution",
    tactic: "Execution",
    score: (n) => {
      let s = 0;
      if (n.vt_score >= 15 && n.tags.length === 0) s += 50;
      if (n.vt_score >= 10 && hasTagPartial(n, ["exploit", "vuln"])) s += 40;
      return s;
    },
    reasons: (n) => {
      const r: string[] = [];
      if (n.vt_score >= 10) r.push(`High VirusTotal detection rate (${n.vt_score} vendors flagged this IOC)`);
      return r;
    },
    mitigations: [
      {
        id: "M1050",
        name: "Exploit Protection",
        description: "Enable OS exploit mitigations (ASLR, DEP, CFG). Deploy behavioral EDR. Aligns with NIST SP 800-53r5 SI-16.",
        framework: "MITRE ATT&CK + NIST SP 800-53r5 SI-16",
      },
      {
        id: "M1051",
        name: "Update Software",
        description: "Apply available patches by CVSS priority. Aligns with NIST SP 800-40r4.",
        framework: "MITRE ATT&CK + NIST SP 800-40r4",
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