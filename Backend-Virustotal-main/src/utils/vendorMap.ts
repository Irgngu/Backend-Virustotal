export type VendorMapItem = {
  keyword: string;
  confidence: number;
  category: string;
};

export const vendorMap: Record<string, VendorMapItem> = {
  "fortinet fortigate": {
    keyword: "FortiOS",
    confidence: 98,
    category: "Firewall",
  },

  "fortinet ssl vpn": {
    keyword: "FortiOS SSL VPN",
    confidence: 97,
    category: "VPN",
  },

  mikrotik: {
    keyword: "RouterOS",
    confidence: 96,
    category: "Router",
  },

  "palo alto": {
    keyword: "PAN-OS",
    confidence: 96,
    category: "Firewall",
  },

  "citrix netscaler": {
    keyword: "Citrix ADC",
    confidence: 95,
    category: "ADC",
  },

  apache: {
    keyword: "Apache HTTP Server",
    confidence: 95,
    category: "Web Server",
  },

  nginx: {
    keyword: "nginx",
    confidence: 95,
    category: "Web Server",
  },

  exchange: {
    keyword: "Microsoft Exchange Server",
    confidence: 97,
    category: "Mail Server",
  },

  wordpress: {
    keyword: "WordPress",
    confidence: 98,
    category: "CMS",
  },
};
export function getProductInfo(input: string) {
  const lower = input.toLowerCase();

  for (const key in vendorMap) {
    if (lower.includes(key)) {
      return vendorMap[key];
    }
  }

  return {
    keyword: input,
    confidence: 50,
    category: "Unknown",
  };
}
