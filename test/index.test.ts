import { describe, expect, it } from "vitest";
import { whoisToRdap } from "../src/index.js";

describe("whoisToRdap", () => {
  it("returns a minimal RDAP domain object", () => {
    const result = whoisToRdap("", { domain: "example.com" });
    expect(result.objectClassName).toBe("domain");
    expect(result.ldhName).toBe("example.com");
    expect(result.rdapConformance).toEqual(["rdap_level_0"]);
  });

  it("omits rdapConformance when disabled", () => {
    const result = whoisToRdap("", { domain: "example.com", includeConformance: false });
    expect(result.rdapConformance).toBeUndefined();
  });
});
