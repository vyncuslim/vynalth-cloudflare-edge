import test from "node:test";
import assert from "node:assert/strict";
import edge from "./index.js";

const IP = "60.49.64.83";

function req(host = "vyncuslim.com", path = "/") {
  return new Request("https://" + host + path, {
    headers: { "CF-Connecting-IP": IP }
  });
}

async function withOrigin(fn) {
  const old = globalThis.fetch;
  let count = 0;
  globalThis.fetch = async () => {
    count++;
    return new Response("origin", {
      status: 200, headers: { "x-vercel-id": "test" }
    });
  };
  try { return await fn(() => count); }
  finally { globalThis.fetch = old; }
}

function binding({ version = "internal-204-v1", block = false } = {}) {
  const history = [];
  return {
    history,
    async fetch(r) {
      const url = new URL(r.url);
      history.push({
        path: url.pathname, host: url.hostname,
        clientIp: r.headers.get("X-Vynalth-Policy-Client-IP"),
        query: url.search
      });
      if (url.pathname === "/health") {
        return Response.json({ policyProtocol: version, kvBound: true });
      }
      assert.equal(r.headers.get("X-Vynalth-Policy-Client-IP"), IP);
      if (block) return new Response("denied", {
        status: 403,
        headers: { "X-School-Policy": "blocked" }
      });
      return new Response(null, { status: 204 });
    }
  };
}

test("default disabled: existing origin and headers remain", async () => {
  await withOrigin(async count => {
    const s = binding({ block: true });
    const response = await edge.fetch(req(), {
      SCHOOL_POLICY_ENABLED: "false", SCHOOL_POLICY: s
    });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("x-vynalth-zone"), "vyncuslim.com");
    assert.equal(count(), 1);
    assert.equal(s.history.length, 0);
  });
});

test("legacy policy health response cannot trigger recursion", async () => {
  await withOrigin(async count => {
    const s = binding({ version: undefined, block: true });
    const response = await edge.fetch(req(), {
      SCHOOL_POLICY_ENABLED: "true", SCHOOL_POLICY: s
    });
    assert.equal(response.status, 200);
    assert.equal(count(), 1);
    assert.equal(s.history.length, 1);
    assert.equal(s.history[0].path, "/health");
  });
});

test("enabled compatible policy blocks only tagged 403", async () => {
  await withOrigin(async count => {
    const s = binding({ block: true });
    const response = await edge.fetch(req(), {
      SCHOOL_POLICY_ENABLED: "true", SCHOOL_POLICY: s
    });
    assert.equal(response.status, 403);
    assert.equal(response.headers.get("x-school-policy"), "blocked");
    assert.equal(count(), 0);
    assert.deepEqual(s.history.map(x => x.path), ["/health", "/"]);
  });
});

test("enabled policy allows each of seven website zones", async () => {
  await withOrigin(async count => {
    const s = binding();
    const zones = [
      "vynalthai.com", "vynalthai.si", "vyncuslim.com",
      "vyncuslim.si", "sleepsomno.com", "powiismunc.com",
      "vitamindai.online"
    ];
    for (const host of zones) {
      const response = await edge.fetch(req(host), {
        SCHOOL_POLICY_ENABLED: "true", SCHOOL_POLICY: s
      });
      assert.equal(response.status, 200);
      assert.equal(response.headers.get("x-vynalth-zone"), host);
    }
    assert.equal(count(), zones.length);
    assert.equal(s.history.length, zones.length * 2);
  });
});

test("validation endpoints never call policy Worker", async () => {
  await withOrigin(async count => {
    const s = binding({ block: true });
    const response = await edge.fetch(
      req("vyncuslim.com", "/.well-known/acme-challenge/cert"),
      { SCHOOL_POLICY_ENABLED: "true", SCHOOL_POLICY: s }
    );
    assert.equal(response.status, 200);
    assert.equal(count(), 1);
    assert.equal(s.history.length, 0);
  });
});

test("signed campus beacon remains separate from school policy", async () => {
  const s = binding({ block: true });
  const response = await edge.fetch(
    new Request("https://vynalthai.com/__shield/campus-beacon", {
      method: "POST", headers: { "CF-Connecting-IP": IP }
    }),
    { SCHOOL_POLICY_ENABLED: "true", SCHOOL_POLICY: s }
  );
  assert.equal(response.status, 503); // beacon disabled without signing/KV secrets
  assert.equal(s.history.length, 0);
});

test("unavailable service fails open without changing origin", async () => {
  await withOrigin(async count => {
    const s = { async fetch() { throw new Error("binding unavailable"); } };
    const response = await edge.fetch(req(), {
      SCHOOL_POLICY_ENABLED: "true", SCHOOL_POLICY: s
    });
    assert.equal(response.status, 200);
    assert.equal(count(), 1);
  });
});

test("policy requests never forward browser query or cookie", async () => {
  await withOrigin(async () => {
    const s = binding();
    const request = new Request("https://vyncuslim.com/?token=private", {
      headers: {
        "CF-Connecting-IP": IP,
        Cookie: "privateSession=secret"
      }
    });
    const response = await edge.fetch(request, {
      SCHOOL_POLICY_ENABLED: "true", SCHOOL_POLICY: s
    });
    assert.equal(response.status, 200);
    for (const call of s.history) assert.equal(call.query, "");
  });
});
