import test from "node:test";
import assert from "node:assert/strict";
import edge from "../src/index.js";

// Existing edge behavior is tested with a stub origin and stub Service Binding.
function request(hostname = "vyncuslim.com", path = "/") {
  return new Request("https://" + hostname + path, {
    headers: { "CF-Connecting-IP": "60.49.64.83" }
  });
}

async function withOrigin(run) {
  const original = globalThis.fetch;
  let count = 0;
  globalThis.fetch = async () => {
    count++;
    return new Response("origin-ok", {
      status: 200, headers: { "x-vercel-id": "test" }
    });
  };
  try { return await run(() => count); }
  finally { globalThis.fetch = original; }
}

test("policy allow 204 preserves original homepage and headers", async () => {
  await withOrigin(async getCalls => {
    let called = false;
    const env = {
      SCHOOL_POLICY: {
        async fetch(policyReq) {
          called = true;
          assert.equal(policyReq.headers.get("X-Vynalth-Policy-Client-IP"), "60.49.64.83");
          assert.equal(new URL(policyReq.url).hostname, "vyncuslim.com");
          return new Response(null, { status: 204 });
        }
      }
    };
    const response = await edge.fetch(request(), env, {});
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("x-vynalth-zone"), "vyncuslim.com");
    assert.equal(getCalls(), 1);
    assert.equal(called, true);
  });
});

test("policy 403 tagged as blocked prevents origin fetch", async () => {
  await withOrigin(async getCalls => {
    const env = {
      SCHOOL_POLICY: { async fetch() {
        return new Response("blocked", {
          status: 403, headers: { "X-School-Policy": "blocked" }
        });
      }}
    };
    const response = await edge.fetch(request(), env, {});
    assert.equal(response.status, 403);
    assert.equal(response.headers.get("x-school-policy"), "blocked");
    assert.equal(getCalls(), 0);
  });
});

test("untagged 403 cannot accidentally block a website", async () => {
  await withOrigin(async getCalls => {
    const env = { SCHOOL_POLICY: { async fetch() {
      return new Response("unrelated error", { status: 403 });
    }}};
    const response = await edge.fetch(request(), env, {});
    assert.equal(response.status, 200);
    assert.equal(getCalls(), 1);
  });
});

test("missing or failing service binding fails open", async () => {
  await withOrigin(async getCalls => {
    const first = await edge.fetch(request(), {}, {});
    const second = await edge.fetch(request(), {
      SCHOOL_POLICY: { async fetch() { throw new Error("temporary outage"); } }
    }, {});
    assert.equal(first.status, 200);
    assert.equal(second.status, 200);
    assert.equal(getCalls(), 2);
  });
});

test("two new SI zones are recognized and routed through policy", async () => {
  await withOrigin(async getCalls => {
    const seen = [];
    const env = { SCHOOL_POLICY: { async fetch(req) {
      seen.push(new URL(req.url).hostname);
      return new Response(null, { status: 204 });
    }}};
    for (const host of ["vynalthai.si", "www.vyncuslim.si"]) {
      const response = await edge.fetch(request(host), env, {});
      assert.equal(response.status, 200);
    }
    assert.deepEqual(seen, ["vynalthai.si", "www.vyncuslim.si"]);
    assert.equal(getCalls(), 2);
  });
});

test("sensitive query strings are not forwarded to policy Worker", async () => {
  await withOrigin(async () => {
    let secretForwarded = false;
    const env = { SCHOOL_POLICY: { async fetch(req) {
      secretForwarded = req.url.includes("secret-token");
      return new Response(null, { status: 204 });
    }}};
    const response = await edge.fetch(request("vyncuslim.com", "/?token=secret-token"), env, {});
    assert.equal(response.status, 200);
    assert.equal(secretForwarded, false);
  });
});

test("ACME validation requests bypass policy to preserve certificates", async () => {
  await withOrigin(async getCalls => {
    const env = { SCHOOL_POLICY: { async fetch() {
      throw new Error("policy should not see ACME challenge");
    }}};
    const response = await edge.fetch(request("vynalthai.com", "/.well-known/acme-challenge/test"), env, {});
    assert.equal(response.status, 200);
    assert.equal(getCalls(), 1);
  });
});
