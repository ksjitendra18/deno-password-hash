import { Hono } from "https://deno.land/x/hono@v3.7.0-rc.1/mod.ts";
import {
  hash as hashPromise,
  hashSync,
  compare as comparePromise,
  compareSync,
  genSaltSync,
} from "https://deno.land/x/bcrypt/mod.ts";

const app = new Hono();

const isRunningInDenoDeploy = (globalThis as any).Worker === undefined;

const hash: typeof hashPromise = isRunningInDenoDeploy
  ? (plaintext: string, salt: string | undefined = undefined) =>
      new Promise((res) => res(hashSync(plaintext, salt)))
  : hashPromise;

const compare: typeof comparePromise = isRunningInDenoDeploy
  ? (plaintext: string, hash: string) =>
      new Promise((res) => res(compareSync(plaintext, hash)))
  : comparePromise;

app.post("/password/hash", async (c) => {
  const { password } = await c.req.json();

  try {
    const salt = await genSaltSync(8);
    const hashedPassword = await hash(password, salt);
    return c.json({ success: true, data: { hashedPassword: hashedPassword } });
  } catch (e) {
    console.log("error", e);
    return c.json({ success: false, data: null, error: e });
  }
});

app.post("/password/verify", async (c) => {
  const { password, hashedPassword } = await c.req.json();

  try {
    const verifyPassword = await compare(password, hashedPassword);
    return c.json({ success: true, data: { verifyPassword } });
  } catch (e) {
    console.log("error", e);
    return c.json({ success: false, data: null, error: e });
  }
});

Deno.serve(app.fetch);
