// Deliberately vulnerable Express + TypeScript fixture for Plan F multilang
// coverage tests. The `/search` route reads `req.query.q` (user-controlled)
// and echoes it back via `res.send` without any HTML escaping — an
// intentional reflected-XSS sink (CWE-79). Static_hunter / eslint / semgrep
// should flag the source -> sink dataflow.

import express, { Request, Response } from "express";

const app = express();

app.get("/search", (req: Request, res: Response) => {
  // DELIBERATE XSS SINK (CWE-79): user-controlled `req.query.q` is
  // interpolated directly into an HTML response without escaping.
  const q = String(req.query.q ?? "");
  res.send(`<html><body><h1>Results for: ${q}</h1></body></html>`);
});

const port = Number(process.env.PORT ?? 3000);
app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`listening on ${port}`);
});
