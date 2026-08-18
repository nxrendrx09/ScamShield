"use client";

import { ChangeEvent, useEffect, useState } from "react";

type Mode = "link" | "message" | "qr";
type Finding = { title: string; detail: string; weight: number };
type Scan = { id: string; mode: Mode; target: string; score: number; level: "Low risk" | "Suspicious" | "High risk"; findings: Finding[] };

const shorteners = ["bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy", "is.gd"];
const suspiciousWords = ["verify", "kyc", "reward", "prize", "urgent", "suspended", "refund", "claim", "lottery", "free-gift"];
const brands = ["paytm", "phonepe", "googlepay", "amazon", "flipkart", "sbi", "hdfc", "icici", "instagram", "whatsapp"];

const levelFor = (score: number): Scan["level"] => score >= 65 ? "High risk" : score >= 30 ? "Suspicious" : "Low risk";
const scanId = () => `${Date.now()}-${Math.random().toString(36).slice(2)}`;

function linkScan(raw: string): Scan {
  const value = raw.trim();
  const findings: Finding[] = [];
  let url: URL | null = null;
  try { url = new URL(/^https?:\/\//i.test(value) ? value : `https://${value}`); }
  catch { findings.push({ title: "Invalid or disguised address", detail: "This could not be parsed as a normal web address.", weight: 55 }); }
  if (url) {
    const host = url.hostname.toLowerCase();
    const full = url.href.toLowerCase();
    if (url.protocol !== "https:") findings.push({ title: "No HTTPS protection", detail: "Information sent to this page may not be encrypted.", weight: 18 });
    if (url.username || value.includes("@")) findings.push({ title: "Misleading @ symbol", detail: "The beginning of this address may hide the real destination.", weight: 32 });
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) findings.push({ title: "Raw IP address", detail: "Legitimate services normally use a recognisable domain.", weight: 24 });
    if (host.includes("xn--")) findings.push({ title: "Lookalike characters", detail: "Punycode can imitate familiar brand names.", weight: 25 });
    if (shorteners.some(d => host === d || host.endsWith(`.${d}`))) findings.push({ title: "Shortened destination", detail: "The final website is hidden until the link is opened.", weight: 18 });
    if (host.split(".").length > 4) findings.push({ title: "Excessive subdomains", detail: "A long domain chain can make a fake address appear trustworthy.", weight: 16 });
    if (value.length > 120) findings.push({ title: "Unusually long link", detail: "Long links can conceal suspicious parameters.", weight: 12 });
    if (/%[0-9a-f]{2}/i.test(value)) findings.push({ title: "Encoded characters", detail: "Parts of this destination are obscured.", weight: 13 });
    const terms = suspiciousWords.filter(word => full.includes(word));
    if (terms.length) findings.push({ title: "Pressure or reward wording", detail: `Detected: ${terms.slice(0, 4).join(", ")}.`, weight: Math.min(28, 10 + terms.length * 5) });
    const matches = brands.filter(brand => host.includes(brand));
    if (matches.length && !matches.some(brand => host === `${brand}.com` || host.endsWith(`.${brand}.com`))) findings.push({ title: "Possible brand impersonation", detail: "A familiar brand name appears inside an unfamiliar domain.", weight: 30 });
  }
  const score = Math.min(100, findings.reduce((sum, item) => sum + item.weight, 0));
  return { id: scanId(), mode: "link", target: value, score, level: levelFor(score), findings };
}

function messageScan(raw: string): Scan {
  const value = raw.trim();
  const lower = value.toLowerCase();
  const findings: Finding[] = [];
  const tests = [
    ["Urgency or threat", ["urgent", "immediately", "blocked", "suspended", "last warning"], 24, "Scammers create panic so people act without checking."],
    ["Sensitive information request", ["otp", "pin", "password", "cvv", "account number", "aadhaar"], 34, "Never share banking or authentication details in a message."],
    ["Unexpected reward", ["won", "lottery", "cashback", "reward", "prize", "refund", "free gift"], 25, "Unexpected rewards are a common fraud lure."],
    ["Payment pressure", ["pay now", "transfer", "upi", "processing fee", "advance payment"], 27, "Verify payment requests using an official number or app."],
    ["Remote access request", ["anydesk", "teamviewer", "screen share", "remote access"], 38, "Remote-control software can give a stranger access to your device."]
  ] as const;
  tests.forEach(([title, words, weight, detail]) => {
    const hits = words.filter(word => lower.includes(word));
    if (hits.length) findings.push({ title, detail: `${detail} Detected: ${hits.slice(0, 3).join(", ")}.`, weight });
  });
  if (/https?:\/\/|\bwww\.|\b[a-z0-9-]+\.(com|in|net|org|ly)\b/i.test(value)) findings.push({ title: "Contains a clickable link", detail: "Inspect its destination separately before opening it.", weight: 12 });
  const score = Math.min(100, findings.reduce((sum, item) => sum + item.weight, 0));
  return { id: scanId(), mode: "message", target: value.slice(0, 90), score, level: levelFor(score), findings };
}

export default function Home() {
  const [mode, setMode] = useState<Mode>("link");
  const [input, setInput] = useState("");
  const [result, setResult] = useState<Scan | null>(null);
  const [history, setHistory] = useState<Scan[]>([]);
  const [qrStatus, setQrStatus] = useState("");
  useEffect(() => { try { setHistory(JSON.parse(localStorage.getItem("scamshield-history") || "[]")); } catch { setHistory([]); } }, []);
  function save(next: Scan) { const updated = [next, ...history].slice(0, 6); setResult(next); setHistory(updated); localStorage.setItem("scamshield-history", JSON.stringify(updated)); }
  function scan() { if (input.trim()) save(mode === "message" ? messageScan(input) : linkScan(input)); }
  function switchMode(next: Mode) { setMode(next); setResult(null); setQrStatus(""); setInput(""); }
  async function readQr(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]; if (!file) return; setQrStatus("Reading QR code…");
    try {
      const Detector = (window as unknown as { BarcodeDetector?: new (o: { formats: string[] }) => { detect(i: ImageBitmap): Promise<{ rawValue: string }[]> } }).BarcodeDetector;
      if (!Detector) throw new Error();
      const codes = await new Detector({ formats: ["qr_code"] }).detect(await createImageBitmap(file));
      if (!codes[0]?.rawValue) throw new Error();
      setInput(codes[0].rawValue); setQrStatus(`Found: ${codes[0].rawValue}`);
      const next = linkScan(codes[0].rawValue); next.mode = "qr"; save(next);
    } catch { setQrStatus("No clear QR code was found. Paste its destination in the Link tab instead."); }
  }

  return <main>
    <header className="main-header" id="top"><div className="shell header-inner">
      <a className="brand" href="#top" aria-label="ScamShield home"><i>✓</i><span>ScamShield<small>Digital safety checker</small></span></a>
      <nav aria-label="Primary navigation"><a href="#scanner">Check content</a><a href="#how">How it works</a><a href="#history">Recent checks</a></nav>
      <span className="privacy-pill"><i /> Your analysis stays private</span>
    </div></header>

    <section className="hero" id="scanner"><div className="shell hero-grid">
      <div className="hero-copy"><span className="eyebrow">SAFER DIGITAL DECISIONS</span><h1>Pause. Check.<br/><em>Stay protected.</em></h1><p>A simple safety check for suspicious links, messages and QR codes. Understand every warning before you click, reply or pay.</p><div className="trust-chips"><span>✓ No sign-up</span><span>✓ Instant results</span><span>✓ Clear explanations</span></div></div>
      <div className="scanner-card">
        <div className="scanner-heading"><div><span>SCAMSHIELD CHECK</span><h2>What would you like to inspect?</h2></div><i>Private</i></div>
        <div className="tabs" role="tablist" aria-label="Choose what to scan">
          <button role="tab" aria-selected={mode === "link"} className={mode === "link" ? "active" : ""} onClick={() => switchMode("link")}><b>↗</b> Link</button>
          <button role="tab" aria-selected={mode === "message"} className={mode === "message" ? "active" : ""} onClick={() => switchMode("message")}><b>✉</b> Message</button>
          <button role="tab" aria-selected={mode === "qr"} className={mode === "qr" ? "active" : ""} onClick={() => switchMode("qr")}><b>▦</b> QR code</button>
        </div>
        {mode === "qr" ? <div className="qr-box"><b>▦</b><h3>Upload a QR-code image</h3><p>We reveal and inspect its destination before you open it.</p><label>Choose image<input type="file" accept="image/*" onChange={readQr} /></label>{qrStatus && <small>{qrStatus}</small>}</div> :
          <div className="input-box"><label htmlFor="scan-input">{mode === "link" ? "Paste the web address below" : "Paste the complete suspicious message"}</label>{mode === "message" ? <textarea id="scan-input" value={input} onChange={e => setInput(e.target.value)} placeholder="Paste an SMS, WhatsApp message or email…" /> : <input id="scan-input" value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === "Enter" && scan()} placeholder="https://example.com/suspicious-link" />}<button className="scan-button" disabled={!input.trim()} onClick={scan}>Scan safely <span>→</span></button><small>Want to test it? <button onClick={() => setInput(mode === "message" ? "URGENT: Your KYC is suspended. Share OTP and pay processing fee now." : "http://paytm-urgent-reward.example/verify-account")}>Use a suspicious example</button></small></div>}
        <div className="local-note"><i>✓</i><span><b>Local privacy mode</b>Your content is analysed on this device and is not uploaded.</span></div>
      </div>
    </div></section>

    {result && <div className="shell result-wrap"><Result result={result} /></div>}
    <section className="safety-bar"><div className="shell"><b>Never share an OTP, UPI PIN, CVV or password.</b><span>Legitimate organisations will not ask for these details by message or phone.</span></div></section>

    <section className="how shell" id="how"><header><span className="eyebrow">HOW IT WORKS</span><h2>Clear evidence, not confusing jargon.</h2><p>ScamShield helps you slow down and make a safer decision in three simple steps.</p></header><div className="steps">
      <article><span>01</span><i>⌁</i><h3>Inspect</h3><p>We check for disguised addresses, pressure tactics, impersonation and common scam patterns.</p></article>
      <article><span>02</span><i>◎</i><h3>Understand</h3><p>Every detected warning includes a plain-language explanation of why it matters.</p></article>
      <article><span>03</span><i>✓</i><h3>Decide safely</h3><p>Receive practical next steps without opening or interacting with suspicious content.</p></article>
    </div></section>

    <section className="history-section" id="history"><div className="shell history"><header><div><span className="eyebrow">RECENT CHECKS</span><h2>Your private scan history</h2><p>Stored only in this browser on your device.</p></div>{history.length > 0 && <button onClick={() => { setHistory([]); localStorage.removeItem("scamshield-history"); }}>Clear history</button>}</header>{!history.length ? <div className="empty"><i>◷</i><b>No checks yet</b><span>Your recent link, message and QR checks will appear here.</span></div> : <div className="history-list">{history.map(item => <button key={item.id} onClick={() => { setResult(item); document.getElementById("scanner")?.scrollIntoView(); }}><i className={item.level.replace(" ", "-").toLowerCase()} /><span>{item.target}</span><small>{item.mode}</small><b>{item.score}/100</b></button>)}</div>}</div></section>
    <footer><div className="shell footer-inner"><a className="brand footer-brand" href="#top"><i>✓</i><span>ScamShield<small>Digital safety checker</small></span></a><p>Independent educational cybersecurity project. Risk guidance is informational and cannot guarantee safety.</p><span>Think before you click.</span></div></footer>
  </main>;
}

function Result({ result }: { result: Scan }) {
  const state = result.level.replace(" ", "-").toLowerCase();
  return <section className={`result ${state}`} aria-live="polite"><div className="summary"><div className="ring" style={{ "--score": `${result.score * 3.6}deg` } as React.CSSProperties}><div><strong>{result.score}</strong><small>/100</small></div></div><div><span>SCAMSHIELD ASSESSMENT</span><h2>{result.level}</h2><p>{result.level === "Low risk" ? "No strong warning signs were found, but always verify unexpected requests." : result.level === "Suspicious" ? "Some warning signs need your attention before you continue." : "Multiple strong scam indicators were detected. Do not open or respond."}</p></div></div><div className="findings"><h3>{result.findings.length ? `${result.findings.length} warning sign${result.findings.length > 1 ? "s" : ""} found` : "No obvious warning signs found"}</h3>{result.findings.length ? result.findings.map((item, i) => <article key={i}><b>!</b><div><strong>{item.title}</strong><p>{item.detail}</p></div></article>) : <article className="clean"><b>✓</b><div><strong>Basic checks passed</strong><p>This does not guarantee safety. Verify the sender before sharing money or personal details.</p></div></article>}</div><aside><i>✓</i><div><strong>Safest next step</strong><p>Open the organisation’s official app or type its known website yourself. Never share an OTP, PIN, password or CVV.</p></div></aside></section>;
}
