import { useEffect } from "react";

// SAIF scientific poster (ملصق علمي) — reachable at /poster.
//
// HOW TO FILL IT: edit the `C` object below. Text is Arabic (RTL); technical
// terms and numbers stay LTR. Everything you'd change lives in `C` — the JSX
// underneath just lays it out. Print / export to PDF with the button top-left
// (or Cmd/Ctrl+P → "Save as PDF"). Page size is set for A1 portrait in the
// print stylesheet at the bottom of this file; change `size:` there for A0/A2.

const C = {
  // ── Header ────────────────────────────────────────────────────────────
  title: "حَكَم",
  titleLatin: "Hakam",
  subtitle: "جدار حماية سيبراني  في عمق النواة (eBPF) ",
  chips: ["XDP", "BPF-LSM",  "eBPF", "Rust"],

  author: "عمر زيد الزهراني",
  org: "تخصص علوم حاسب — جامعة أم القرى",
  event: "مسابقة سيف (SAIF)",

  // ── Sections (edit freely; each is a titled card) ──────────────────────
  intro: {
    title: "المقدمة والمشكلة",
    bullets: [
      "تستهلك المنشآت اليوم موارد هائلة لبناء بنيات تحتية معقدة (Clusters) لتحقيق الأمان بناءً على مبدأ «افتراض الاختراق».",
      "تأتي هذه الحماية على حساب سرعة الأداء وسلاسة العمل، حيث تعاني الأنظمة من البطء بسبب تفكيك وفحص كل حزمة بيانات في مساحة المستخدم.",
      "الخوادم المفردة والأجهزة الطرفية تعجز عن تحمل تكلفة وتعقيد هذه الحلول، مما يتركها عرضة للتهديدات أو بضوابط أمنية ضعيفة.",
    ],
  },
  objective: {
    title: "الهدف والحل المبتكر",
    bullets: [
      "«حَكَم» يقلب المعادلة: جدار حماية يعمل في أعمق نقطة بالنظام (Kernel) بتقنية eBPF، ليوفر أقصى درجات الحماية دون استنزاف موارد الخادم.",
      "تقديم المنظومة بلغة Rust (صفر تعقيد تشغيلي)، يمكن نشره في دقائق على أي نظام Linux (5.15 فأحدث).",
    ],
  },
  // The three kernel enforcement points — the heart of the poster.
  layers: {
    title: "المعمارية — ثلاث نقاط إنفاذ أمنية صارمة في النواة",
    items: [
      {
        tag: "عند السلك · XDP",
        text: "يُسقط برنامج XDP حركة المرور المعادية فور وصولها لكرت الشبكة وقبل تخصيص أي ذاكرة (sk_buff)، مما يوقف الاستنزاف المالي السحابي.",
      },
      {
        tag: "عند محاوله الاتصال بالنظام · BPF-LSM",
        text: "خطّاف socket_connect يرفض الاتصالات الخارجية المخالفة   — قنوات الاتصال العكسية (Reverse Shells) تُقتل قبل ولادة أي حزمة.",
      },
      {
        tag: "عند العملية · Tracepoint",
        text: "نقطة التتبّع sys_enter_connect تربط كل عملية حظر بالجهة التي أنشأتها (PID والاسم)، مما يمنح رؤية دقيقة للتهديدات الداخلية.",
      },
    ],
    note: "يوجد محرك يطابق 202 توقيع لـ 13 عائلة هجومية ويتم رفضهم ويحدث قائمه الحظر فوريًا.",
  },
  // ── Results — real, kernel-measured numbers (already correct) ───────────
  results: {
    title: "النتائج ومؤشرات الأداء",
    stats: [
      { value: "48", unit: "ns", label: "زمن الاستجابة · p50" },
      { value: "96", unit: "ns", label: "زمن الاستجابة · p99" },
      { value: "41.5M", unit: "", label: "عملية إسقاط مختبرة" },
      { value: "1", unit: "Binary", label: "ملف تشغيل شامل بـ Rust" },
    ],
    note: "الأرقام مقيسة مباشرة من خريطة LATENCY_HIST داخل النواة تحت ضغط حقيقي. يحقق حَكَم إنتاجية حزمٍ أعلى بكلفة معالجةٍ أقل مقارنة بالأنظمة غير المحمية.",
    figureCaption: "واجهة Hakam الحيّة (HUD): لوحة التحكم التفاعلية والمخطط الشبكي أثناء التشغيل",
  },
  conclusion: {
    title: "الخلاصة والأثر",
    bullets: [
      "الابتكار ليس في تعقيد الأنظمة بل في تبسيطها؛ نقل أداء الحماية العنقودية لملف تنفيذي واحد يسهل تدقيقه ونشره دون فرق تشغيل ضخمة.",
      "مشروع مصنوع محلياً، يثبت قدرة الكفاءات الوطنية الشابة على هندسة وبناء أدوات دفاعية تلامس جذور أنظمة التشغيل.",
    ],
  },
  refs: {
    title: "المراجع والتواصل",
    repo: "github.com/realozk/hakam",
    url: "https://github.com/realozk/hakam",
    lines: ["الترخيص: MIT (مفتوح المصدر)"],
  },
};

const SectionHead = ({ n, title }: { n: string; title: string }) => (
  <div className="pstr-shead">
    <span className="pstr-sindex" dir="ltr">
      {n}
    </span>
    <h2 className="pstr-h2">{title}</h2>
  </div>
);

const Bullets = ({ items }: { items: string[] }) => (
  <ul className="pstr-ul">
    {items.map((b, i) => (
      <li key={i}>{b}</li>
    ))}
  </ul>
);

// Before printing, size the PDF page to the poster's real content height so it
// all lands on ONE page with nothing clipped. Runs on the button and on Cmd+P.
function setPrintPageSize() {
  const canvas = document.querySelector(".pstr-canvas") as HTMLElement | null;
  const el = document.getElementById("pstr-page-size");
  if (!canvas || !el) return;
  const h = Math.ceil(canvas.getBoundingClientRect().height) + 4;
  el.textContent = `@page { size: 1040px ${h}px; margin: 0; }`;
}

export default function Poster() {
  useEffect(() => {
    window.addEventListener("beforeprint", setPrintPageSize);
    return () => window.removeEventListener("beforeprint", setPrintPageSize);
  }, []);

  return (
    <div className="pstr-root" dir="rtl">
      <div className="pstr-toolbar">
        <button
          className="pstr-btn"
          onClick={() => {
            setPrintPageSize();
            window.print();
          }}
        >
          🖨 طباعة / حفظ PDF
        </button>
        <span className="pstr-hint">عدّل النصوص في كائن C أعلى ملف Poster.tsx</span>
      </div>

      <article className="pstr-canvas">
        {/* ── Header ─────────────────────────────────────────────── */}
        <header className="pstr-header">
          <div className="pstr-titleblock">
            <div className="pstr-titlerow">
              <h1 className="pstr-title">{C.title}</h1>
              <span className="pstr-titlelatin" dir="ltr">
                {C.titleLatin}
              </span>
            </div>
            <p className="pstr-subtitle">{C.subtitle}</p>
            <div className="pstr-chips" dir="ltr">
              {C.chips.map((c, i) => (
                <span className="pstr-chip" key={c}>
                  {c}
                  {i < C.chips.length - 1 && <i className="pstr-dot" />}
                </span>
              ))}
            </div>
          </div>
          <div className="pstr-meta">
            <div className="pstr-author">{C.author}</div>
            <div className="pstr-metaline">{C.org}</div>
            <div className="pstr-metaline pstr-accent">{C.event}</div>
          </div>
        </header>

        {/* ── Body ───────────────────────────────────────────────── */}
        <div className="pstr-body">
          <div className="pstr-cols2">
            <section>
              <SectionHead n="01" title={C.intro.title} />
              <Bullets items={C.intro.bullets} />
            </section>
            <section>
              <SectionHead n="02" title={C.objective.title} />
              <Bullets items={C.objective.bullets} />
            </section>
          </div>

          <hr className="pstr-rule" />

          <section>
            <SectionHead n="03" title={C.layers.title} />
            <div className="pstr-layers">
              {C.layers.items.map((l, i) => (
                <div className="pstr-layer" key={l.tag}>
                  <span className="pstr-lnum" dir="ltr">
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  <div className="pstr-layertag">{l.tag}</div>
                  <p className="pstr-layertext">{l.text}</p>
                </div>
              ))}
            </div>
            <p className="pstr-note">{C.layers.note}</p>
          </section>

          <hr className="pstr-rule" />

          <section>
            <SectionHead n="04" title={C.results.title} />
            <div className="pstr-stats">
              {C.results.stats.map((s) => (
                <div className="pstr-stat" key={s.label}>
                  <div className="pstr-statnum" dir="ltr">
                    {s.value}
                    {s.unit && <span className="pstr-statunit">{s.unit}</span>}
                  </div>
                  <div className="pstr-statlabel">{s.label}</div>
                </div>
              ))}
            </div>
            <p className="pstr-note">{C.results.note}</p>
            <figure className="pstr-figure">
              <img className="pstr-figimg" src="/hud-screenshot.jpeg" alt="Hakam HUD" />
              <figcaption className="pstr-figcap">{C.results.figureCaption}</figcaption>
            </figure>
          </section>

          <hr className="pstr-rule" />

          <div className="pstr-cols2">
            <section>
              <SectionHead n="05" title={C.conclusion.title} />
              <Bullets items={C.conclusion.bullets} />
            </section>
            <section>
              <SectionHead n="06" title={C.refs.title} />
              <div className="pstr-refrow">
                <div>
                  <a
                    className="pstr-repo"
                    href={C.refs.url}
                    target="_blank"
                    rel="noreferrer"
                    dir="ltr"
                  >
                    {C.refs.repo}
                  </a>
                  {C.refs.lines.map((l, i) => (
                    <div className="pstr-metaline" key={i}>
                      {l}
                    </div>
                  ))}
                </div>
              </div>
            </section>
          </div>
        </div>

        <footer className="pstr-footer">
          <a
            className="pstr-footlink"
            href={C.refs.url}
            target="_blank"
            rel="noreferrer"
            dir="ltr"
          >
            {C.refs.repo}
          </a>
          <span>{C.event}</span>
        </footer>
      </article>

      <style>{`
        .pstr-root {
          position: fixed; inset: 0; overflow: auto;
          background: #04060b; color: #c5cdd5;
          font-family: var(--font-sans, Inter, system-ui, sans-serif);
          display: flex; flex-direction: column; align-items: center;
          padding: 28px 0 72px;
        }
        .pstr-toolbar {
          width: 1040px; max-width: 94vw; display: flex; align-items: center;
          gap: 16px; margin-bottom: 18px;
        }
        .pstr-btn {
          background: #6fe7d4; color: #04060b; border: 0; cursor: pointer;
          font: 600 13px var(--font-sans, Inter, sans-serif);
          padding: 9px 16px; border-radius: 4px; letter-spacing: .02em;
        }
        .pstr-hint { font-size: 12px; color: rgba(197,205,213,.4); }

        /* ── Canvas: A1 portrait ratio, roomy margins ── */
        .pstr-canvas {
          width: 1040px; max-width: 94vw; min-height: 1471px;
          background: #070a11; border: 1px solid rgba(255,255,255,.06);
          border-radius: 4px; overflow: hidden;
          display: flex; flex-direction: column;
          box-shadow: 0 40px 120px rgba(0,0,0,.6);
        }

        /* ── Header ── */
        .pstr-header {
          position: relative;
          display: flex; justify-content: space-between; align-items: flex-start; gap: 48px;
          padding: 64px 72px 40px;
          background: radial-gradient(130% 90% at 100% 0, rgba(111,231,212,.09), transparent 55%);
        }
        .pstr-header::after {
          content: ""; position: absolute; left: 72px; right: 72px; bottom: 0; height: 1px;
          background: linear-gradient(90deg, transparent, rgba(111,231,212,.4), transparent);
        }
        .pstr-titleblock { min-width: 0; }
        .pstr-titlerow { display: flex; align-items: baseline; gap: 20px; }
        .pstr-title {
          font: 700 88px/.95 var(--font-disp, 'Clash Display', sans-serif);
          color: #f4f7fa; margin: 0; letter-spacing: -.01em;
        }
        .pstr-titlelatin {
          font: 500 21px var(--font-mono, ui-monospace, monospace);
          color: #6fe7d4; letter-spacing: .34em; text-transform: uppercase;
        }
        .pstr-subtitle {
          font-size: 19px; line-height: 1.75; color: #c9d2db; font-weight: 400;
          margin: 22px 0 24px; max-width: 60ch;
        }
        .pstr-chips { display: flex; align-items: center; gap: 12px; }
        .pstr-chip {
          display: inline-flex; align-items: center; gap: 12px;
          font: 600 13px var(--font-mono, monospace); color: rgba(111,231,212,.9);
          letter-spacing: .16em;
        }
        .pstr-dot { width: 3px; height: 3px; border-radius: 50%; background: rgba(111,231,212,.45); }
        .pstr-meta { text-align: left; min-width: 280px; padding-top: 10px; }
        .pstr-author { font: 600 20px var(--font-sans, sans-serif); color: #f4f7fa; margin-bottom: 10px; }
        .pstr-metaline { font-size: 15px; line-height: 2; color: rgba(197,205,213,.66); }
        .pstr-accent { color: #d6e3ee; }
        .pstr-track { color: #6fe7d4; margin-top: 12px; font-weight: 600; }

        /* ── Body ── */
        .pstr-body {
          flex: 1; padding: 48px 72px 44px;
          display: flex; flex-direction: column; gap: 46px;
        }
        .pstr-cols2 { display: grid; grid-template-columns: 1fr 1fr; gap: 60px; align-items: start; }
        .pstr-rule { border: 0; height: 1px; margin: 0; background: rgba(255,255,255,.07); }

        /* ── Section heading ── */
        .pstr-shead { display: flex; align-items: baseline; gap: 16px; margin-bottom: 24px; }
        .pstr-sindex {
          font: 600 15px var(--font-mono, monospace); color: #6fe7d4; letter-spacing: .1em;
        }
        .pstr-h2 {
          font: 600 26px var(--font-disp, 'Clash Display', sans-serif);
          color: #f4f7fa; margin: 0; letter-spacing: -.005em; line-height: 1.25;
        }

        /* ── Bullets — open, airy, no box ── */
        .pstr-ul { margin: 0; padding: 0; list-style: none; }
        .pstr-ul li {
          position: relative; font-size: 16px; line-height: 1.95;
          color: #bac3cd; margin-bottom: 18px; padding-right: 24px;
        }
        .pstr-ul li:last-child { margin-bottom: 0; }
        .pstr-ul li::before {
          content: ""; position: absolute; right: 2px; top: 13px;
          width: 7px; height: 7px; border: 1.5px solid #6fe7d4; border-radius: 50%;
        }

        .pstr-note {
          font-size: 15.5px; line-height: 1.9; color: rgba(197,205,213,.66);
          margin: 28px 0 0; padding-right: 16px; border-right: 2px solid rgba(111,231,212,.4);
        }

        /* ── Three enforcement layers — no boxes, top-rule marker ── */
        .pstr-layers { display: grid; grid-template-columns: repeat(3, 1fr); gap: 44px; }
        .pstr-layer { position: relative; padding-top: 22px; }
        .pstr-layer::before {
          content: ""; position: absolute; top: 0; right: 0; width: 46px; height: 2px; background: #6fe7d4;
        }
        .pstr-lnum {
          display: block; font: 600 14px var(--font-mono, monospace);
          color: rgba(111,231,212,.75); margin-bottom: 14px; letter-spacing: .1em;
        }
        .pstr-layertag { font: 600 16px var(--font-sans, sans-serif); color: #f4f7fa; margin-bottom: 12px; }
        .pstr-layertext { font-size: 16px; line-height: 1.85; color: #b4bdc7; margin: 0; }

        /* ── Results — hairline-separated stat row, not tiles ── */
        .pstr-stats { display: grid; grid-template-columns: repeat(4, 1fr); }
        .pstr-stat { text-align: center; padding: 8px 24px; border-inline-start: 1px solid rgba(255,255,255,.08); }
        .pstr-stat:first-child { border-inline-start: 0; }
        .pstr-statnum {
          font: 700 60px/1 var(--font-disp, 'Clash Display', sans-serif);
          color: #6fe7d4; letter-spacing: -.02em;
        }
        .pstr-statunit { font-size: 22px; color: rgba(111,231,212,.65); margin-right: 5px; letter-spacing: 0; }
        .pstr-statlabel { font-size: 15px; color: rgba(197,205,213,.62); margin-top: 16px; line-height: 1.55; }

        .pstr-figure {
          margin: 30px 0 0; border: 1px solid rgba(255,255,255,.1); border-radius: 6px;
          overflow: hidden; background: #04060b;
        }
        .pstr-figimg { display: block; width: 100%; height: auto; }
        .pstr-figcap {
          font-size: 13.5px; color: rgba(197,205,213,.55); text-align: center;
          padding: 13px 18px; border-top: 1px solid rgba(255,255,255,.07);
        }

        /* ── Refs ── */
        .pstr-refrow { display: flex; gap: 24px; align-items: center; }
        .pstr-qr {
          width: 92px; height: 92px; flex: none; border: 1px solid rgba(255,255,255,.14);
          border-radius: 4px; display: flex; align-items: center; justify-content: center;
          font: 600 13px var(--font-mono, monospace); color: rgba(197,205,213,.4);
        }
        .pstr-repo {
          display: inline-block; font: 600 16px var(--font-mono, monospace); color: #6fe7d4;
          margin-bottom: 12px; text-decoration: none;
        }
        .pstr-repo:hover { text-decoration: underline; }
        .pstr-footlink { color: rgba(111,231,212,.8); text-decoration: none; }
        .pstr-footlink:hover { text-decoration: underline; }

        /* ── Footer ── */
        .pstr-footer {
          margin-top: auto; display: flex; justify-content: space-between; gap: 16px;
          padding: 24px 72px; border-top: 1px solid rgba(255,255,255,.07);
          font-size: 14px; color: rgba(197,205,213,.5);
        }

        /* ── Print / export to PDF — page height is set dynamically (JS,
           setPrintPageSize) to the poster's real content height, so everything
           fits on exactly one page with nothing clipped or spilling over. ── */
        @media print {
          html, body { margin: 0; padding: 0; }
          .pstr-root {
            position: static; overflow: visible; padding: 0; margin: 0; display: block;
            background: #070a11;
          }
          .pstr-toolbar { display: none; }
          .pstr-canvas {
            width: 1040px; max-width: none; height: auto; min-height: 0;
            margin: 0; border: 0; border-radius: 0; box-shadow: none;
            -webkit-print-color-adjust: exact; print-color-adjust: exact;
          }
        }
      `}</style>
      <style id="pstr-page-size">{`@page { size: 1040px 1600px; margin: 0; }`}</style>
    </div>
  );
}
