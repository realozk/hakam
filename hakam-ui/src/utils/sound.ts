let ctx: AudioContext | null = null;
let ready = false;

export function unlockAudio(): void {
  if (!ctx) {
    ctx = new (window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext)();
  }
  if (ctx.state === 'suspended') ctx.resume();
  ready = true;
}

export function playIntercept(): void {
  if (!ctx || !ready) return;
  const t = ctx.currentTime;

  // Sub-bass thud: 90 → 28 Hz sine, 90 ms
  const osc = ctx.createOscillator();
  const oscGain = ctx.createGain();
  osc.connect(oscGain);
  oscGain.connect(ctx.destination);
  osc.type = 'sine';
  osc.frequency.setValueAtTime(90, t);
  osc.frequency.exponentialRampToValueAtTime(28, t + 0.09);
  oscGain.gain.setValueAtTime(0.36, t);
  oscGain.gain.exponentialRampToValueAtTime(0.001, t + 0.09);
  osc.start(t);
  osc.stop(t + 0.09);

  // High click: shaped white noise, 20 ms
  const bufLen = Math.floor(ctx.sampleRate * 0.02);
  const buf = ctx.createBuffer(1, bufLen, ctx.sampleRate);
  const data = buf.getChannelData(0);
  for (let i = 0; i < bufLen; i++) {
    data[i] = (Math.random() * 2 - 1) * ((1 - i / bufLen) ** 2);
  }
  const noise = ctx.createBufferSource();
  noise.buffer = buf;
  const noiseGain = ctx.createGain();
  noiseGain.gain.setValueAtTime(0.11, t);
  noise.connect(noiseGain);
  noiseGain.connect(ctx.destination);
  noise.start(t);
}
