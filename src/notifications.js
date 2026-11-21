'use strict';
const COOLDOWN = 30 * 60 * 1000, SILENCE = 5 * 60 * 1000;
class NotificationTracker {
  constructor() { this.active=new Set(); this.lastNotified=new Map(); this.runningSince=0; this.session=0; this.warnedSilence=new Set(); }
  tick(snapshot, options, now=Date.now()) {
    if (!snapshot.running || !options.enabled) { this.active.clear(); this.runningSince=0; this.session=0; this.warnedSilence.clear(); return []; }
    if (snapshot.startedAt && this.session !== snapshot.startedAt) { this.active.clear(); this.warnedSilence.clear(); this.runningSince=snapshot.startedAt; this.session=snapshot.startedAt; }
    if (!this.runningSince) this.runningSince=now;
    const messages=[]; const seen=new Set(); const fresh=[];
    for (const alert of snapshot.alerts || []) {
      if (options.minimum==='medium' && alert.severity!=='medium') continue;
      const key=`${alert.type}|${alert.ip}`; seen.add(key);
      if (!this.active.has(key) && now-(this.lastNotified.get(key)||0)>=COOLDOWN) { fresh.push(alert); this.lastNotified.set(key,now); }
    }
    this.active=seen;
    for (const [key,time] of this.lastNotified) if (now-time>COOLDOWN*2) this.lastNotified.delete(key);
    if (fresh.length) messages.push({ title:'Net Control: новые сигналы', body:`Новых сигналов: ${fresh.length}. Откройте приложение для проверки.` });
    const sources = snapshot.sources && Object.keys(snapshot.sources).length ? snapshot.sources : {роутер:{lastPacket:snapshot.lastPacket}};
    const silent=[];
    for (const [ip, source] of Object.entries(sources)) {
      const last=source.lastPacket || this.runningSince;
      if (now-last>=SILENCE && !this.warnedSilence.has(ip)) { silent.push(ip); this.warnedSilence.add(ip); }
      if (source.lastPacket && now-source.lastPacket<SILENCE) this.warnedSilence.delete(ip);
    }
    if (silent.length) messages.push({title:'Net Control: нет данных',body:`Пять минут без пакетов: ${silent.join(', ')}. Проверьте экспорт и сеть.`});
    return messages;
  }
}
module.exports={NotificationTracker,COOLDOWN,SILENCE};
