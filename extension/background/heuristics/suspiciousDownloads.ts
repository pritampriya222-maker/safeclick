/**
 * background/heuristics/suspiciousDownloads.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Heuristic: Detection of shady movie streaming, cracked game/software, warez,
 * and high-risk APK/media download portals.
 *
 * Rationale:
 * Shady streaming and cracked software sites frequently host malvertising,
 * deceptive "Download" buttons that deliver adware/infostealers, and browser lockers.
 *
 * Scoring Strategy:
 * - Mild streaming/piracy domain: weight 35–45 (marks site as Suspicious / Amber)
 * - Known crack/keygen/fake repack mirror on risky TLD: weight 50–70 (pushes to Suspicious/Dangerous)
 */

import type { HeuristicResult, NormalizedUrl, PageSignals } from '../../shared/types';

const RULE_ID = 'heuristic:suspicious_downloads';

// ─── Keyword Sets ─────────────────────────────────────────────────────────────

const SHADY_STREAMING_KEYWORDS = [
  '123movies', '123movie', 'fmovies', 'fmovie', 'watchseries',
  'freemovies', 'gostream', 'putlocker', 'soap2day', 'myflixer',
  'hdmovie', 'solarmovie', 'filmyzilla', 'tamilrockers', 'cineb',
  'lookmovie', 'streamm4u', 'yify', 'yts', 'piratebay', '1337x',
  'movies7', 'flixtor', 'hdtoday', 'bflix', 'hurawatch', 'gomovies',
  'primewire', 'streamlord', 'cinebloom', 'movie4k',
] as const;

const SHADY_DOWNLOAD_KEYWORDS = [
  'steamunlocked', 'oceanofgames', 'igg-games', 'skidrow',
  'repack', 'repacks', 'fitgirl-repack', 'dodi-repack',
  'cracked', 'keygen', 'key-gen', 'serialkey', 'warez',
  'free-download', 'freepcgames', 'apkmod', 'modapk', 'apkmody',
  'full-crack', 'patcher', 'activator', 'torrent-games', 'pcgames-download',
  'crackz', 'warezdownload', 'dl-free', 'unlocked-game', 'game-repack',
] as const;

const SHADY_MEDIA_TLDS = new Set([
  '.to', '.is', '.cc', '.ru', '.su', '.pw', '.top',
  '.xyz', '.site', '.vip', '.icu', '.lat', '.biz',
  '.stream', '.download', '.click', '.link', '.fit', '.gq', '.cf', '.ga', '.tk', '.ml'
]);

export function analyzeSuspiciousDownloads(
  normalizedUrl: NormalizedUrl,
  _pageSignals: PageSignals | null
): HeuristicResult {
  const { hostname, registeredDomain, path, original } = normalizedUrl;
  const fullTarget = `${hostname}${path}`.toLowerCase();

  const matchedStreaming: string[] = [];
  for (const kw of SHADY_STREAMING_KEYWORDS) {
    if (fullTarget.includes(kw)) {
      matchedStreaming.push(kw);
    }
  }

  const matchedDownloads: string[] = [];
  for (const kw of SHADY_DOWNLOAD_KEYWORDS) {
    if (fullTarget.includes(kw)) {
      matchedDownloads.push(kw);
    }
  }

  // Check if domain uses a common piracy/media TLD
  const tldMatch = hostname.match(/\.[a-z]{2,8}$/i);
  const currentTld = tldMatch ? tldMatch[0].toLowerCase() : '';
  const hasShadyTld = SHADY_MEDIA_TLDS.has(currentTld);

  // Check for suspicious direct binary download extension in URL path
  const hasDangerousExecutableExt = /\.(exe|scr|bat|vbs|iso|apk|msi|crx)(\?|$)/i.test(path);

  const isStreamingSite = matchedStreaming.length > 0;
  const isDownloadSite = matchedDownloads.length > 0;
  const isTriggered = isStreamingSite || isDownloadSite || (hasShadyTld && (fullTarget.includes('free') || fullTarget.includes('movie') || fullTarget.includes('download')));

  if (!isTriggered) {
    return {
      ruleId: RULE_ID,
      triggered: false,
      weight: 0,
      explanation: 'No suspicious download or piracy streaming patterns detected.',
    };
  }

  // Weight calculation
  let weight = 0;
  const details: string[] = [];

  if (isDownloadSite) {
    weight += 45;
    details.push(`Cracked software/repack keyword detected (${matchedDownloads.join(', ')})`);
  }

  if (isStreamingSite) {
    weight += 35;
    details.push(`Free streaming/piracy index keyword detected (${matchedStreaming.join(', ')})`);
  }

  if (hasShadyTld) {
    weight += 15;
    details.push(`Uses high-risk media TLD (${currentTld})`);
  }

  if (hasDangerousExecutableExt) {
    weight += 20;
    details.push('Direct executable/package download path');
  }

  weight = Math.min(weight, 65); // Cap heuristic contribution

  return {
    ruleId: RULE_ID,
    triggered: true,
    weight,
    explanation: `Potential unverified media or software download site. Watch out for deceptive download buttons, adware, or bundled malware (${details.join('; ')}).`,
  };
}
